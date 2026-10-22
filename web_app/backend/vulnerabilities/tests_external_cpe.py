"""Worker-backed external CPE-ID verification, with synthetic NVD responses only."""
from uuid import uuid4
from unittest.mock import Mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient

from assets.models import Asset, Hardware, Software
from vulnerabilities.models import Cpe, CpeSearchRun, AssetCpe, AssetCpeDecision
from vulnerabilities.services.cpe_search import create_run
from vulnerabilities.services.external_cpe import (
    enqueue_external_cpe, execute_external_cpe, EXTERNAL_CPE_TRIGGER,
)
from vulnerabilities.services.nvd_client import NvdError, fetch_page


class NvdUUIDClientValidationTests(SimpleTestCase):
    def test_bad_or_unbounded_id_fails_before_http(self):
        for bad in ("cpe:2.3:h:siemens:*", "../uuid", "bad", "x" * 400):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                fetch_page("cpeNameId", bad, 0, Mock(), results_per_page=1)
        with self.assertRaises(ValueError):
            fetch_page("cpeNameId", str(uuid4()), 50, Mock(), results_per_page=1)
        with self.assertRaises(ValueError):
            fetch_page("cpeNameId", str(uuid4()), 0, Mock(), results_per_page=100)


class WorkerDispatchTests(SimpleTestCase):
    def test_one_worker_routes_manual_uuid_without_running_discovery(self):
        from unittest.mock import patch
        from vulnerabilities.management.commands.run_cpe_worker import dispatch_cpe_run
        external = Mock(trigger=EXTERNAL_CPE_TRIGGER)
        automatic = Mock(trigger="MANUAL")
        with patch(
            "vulnerabilities.management.commands.run_cpe_worker.execute_external_cpe"
        ) as verify, patch(
            "vulnerabilities.management.commands.run_cpe_worker.execute_run"
        ) as discover:
            dispatch_cpe_run(external, "pacer")
            verify.assert_called_once_with(external, "pacer")
            discover.assert_not_called()
            dispatch_cpe_run(automatic, "pacer")
            discover.assert_called_once_with(automatic, "pacer")


class ExternalCpeVerificationTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(username="external-cpe-analyst", role=User.Role.ANALYST)
        self.operator = User.objects.create_user(username="external-cpe-operator", role=User.Role.OPERATOR)
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.hardware = Asset.objects.create(
            name="PLC Siemens", asset_type=Asset.AssetType.HARDWARE,
            created_by=self.analyst, updated_by=self.analyst
        )
        Hardware.objects.create(asset=self.hardware, manufacturer="Siemens",
                                model="SIMATIC S7 1200", cpu_model="1215C", role="PLC")
        self.software = Asset.objects.create(
            name="Cisco IOS", asset_type=Asset.AssetType.SOFTWARE,
            created_by=self.analyst, updated_by=self.analyst
        )
        Software.objects.create(asset=self.software, manufacturer="Cisco",
                                product="IOS", version="12.1", software_type="OS")
        self.uuid = uuid4()

    def url(self, asset=None):
        asset = asset or self.hardware
        return f"/api/vulnerabilities/assets/{asset.pk}/cpe-verifications/"

    def record(self, part="h", vendor="siemens", product="simatic_s7_1200",
               version="12.1", deprecated=False, uid=None):
        name = ":".join(["cpe", "2.3", part, vendor, product, version] + ["*"] * 7)
        return {"cpe": {
            "cpeNameId": str(uid or self.uuid),
            "cpeName": name, "deprecated": deprecated,
            "titles": [{"lang": "en", "title": "Official product NVD"}],
            "refs": [{"ref": "https://support.siemens.com/products", "type": "Product"}],
        }}

    def start(self, asset=None, uid=None):
        response = self.client.post(
            self.url(asset), {"cpe_name_id": str(uid or self.uuid)}, format="json"
        )
        self.assertEqual(response.status_code, 202, response.data)
        return CpeSearchRun.objects.get(pk=response.data["run_id"])

    def finish(self, run, product=None, exc=None, count=None):
        if exc:
            def fetcher(*args, **kwargs):
                raise exc
        else:
            rows = [product] if product is not None else []
            response = {"totalResults": len(rows) if count is None else count,
                        "startIndex": 0, "products": rows}
            fetcher = Mock(return_value=response)
        pacer = object()
        completed = execute_external_cpe(run, pacer, fetcher=fetcher)
        if not exc:
            fetcher.assert_called_once_with(
                "cpeNameId", str(self.uuid), 0, pacer, results_per_page=1,
            )
        completed.refresh_from_db()
        return completed

    def test_hardware_uuid_verifies_official_data_without_creating_association(self):
        run = self.start()
        self.assertEqual(run.trigger, EXTERNAL_CPE_TRIGGER)
        self.assertEqual(run.queries[0]["parameter"], str(self.uuid))
        done = self.finish(run, self.record())
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(done.queries[0]["status"], "VERIFIED")
        self.assertEqual(done.candidates[0]["cpe_name_id"], str(self.uuid))
        self.assertEqual(done.candidates[0]["title"], "Official product NVD")
        self.assertTrue(done.candidates[0]["nvd_references"])
        self.assertEqual(done.candidates[0]["verification_origin"], "EXTERNAL_CPE")
        self.assertEqual(Cpe.objects.count(), 0)
        self.assertFalse(AssetCpe.objects.exists())
        self.assertFalse(AssetCpeDecision.objects.exists())
        got = self.client.get(self.url() + f"{run.pk}/")
        self.assertEqual(got.status_code, 200)
        self.assertEqual(got.data["verification"]["verification_status"], "VERIFIED")
        self.assertIsNone(got.data["verification"]["existing_association"])

    def test_valid_absent_uuid_is_not_a_network_error(self):
        done = self.finish(self.start())
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(done.queries[0]["status"], "NOT_FOUND")
        self.assertEqual(done.candidates, [])
        self.assertEqual(Cpe.objects.count(), 0)

    def test_invalid_uuid_is_rejected_before_queue_or_nvd(self):
        response = self.client.post(
            self.url(), {"cpe_name_id": "fake-uuid"}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(CpeSearchRun.objects.exists())

    def test_incompatible_part_has_no_selectable_candidate(self):
        run = self.start(self.software)
        done = self.finish(run, self.record(part="h"))
        self.assertEqual(done.queries[0]["status"], "INCOMPATIBLE_PART")
        self.assertEqual(done.candidates, [])
        post = self.client.post(
            f"/api/vulnerabilities/assets/{self.software.pk}/cpes/",
            {"run_id": done.pk, "cpe_name_id": str(self.uuid), "status": "CONFIRMED"},
            format="json"
        )
        self.assertEqual(post.status_code, 400)
        self.assertFalse(AssetCpe.objects.exists())

    def test_software_version_text_discrepancy_is_warning_not_blocking(self):
        run = self.start(self.software)
        done = self.finish(run, self.record(part="o", vendor="other",
                                            product="alternative_software", version="1.0"))
        self.assertEqual(done.queries[0]["status"], "VERIFIED")
        self.assertEqual(done.candidates[0]["match_level"], "POSSIBLE_INCOMPATIBILITY")
        self.assertTrue(any("fabricante" in w.lower() for w in done.candidates[0]["warnings"]))
        response = self.client.post(
            f"/api/vulnerabilities/assets/{self.software.pk}/cpes/",
            {"run_id": done.pk, "cpe_name_id": str(self.uuid), "status": "REJECTED",
             "justification": "Discrepancia documental"}, format="json"
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        self.assertEqual(AssetCpe.objects.first().validation_status, "REJECTED")

    def test_deprecated_cpe_remains_verifiable_but_warns(self):
        done = self.finish(self.start(), self.record(deprecated=True))
        self.assertTrue(done.candidates[0]["deprecated"])
        self.assertTrue(any("obsoleto" in w for w in done.candidates[0]["warnings"]))

    def test_nvd_error_and_timeout_are_failed_not_nonexistent(self):
        for error in (NvdError("HTTP 503"), TimeoutError("timeout")):
            run = self.start(uid=uuid4())
            done = execute_external_cpe(run, object(), fetcher=Mock(side_effect=error))
            self.assertEqual(done.status, "FAILED")
            self.assertEqual(done.queries[0]["status"], "ERROR")
            self.assertEqual(done.candidates, [])
        self.assertFalse(AssetCpe.objects.exists())

    def test_nvd_wrong_uuid_or_multiple_records_not_trusted(self):
        wrong = self.finish(self.start(), self.record(uid=uuid4()))
        self.assertEqual(wrong.queries[0]["status"], "INVALID_RESPONSE")
        ambiguous = self.finish(self.start(), self.record(), count=2)
        self.assertEqual(ambiguous.queries[0]["status"], "INVALID_RESPONSE")
        self.assertFalse(AssetCpe.objects.exists())

    def test_pending_same_uuid_is_reused_and_existing_association_is_returned(self):
        run = self.start()
        second = self.client.post(self.url(), {"cpe_name_id": str(self.uuid)}, format="json")
        self.assertTrue(second.data["reused"])
        self.assertEqual(second.data["run_id"], run.pk)
        done = self.finish(run, self.record())
        create = self.client.post(
            f"/api/vulnerabilities/assets/{self.hardware.pk}/cpes/",
            {"run_id": done.pk, "cpe_name_id": str(self.uuid),
             "status": "CONFIRMED", "justification": "Validado manualmente"}, format="json"
        )
        self.assertEqual(create.status_code, 201, create.data)
        self.assertEqual(AssetCpe.objects.count(), 1)
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        self.assertEqual(create.data["association"]["source_run_trigger"], "EXTERNAL_CPE")
        duplicate = self.client.post(
            f"/api/vulnerabilities/assets/{self.hardware.pk}/cpes/",
            {"run_id": done.pk, "cpe_name_id": str(self.uuid), "status": "REJECTED"},
            format="json"
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(AssetCpe.objects.count(), 1)
        detail = self.client.get(self.url() + f"{run.pk}/")
        self.assertEqual(detail.data["verification"]["existing_association"]["status"], "CONFIRMED")
        association = AssetCpe.objects.get()
        changed = self.client.patch(
            f"/api/vulnerabilities/assets/{self.hardware.pk}/cpes/{association.pk}/",
            {"run_id": done.pk, "cpe_name_id": str(self.uuid),
             "status": "REJECTED", "justification": "Nueva evidencia"}, format="json"
        )
        self.assertEqual(changed.status_code, 200, changed.data)
        self.assertEqual(AssetCpeDecision.objects.count(), 2)
        self.assertEqual(AssetCpe.objects.count(), 1)

    def test_external_does_not_replace_latest_automatic_run_or_counts(self):
        original = create_run(self.hardware.pk, self.analyst, "SPECIFIC")
        before = self.client.get("/api/vulnerabilities/cpe-overview/")
        row = next(x for x in before.data["results"] if x["asset_id"] == self.hardware.pk)
        start = self.start()
        self.finish(start, self.record())
        latest = self.client.get(
            f"/api/vulnerabilities/assets/{self.hardware.pk}/cpe-searches/latest/"
        )
        self.assertEqual(latest.data["run"]["id"], original.pk)
        after = self.client.get("/api/vulnerabilities/cpe-overview/")
        next_row = next(x for x in after.data["results"] if x["asset_id"] == self.hardware.pk)
        for key in ("run_id", "candidate_count", "identification_status",
                    "confirmed_count", "unreviewed_count"):
            self.assertEqual(row[key], next_row[key])
        verifications = self.client.get(self.url())
        self.assertEqual(len(verifications.data["verifications"]), 1)

    def test_operator_cannot_enqueue_but_can_read_existing_verification(self):
        run = self.start()
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.post(
            self.url(), {"cpe_name_id": str(uuid4())}, format="json"
        ).status_code, 403)
        self.assertEqual(self.client.get(self.url()).status_code, 200)
        self.assertEqual(self.client.get(self.url() + f"{run.pk}/").status_code, 200)

    def test_stale_inventory_blocks_decision(self):
        run = self.start()
        done = self.finish(run, self.record())
        self.hardware.hardware.model = "Different PLC"
        self.hardware.hardware.save()
        invalid = self.client.post(
            f"/api/vulnerabilities/assets/{self.hardware.pk}/cpes/",
            {"run_id": done.pk, "cpe_name_id": str(self.uuid), "status": "CONFIRMED"},
            format="json",
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertFalse(AssetCpe.objects.exists())
