"""Phase 3: reuse existing HTTP endpoints for software CPE lifecycle."""
from uuid import uuid5, NAMESPACE_DNS

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from assets.models import Asset, Software
from vulnerabilities.models import CpeSearchRun, AssetCpe, AssetCpeDecision, CpeQuerySnapshot
from vulnerabilities.services.cpe_catalogue import execute_catalogue_snapshot
from vulnerabilities.services.cpe_search import execute_run
from vulnerabilities.services.identity import fingerprint, software_identity


class SoftwareCpeHttpTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(username="sw-cpe-analyst", role=User.Role.ANALYST)
        self.operator = User.objects.create_user(username="sw-cpe-operator", role=User.Role.OPERATOR)
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.asset = Asset.objects.create(
            name="Cisco IOS Catalyst 2955", asset_type=Asset.AssetType.SOFTWARE,
            created_by=self.analyst, updated_by=self.analyst,
        )
        Software.objects.create(
            asset=self.asset, software_type=Software.SoftwareType.OS,
            manufacturer="Cisco", product="IOS", version="12.1",
        )
        self.root = f"/api/vulnerabilities/assets/{self.asset.pk}/"
        self.cpe = "cpe:2.3:o:cisco:ios:12.1:*:*:*:*:*:*:*"
        self.cpe_id = str(uuid5(NAMESPACE_DNS, self.cpe))

    def _nvd_exact(self):
        return {"cpe": {
            "cpeNameId": self.cpe_id,
            "cpeName": self.cpe,
            "deprecated": False,
            "titles": [{"lang": "en", "title": "Cisco IOS 12.1"}],
        }}

    def _complete(self):
        start = self.client.post(self.root + "cpe-searches/", {"scope": "SPECIFIC"}, format="json")
        self.assertEqual(start.status_code, 202, start.data)
        run = CpeSearchRun.objects.get(pk=start.data["run_id"])
        pending = execute_run(run, object(), fetcher=lambda *args: {
            "products": [self._nvd_exact()], "totalResults": 1, "startIndex": 0,
        })
        self.assertEqual(pending.status, CpeSearchRun.Status.QUEUED)
        snapshot = CpeQuerySnapshot.objects.get()
        execute_catalogue_snapshot(
            snapshot, object(),
            fetcher=lambda strategy, parameter, start, pacer, *, results_per_page:
            {"products": [self._nvd_exact()], "totalResults": 1, "startIndex": start},
        )
        execute_run(pending, object(), fetcher=lambda *args:
                    self.fail("No debe repetirse la consulta específica"))
        run.refresh_from_db()
        self.assertEqual(run.status, CpeSearchRun.Status.COMPLETED)
        return run

    def test_search_latest_detail_and_overview_include_software(self):
        before = self.client.get("/api/vulnerabilities/cpe-overview/")
        status = next(r for r in before.data["results"] if r["asset_id"] == self.asset.pk)
        self.assertEqual(status["identification_status"], "NOT_SEARCHED")
        run = self._complete()
        latest = self.client.get(self.root + "cpe-searches/latest/")
        detail = self.client.get(self.root + f"cpe-searches/{run.pk}/")
        self.assertEqual(latest.status_code, 200)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["run"]["candidate_count"], 1)
        self.assertEqual(detail.data["run"]["candidates"][0]["match_level"], "SOFTWARE_EXACT")
        self.assertEqual(detail.data["run"]["candidates"][0]["cpe_type"], "o")
        self.assertTrue(detail.data["run"]["identity_is_current"])
        after = self.client.get("/api/vulnerabilities/cpe-overview/")
        row = next(r for r in after.data["results"] if r["asset_id"] == self.asset.pk)
        self.assertEqual(row["identification_status"], "TO_REVIEW")
        self.assertEqual(row["candidate_count"], 1)
        self.assertEqual(row["unreviewed_count"], 1)

    def test_analyst_can_confirm_and_reject_with_shared_review_flow(self):
        run = self._complete()
        payload = {
            "run_id": run.pk, "cpe_name_id": self.cpe_id,
            "status": "CONFIRMED", "justification": "Inventario cotejado por analista",
        }
        decision = self.client.post(self.root + "cpes/", payload, format="json")
        self.assertEqual(decision.status_code, 201, decision.data)
        self.assertEqual(AssetCpe.objects.get(asset=self.asset).validation_status, "CONFIRMED")
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        overview = self.client.get("/api/vulnerabilities/cpe-overview/")
        row = next(r for r in overview.data["results"] if r["asset_id"] == self.asset.pk)
        self.assertEqual(row["identification_status"], "EVALUATED")
        self.assertEqual(row["confirmed_count"], 1)

        association = AssetCpe.objects.get(asset=self.asset)
        payload["status"] = "REJECTED"
        payload["justification"] = "Evidencia posterior descarta correspondencia"
        changed = self.client.patch(
            self.root + f"cpes/{association.pk}/", payload, format="json"
        )
        self.assertEqual(changed.status_code, 200, changed.data)
        self.assertEqual(AssetCpeDecision.objects.count(), 2)
        self.assertEqual(changed.data["association"]["validation_status"], "REJECTED")

    def test_software_version_change_requires_new_review(self):
        run = self._complete()
        self.asset.software.version = "12.10"
        self.asset.software.save(update_fields=["version"])
        detail = self.client.get(self.root + f"cpe-searches/{run.pk}/")
        self.assertFalse(detail.data["run"]["identity_is_current"])
        overview = self.client.get("/api/vulnerabilities/cpe-overview/")
        row = next(r for r in overview.data["results"] if r["asset_id"] == self.asset.pk)
        self.assertEqual(row["identification_status"], "STALE")

    def test_operator_can_read_but_not_start_or_confirm(self):
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.get(self.root + "cpe-searches/latest/").status_code, 200)
        self.assertEqual(self.client.post(self.root + "cpe-searches/",
                                         {"scope": "SPECIFIC"}, format="json").status_code, 403)
        self.assertEqual(CpeSearchRun.objects.count(), 0)

    def test_advanced_search_remains_hardware_only(self):
        self.assertEqual(
            self.client.post(self.root + "cpe-searches/advanced/",
                             {"strategy": "cpeMatchString",
                              "parameter": "cpe:2.3:o:cisco:ios:*"}, format="json").status_code,
            404,
        )
