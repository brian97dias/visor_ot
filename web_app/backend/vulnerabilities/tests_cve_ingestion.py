"""First CVE increment: mocked NVD retrieval and exact configuration evidence."""
import copy
import io
import json
from datetime import timedelta
from decimal import Decimal
from io import BytesIO, StringIO
from unittest.mock import Mock, patch
from uuid import uuid4

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from vulnerabilities.models import Cpe, AssetCpe, Cve
from vulnerabilities.management.commands.run_cpe_worker import oldest_work_kind
from vulnerabilities.services.nvd_client import NvdError
from vulnerabilities.services.nvd_cve_client import (
    EXPERIMENTAL_CVE_ID, fetch_cve, NVD_CVE_URL,
)
from vulnerabilities.services.cve_ingestion import (
    CveResponseError, FIRMWARE_CRITERION, HARDWARE_CRITERION,
    enqueue_experimental_cve, execute_cve_fetch, find_experimental_configuration,
    validated_cve_payload,
)


def match(criteria, vulnerable, **version_bounds):
    return {
        "vulnerable": vulnerable, "criteria": criteria,
        "matchCriteriaId": str(uuid4()), **version_bounds,
    }


def configuration(firmware=FIRMWARE_CRITERION,
                  hardware=HARDWARE_CRITERION, firmware_vulnerable=True,
                  hardware_vulnerable=False, operator="AND"):
    return {
        "operator": operator, "negate": False,
        "nodes": [
            {"operator": "OR", "negate": False,
             "cpeMatch": [match(firmware, firmware_vulnerable)]},
            {"operator": "OR", "negate": False,
             "cpeMatch": [match(hardware, hardware_vulnerable)]},
        ],
    }


def nvd_fixture():
    different_firmware = "cpe:2.3:o:phoenixcontact:axl_f_bk_pn_firmware:*:*:*:*:*:*:*:*"
    different_hardware = "cpe:2.3:h:phoenixcontact:axl_f_bk_pn:-:*:*:*:*:*:*:*"
    other = configuration(different_firmware, different_hardware)
    other["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "1.30"
    configs = [copy.deepcopy(other) for _ in range(18)]
    configs[11] = configuration()
    cve = {
        "id": EXPERIMENTAL_CVE_ID,
        "published": "2021-06-25T19:15:09.697",
        "lastModified": "2024-11-21T01:09:02.000",
        "descriptions": [
            {"lang": "en", "value": "Undocumented password protected FTP access."},
            {"lang": "es", "value": "Acceso FTP no documentado."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {"source": "info@cert.vde.com", "type": "Secondary",
                 "cvssData": {"version": "3.1", "baseScore": 7.3,
                              "baseSeverity": "HIGH"}},
                {"source": "nvd@nist.gov", "type": "Primary",
                 "cvssData": {"version": "3.1", "baseScore": 7.3,
                              "baseSeverity": "HIGH"}},
            ],
            "cvssMetricV2": [{"type": "Primary",
                              "cvssData": {"version": "2.0", "baseScore": 7.5},
                              "baseSeverity": "HIGH"}],
        },
        "configurations": configs,
        "references": [{"url": "https://cert.vde.com/en-us/advisories/vde-2021-021",
                        "tags": ["Third Party Advisory"]}],
    }
    return {"totalResults": 1, "resultsPerPage": 1,
            "vulnerabilities": [{"cve": cve}]}


class CveConfigurationParsingTests(SimpleTestCase):
    def test_target_and_node_criteria_are_found_without_losing_original_json(self):
        payload = nvd_fixture()
        original = copy.deepcopy(payload["vulnerabilities"][0]["cve"]["configurations"])
        values, target = validated_cve_payload(payload)
        self.assertEqual(target["position"], 12)
        self.assertEqual(target["index"], 11)
        self.assertEqual(target["configuration"]["operator"], "AND")
        self.assertEqual(target["firmware"]["criteria"], FIRMWARE_CRITERION)
        self.assertIs(target["firmware"]["vulnerable"], True)
        self.assertEqual(target["hardware"]["criteria"], HARDWARE_CRITERION)
        self.assertIs(target["hardware"]["vulnerable"], False)
        self.assertIn("matchCriteriaId", target["firmware"])
        self.assertEqual(values["configurations"], original)
        self.assertEqual(values["configurations"][0]["nodes"][0]["cpeMatch"][0][
            "versionEndExcluding"], "1.30")

    def test_config_is_identified_by_criteria_not_array_position(self):
        configs = nvd_fixture()["vulnerabilities"][0]["cve"]["configurations"]
        configs.append(configs.pop(11))
        target = find_experimental_configuration(configs)
        self.assertEqual(target["position"], 18)
        self.assertEqual(target["firmware"]["criteria"], FIRMWARE_CRITERION)

    def test_negative_platform_condition_is_not_ignored_or_misread(self):
        configs = [configuration(hardware_vulnerable=True)]
        with self.assertRaises(CveResponseError):
            find_experimental_configuration(configs)
        configs = [configuration(operator="OR")]
        with self.assertRaises(CveResponseError):
            find_experimental_configuration(configs)
        configs = [configuration()]
        configs[0]["negate"] = True
        with self.assertRaises(CveResponseError):
            find_experimental_configuration(configs)

    def test_and_parent_with_one_or_child_does_not_mean_both_conditions(self):
        # A single OR operand holding both CPEs would mean hardware OR
        # firmware, not the conjunctive applicability scenario.
        wrong = configuration()
        wrong["nodes"] = [
            {"operator": "OR", "negate": False,
             "cpeMatch": [*wrong["nodes"][0]["cpeMatch"],
                          *wrong["nodes"][1]["cpeMatch"]]},
        ]
        with self.assertRaises(CveResponseError):
            find_experimental_configuration([wrong])

    def test_duplicate_or_missing_scenario_is_rejected(self):
        with self.assertRaises(CveResponseError):
            find_experimental_configuration([configuration(), configuration()])
        with self.assertRaises(CveResponseError):
            find_experimental_configuration([])
        with self.assertRaises(CveResponseError):
            find_experimental_configuration([configuration(
                firmware="cpe:2.3:o:phoenixcontact:different_firmware:*:*:*:*:*:*:*:*"
            )])

    def test_cve_identity_and_envelope_must_be_exact(self):
        fixture = nvd_fixture()
        fixture["vulnerabilities"][0]["cve"]["id"] = "CVE-2021-00001"
        with self.assertRaises(CveResponseError):
            validated_cve_payload(fixture)
        for broken in (
            {"totalResults": 0, "vulnerabilities": []},
            {"totalResults": 1, "vulnerabilities": []},
            {"totalResults": 2, "vulnerabilities": nvd_fixture()["vulnerabilities"]},
        ):
            with self.subTest(value=broken):
                with self.assertRaises(CveResponseError):
                    validated_cve_payload(broken)

    def test_dates_and_cvss_v31_preferred_with_all_metrics_preserved(self):
        data = nvd_fixture()
        values, _ = validated_cve_payload(data)
        self.assertEqual(values["base_score"], Decimal("7.3"))
        self.assertEqual(values["severity"], "HIGH")
        self.assertEqual(values["published"].year, 2021)
        self.assertIsNotNone(values["published"].tzinfo)
        self.assertEqual(len(values["metrics"]["cvssMetricV31"]), 2)
        self.assertEqual(len(values["metrics"]["cvssMetricV2"]), 1)
        self.assertEqual(len(values["references"]), 1)
        data["vulnerabilities"][0]["cve"]["published"] = "not a timestamp"
        with self.assertRaises(CveResponseError):
            validated_cve_payload(data)


class NvdCveApiTests(SimpleTestCase):
    def test_cve_client_uses_official_id_and_shared_pacer(self):
        body = json.dumps(nvd_fixture()).encode("utf-8")
        pacer = Mock()
        with patch("vulnerabilities.services.nvd_cve_client.urlopen",
                   return_value=BytesIO(body)) as urlopen:
            response = fetch_cve(EXPERIMENTAL_CVE_ID, pacer)
        self.assertEqual(response["totalResults"], 1)
        self.assertEqual(pacer.pace.call_count, 1)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url,
                         NVD_CVE_URL + "?cveId=CVE-2021-33540")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 20)

    def test_only_experimental_identifier_is_allowed_without_network(self):
        pacer = Mock()
        with patch("vulnerabilities.services.nvd_cve_client.urlopen") as urlopen:
            with self.assertRaises(ValueError):
                fetch_cve("CVE-2021-00001", pacer)
            urlopen.assert_not_called()
            pacer.pace.assert_not_called()

    def test_retries_use_same_pacer_and_final_error_is_not_not_found(self):
        from urllib.error import URLError
        pacer = Mock()
        with patch("vulnerabilities.services.nvd_cve_client.urlopen",
                   side_effect=URLError("offline")):
            with self.assertRaises(NvdError):
                fetch_cve(EXPERIMENTAL_CVE_ID, pacer)
        self.assertEqual(pacer.pace.call_count, 2)


class CveWorkerPersistenceTests(TestCase):
    def test_enqueue_is_explicit_idempotent_and_does_not_call_nvd(self):
        with patch("vulnerabilities.services.nvd_cve_client.urlopen") as remote:
            first, reused = enqueue_experimental_cve()
            second, reused_again = enqueue_experimental_cve()
        self.assertFalse(reused)
        self.assertTrue(reused_again)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(Cve.objects.count(), 1)
        self.assertEqual(first.fetch_status, Cve.FetchStatus.QUEUED)
        remote.assert_not_called()

    def test_worker_persists_all_18_configurations_without_creating_cpes(self):
        queued, _ = enqueue_experimental_cve()
        pacer = object()
        fetcher = Mock(return_value=nvd_fixture())
        done = execute_cve_fetch(queued, pacer, fetcher=fetcher)
        fetcher.assert_called_once_with(EXPERIMENTAL_CVE_ID, pacer)
        done.refresh_from_db()
        self.assertEqual(done.fetch_status, Cve.FetchStatus.COMPLETED)
        self.assertIsNotNone(done.retrieved_at)
        self.assertEqual(done.description, "Undocumented password protected FTP access.")
        self.assertEqual(len(done.configurations), 18)
        self.assertEqual(done.nvd_record,
                         nvd_fixture()["vulnerabilities"][0]["cve"])
        self.assertEqual(find_experimental_configuration(done.configurations)["position"], 12)
        self.assertEqual(done.severity, "HIGH")
        self.assertEqual(done.base_score, Decimal("7.3"))
        self.assertEqual(Cpe.objects.count(), 0)
        self.assertEqual(AssetCpe.objects.count(), 0)

    def test_same_completed_cve_is_not_retrieved_twice_unless_refresh(self):
        first, _ = enqueue_experimental_cve()
        execute_cve_fetch(first, object(), fetcher=Mock(return_value=nvd_fixture()))
        same, reused = enqueue_experimental_cve()
        self.assertTrue(reused)
        self.assertEqual(same.fetch_status, Cve.FetchStatus.COMPLETED)
        refreshed, reused = enqueue_experimental_cve(refresh=True)
        self.assertFalse(reused)
        self.assertEqual(refreshed.pk, same.pk)
        self.assertEqual(refreshed.fetch_status, Cve.FetchStatus.QUEUED)

    def test_timeout_or_malformed_data_does_not_certify_cve_or_partial_evidence(self):
        for fixture in (None, {"totalResults": 0, "vulnerabilities": []}):
            job, _ = enqueue_experimental_cve(refresh=True)
            fetcher = Mock(side_effect=NvdError("HTTP 503")) if fixture is None else Mock(return_value=fixture)
            result = execute_cve_fetch(job, object(), fetcher=fetcher)
            self.assertEqual(result.fetch_status, Cve.FetchStatus.FAILED)
            self.assertTrue(result.fetch_error)
            self.assertIsNone(result.retrieved_at)
            self.assertEqual(result.configurations, [])

    def test_failed_refresh_keeps_previous_verified_data_but_not_completed_status(self):
        job, _ = enqueue_experimental_cve()
        execute_cve_fetch(job, object(), fetcher=Mock(return_value=nvd_fixture()))
        job, _ = enqueue_experimental_cve(refresh=True)
        failed = execute_cve_fetch(job, object(), fetcher=Mock(side_effect=TimeoutError()))
        self.assertEqual(failed.fetch_status, Cve.FetchStatus.FAILED)
        self.assertIn("TimeoutError", failed.fetch_error)
        self.assertEqual(len(failed.configurations), 18)
        self.assertIsNotNone(failed.retrieved_at)
        self.assertEqual(Cve.objects.count(), 1)

    def test_enqueue_management_command_does_not_directly_call_nvd(self):
        with patch("vulnerabilities.services.nvd_cve_client.urlopen") as remote:
            output = StringIO()
            call_command("enqueue_cve_2021_33540", stdout=output)
            self.assertIn("CVE-2021-33540", output.getvalue())
            self.assertEqual(Cve.objects.filter(fetch_status="QUEUED").count(), 1)
            remote.assert_not_called()


class WorkerSchedulingTests(SimpleTestCase):
    def test_cve_and_cpe_use_same_worker_queue_without_reordering_old_tasks(self):
        now = timezone.now()
        # Real CpeSearchRun.queries is a list; a bare Mock is not subscriptable.
        run = Mock(created_at=now, queries=[])
        snapshot = Mock(created_at=now + timedelta(seconds=2))
        cve = Mock(queued_at=now + timedelta(seconds=1))
        self.assertEqual(oldest_work_kind(run, snapshot, cve), "ASSET")
        self.assertEqual(oldest_work_kind(None, snapshot, cve), "CVE")
        self.assertEqual(oldest_work_kind(None, snapshot, None), "SNAPSHOT")
        self.assertEqual(oldest_work_kind(run, None, None), "ASSET")
        self.assertEqual(oldest_work_kind(None, None, cve), "CVE")
        self.assertIsNone(oldest_work_kind(None, None, None))
