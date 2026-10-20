"""Phase 1 CPE API and worker tests. All NVD calls are mocked."""
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from assets.models import Asset
from assets.services import register_hardware_asset
from .models import CpeSearchRun
from .services.identity import build_queries, fingerprint, hardware_identity
from .services.candidate_matching import merge_candidates
from .services.cpe_search import create_run, execute_run, serialize_run
from .services.nvd_client import PublicNvdPacer, NvdError


def nvd_record(suffix="1215c", uuid="cpe-id-1215c"):
    return {
        "cpe": {
            "cpeNameId": uuid,
            "cpeName": f"cpe:2.3:h:siemens:simatic_s7-1200_cpu_{suffix}:-:*:*:*:*:*:*:*",
            "deprecated": False,
            "titles": [{"lang": "en", "title": f"Siemens SIMATIC S7-1200 CPU {suffix.upper()}"}],
        }
    }


class IdentityTests(SimpleTestCase):
    def setUp(self):
        self.identity = {
            "asset_type": "HARDWARE",
            "manufacturer": " Siemens ",
            "model": "SIMATIC S7 1200",
            "cpu_model": "CPU 1215C",
            "role": "PLC",
        }

    def test_specific_queries_normalize_cpu_and_family_without_repetition(self):
        queries = build_queries(self.identity)
        self.assertEqual([q["strategy"] for q in queries], ["keywordSearch", "cpeMatchString"])
        self.assertIn("1215C", queries[0]["parameter"])
        self.assertEqual(queries[1]["parameter"],
                         "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c*")
        self.assertEqual(queries[0]["parameter"].lower().count("cpu"), 1)

    def test_broad_query_removes_cpu_and_unknown_cpu_uses_family(self):
        broad = build_queries(self.identity, "BROAD")
        self.assertNotIn("1215", broad[0]["parameter"])
        self.assertEqual(broad[1]["parameter"], "cpe:2.3:h:siemens:simatic_s7-1200*")
        without_cpu = {**self.identity, "cpu_model": ""}
        self.assertEqual(build_queries(without_cpu), broad)

    def test_fingerprint_tracks_only_technical_identity(self):
        base = self.identity
        self.assertEqual(fingerprint(base), fingerprint({**base, "model": "SIMATIC  S7-1200"}))
        self.assertNotEqual(fingerprint(base), fingerprint({**base, "cpu_model": "1214C"}))


class PacingTests(SimpleTestCase):
    def test_pacer_initial_wait_and_seven_second_spacing(self):
        time = [100.0]
        delays = []
        def wait(delay):
            delays.append(delay)
            time[0] += delay
        pacer = PublicNvdPacer(wait=wait, clock=lambda: time[0])
        calls = []
        for _ in range(6):
            pacer.pace()
            calls.append(time[0])
        self.assertEqual(calls, [130, 137, 144, 151, 158, 165])
        self.assertEqual(delays, [30, 7, 7, 7, 7, 7])

    def test_pacer_guard_blocks_requests_after_session_loss(self):
        guard = Mock(side_effect=RuntimeError("session lost"))
        pacer = PublicNvdPacer(wait=lambda n: None, clock=lambda: 100.0, guard=guard)
        with self.assertRaises(RuntimeError):
            pacer.pace()


class CpeSearchAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(username="cpe-operator", role=User.Role.OPERATOR)
        self.analyst = User.objects.create_user(username="cpe-analyst", role=User.Role.ANALYST)
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.asset = register_hardware_asset(
            data={
                "asset_type": "HARDWARE", "name": "PLC Siemens",
                "hardware": {
                    "manufacturer": "Siemens",
                    "model": "SIMATIC S7-1200",
                    "cpu_model": "1215C",
                    "role": "PLC",
                },
            },
            user=self.operator,
        )
        self.base = f"/api/vulnerabilities/assets/{self.asset.pk}/cpe-searches/"

    def test_search_locks_only_asset_without_joining_optional_hardware(self):
        """Prevent PostgreSQL's FOR UPDATE on nullable outer-joined hardware."""
        with CaptureQueriesContext(connection) as captured:
            run = create_run(self.asset.pk, self.analyst, "SPECIFIC")

        self.assertEqual(run.status, CpeSearchRun.Status.QUEUED)
        asset_queries = [
            entry["sql"] for entry in captured
            if 'FROM "assets_asset"' in entry["sql"]
            and entry["sql"].lstrip().upper().startswith("SELECT")
        ]
        self.assertEqual(len(asset_queries), 1, asset_queries)
        self.assertNotIn("JOIN", asset_queries[0].upper())
        if connection.vendor == "postgresql":
            self.assertIn("FOR UPDATE", asset_queries[0].upper())

    def test_request_is_queued_and_reuses_open_run(self):
        first = self.client.post(self.base, {"scope": "SPECIFIC"}, format="json")
        self.assertEqual(first.status_code, 202, first.data)
        self.assertEqual(first.data["status"], "QUEUED")
        second = self.client.post(self.base, {"scope": "SPECIFIC"}, format="json")
        self.assertEqual(second.status_code, 202, second.data)
        self.assertEqual(first.data["run_id"], second.data["run_id"])
        self.assertEqual(CpeSearchRun.objects.count(), 1)
        latest = self.client.get(self.base + "latest/")
        self.assertEqual(latest.status_code, 200)
        self.assertEqual(latest.data["run"]["id"], first.data["run_id"])
        self.assertTrue(latest.data["run"]["identity_is_current"])

    def test_roles_and_missing_identification(self):
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.post(self.base, {}, format="json").status_code, 403)
        self.assertEqual(self.client.get(self.base + "latest/").status_code, 200)
        self.client.force_authenticate(self.analyst)
        self.assertEqual(self.client.post(self.base, {"scope": "INVALID"}, format="json").status_code, 400)
        self.asset.hardware.manufacturer = ""
        self.asset.hardware.save(update_fields=["manufacturer"])
        self.assertEqual(self.client.post(self.base, {}, format="json").status_code, 400)
        self.assertFalse(CpeSearchRun.objects.exists())

    def test_worker_deduplicates_and_preserves_provenance(self):
        created = self.client.post(self.base, {}, format="json")
        run = CpeSearchRun.objects.get(pk=created.data["run_id"])
        calls = []
        def fake(strategy, parameter, start_index, pacer):
            calls.append((strategy, start_index))
            return {
                "products": [
                    nvd_record(),
                    *([nvd_record("1214c", "cpe-id-1214c")] if strategy == "cpeMatchString" else []),
                ],
                "totalResults": 1 if strategy == "keywordSearch" else 2,
            }
        execute_run(run, pacer=Mock(), fetcher=fake)
        self.assertEqual(run.status, CpeSearchRun.Status.COMPLETED)
        self.assertEqual(calls, [("keywordSearch", 0), ("cpeMatchString", 0)])
        self.assertEqual(len(run.candidates), 2)
        same = next(c for c in run.candidates if c["cpe_name_id"] == "cpe-id-1215c")
        self.assertEqual(same["methods"], ["cpeMatchString", "keywordSearch"])
        self.assertEqual(same["match_level"], "SPECIFIC")
        other = next(c for c in run.candidates if c["cpe_name_id"] == "cpe-id-1214c")
        self.assertEqual(other["match_level"], "POSSIBLE_INCOMPATIBILITY")
        read = self.client.get(self.base + str(run.pk) + "/")
        self.assertEqual(read.status_code, 200)
        self.assertEqual(read.data["run"]["candidate_count"], 2)

    def test_worker_fetches_remaining_pages_and_reports_errors(self):
        run = CpeSearchRun.objects.create(
            asset=self.asset, requested_by=self.analyst,
            identity_snapshot=hardware_identity(self.asset),
            identity_fingerprint=fingerprint(hardware_identity(self.asset)),
        )
        seen = []
        def fake(strategy, parameter, index, pacer):
            seen.append((strategy, index))
            if strategy == "keywordSearch":
                return {
                    "totalResults": 101,
                    "products": [nvd_record()] if index == 0 else [nvd_record("1214c", "other")],
                }
            return {"totalResults": 0, "products": []}
        execute_run(run, Mock(), fetcher=fake)
        self.assertEqual(run.status, "COMPLETED")
        self.assertIn(("keywordSearch", 100), seen)
        self.assertFalse(run.result_truncated)

        broken = CpeSearchRun.objects.create(
            asset=self.asset, requested_by=self.analyst,
            identity_snapshot=hardware_identity(self.asset),
            identity_fingerprint=fingerprint(hardware_identity(self.asset)),
        )
        def failure(*args):
            raise NvdError("HTTP 429")
        execute_run(broken, Mock(), fetcher=failure)
        self.assertEqual(broken.status, "FAILED")
        self.assertIn("429", broken.error_message)

    def test_stale_identity_after_cpu_change(self):
        response = self.client.post(self.base, {}, format="json")
        run = CpeSearchRun.objects.get(pk=response.data["run_id"])
        self.asset.hardware.cpu_model = "1214C"
        self.asset.hardware.save(update_fields=["cpu_model"])
        self.assertFalse(serialize_run(run)["identity_is_current"])


class NvdHttpClientTests(SimpleTestCase):
    def test_url_encoding_and_response_parsing_without_network(self):
        import io
        import json
        from .services.nvd_client import fetch_page, NVD_CPE_URL
        pacer = Mock()
        payload = {"products": [nvd_record()], "totalResults": 1}
        raw = io.BytesIO(json.dumps(payload).encode("utf-8"))
        with patch("vulnerabilities.services.nvd_client.urlopen", return_value=raw) as urlopen:
            result = fetch_page("cpeMatchString", "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c*", 0, pacer)
        self.assertEqual(result, payload)
        self.assertEqual(pacer.pace.call_count, 1)
        request = urlopen.call_args.args[0]
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 20)
        self.assertIn("services.nvd.nist.gov", request.full_url)
        self.assertIn("cpeMatchString=", request.full_url)
        self.assertIn("startIndex=0", request.full_url)

    def test_http_429_is_retried_with_pacing(self):
        import io
        import json
        from urllib.error import HTTPError
        from .services.nvd_client import fetch_page
        error = HTTPError("https://services.nvd.nist.gov", 429, "rate limit", {"Retry-After": "3"}, None)
        raw = io.BytesIO(json.dumps({"products": [], "totalResults": 0}).encode("utf-8"))
        pacer = Mock()
        with patch("vulnerabilities.services.nvd_client.urlopen", side_effect=[error, raw]):
            result = fetch_page("keywordSearch", "Siemens SIMATIC S7-1200", 0, pacer)
        self.assertEqual(result["products"], [])
        self.assertEqual(pacer.pace.call_count, 2)
        pacer.wait.assert_called_once_with(3)

    def test_bad_strategy_cannot_make_network_request(self):
        from .services.nvd_client import fetch_page
        with patch("vulnerabilities.services.nvd_client.urlopen") as urlopen:
            with self.assertRaises(ValueError):
                fetch_page("apiKey", "anything", 0, Mock())
        urlopen.assert_not_called()
