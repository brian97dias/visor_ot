"""Phase 4: controlled manual CPE searches, no live NVD requests."""
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient

from assets.models import Asset
from assets.services import register_hardware_asset
from vulnerabilities.models import CpeSearchRun
from vulnerabilities.services.advanced_query import validate_advanced_query
from vulnerabilities.services.cpe_search import (
    create_run, execute_run,
)
from vulnerabilities.services.identity import fingerprint, hardware_identity

SIEMENS = {
    "asset_type": "HARDWARE", "manufacturer": "Siemens",
    "model": "SIMATIC S7-1200", "cpu_model": "1215C", "role": "PLC",
}
ROCKWELL = {
    "asset_type": "HARDWARE", "manufacturer": "Rockwell Automation",
    "model": "1783-EMS08T/B", "cpu_model": "", "role": "SWITCH",
}
AXIS = {
    "asset_type": "HARDWARE", "manufacturer": "Axis Communications",
    "model": "AXIS 206", "cpu_model": "", "role": "CAMERA",
}


def product(uuid, vendor, name, part="h"):
    return {"cpe": {
        "cpeNameId": uuid,
        "cpeName": f"cpe:2.3:{part}:{vendor}:{name}:-:*:*:*:*:*:*:*",
        "deprecated": False,
        "titles": [{"lang": "en", "title": f"{vendor} {name}"}],
    }}


def response(products, total=None):
    return {"products": products, "totalResults": len(products) if total is None else total}


def queued(identity, request):
    return SimpleNamespace(
        trigger="ADVANCED", status="QUEUED", scope="SPECIFIC",
        identity_snapshot=identity, queries=[{**request, "level": "ADVANCED", "status": "PLANNED"}],
        candidates=[], result_truncated=False, error_message="",
        save=lambda update_fields: None,
    )


class AdvancedQueryValidationTests(SimpleTestCase):
    def test_keyword_can_use_verified_manufacturer_word(self):
        self.assertEqual(
            validate_advanced_query(ROCKWELL, {"strategy": "keywordSearch", "parameter": " Rockwell "}),
            {"strategy": "keywordSearch", "parameter": "Rockwell", "start_index": 0, "max_pages": 1},
        )
        self.assertEqual(
            validate_advanced_query(AXIS, {"strategy": "keywordSearch", "parameter": "AXIS 206"})["parameter"],
            "AXIS 206",
        )

    def test_cpe_vendor_alias_hardware_and_prefix_are_allowed(self):
        for manufacturer in ("rockwellautomation", "rockwell_automation", "rockwell-automation"):
            value = validate_advanced_query(ROCKWELL, {
                "strategy": "cpeMatchString", "parameter": f"cpe:2.3:h:{manufacturer}:1783*",
                "start_index": 100, "max_pages": 3,
            })
            self.assertEqual(value["start_index"], 100)
            self.assertEqual(value["max_pages"], 3)
        self.assertEqual(validate_advanced_query(SIEMENS, {
            "strategy": "cpeMatchString", "parameter": "cpe:2.3:h:siemens",
        })["parameter"], "cpe:2.3:h:siemens")

    def test_untrusted_queries_cannot_change_vendor_part_or_url(self):
        bad = [
            {"strategy": "keywordSearch", "parameter": "Apache"},
            {"strategy": "keywordSearch", "parameter": "https://services.nvd.nist.gov"},
            {"strategy": "cpeMatchString", "parameter": "cpe:2.3:o:rockwellautomation:factorytalk*"},
            {"strategy": "cpeMatchString", "parameter": "cpe:2.3:h:someone_else:1783*"},
            {"strategy": "cpeMatchString", "parameter": "cpe:2.3:h:rockwellautomation:1783*:*:*"},
            {"strategy": "keywordSearch", "parameter": "Rockwell", "api_url": "https://example.org"},
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_advanced_query(ROCKWELL, data)

    def test_page_bounds_reject_injection_and_invalid_types(self):
        base = {"strategy": "keywordSearch", "parameter": "Siemens"}
        for more in (
            {"max_pages": 0}, {"max_pages": 4}, {"max_pages": True},
            {"start_index": 50}, {"start_index": 10100},
            {"start_index": -100}, {"start_index": "100"}, {"start_index": True},
        ):
            with self.subTest(more=more), self.assertRaises(ValueError):
                validate_advanced_query(SIEMENS, {**base, **more})


class AdvancedWorkerTests(SimpleTestCase):
    def test_rockwell_related_is_not_confirmed_and_records_provenance(self):
        run = queued(ROCKWELL, {
            "strategy": "cpeMatchString", "parameter": "cpe:2.3:h:rockwellautomation:1783*",
            "start_index": 0, "max_pages": 1,
        })
        calls = []
        def fetch(strategy, parameter, index, pacer):
            calls.append((strategy, parameter, index))
            return response([product("uuid-r", "rockwellautomation", "1783-natr"),
                             product("uuid-a", "rockwellautomation", "1784-natr"),
                             product("uuid-o", "rockwellautomation", "1783-software", part="a")])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(run.candidates[0]["match_level"], "RELATED")
        self.assertEqual(run.candidates[0]["discovery_levels"], ["ADVANCED"])
        self.assertEqual(run.queries[0]["filtered_hardware_results"], 1)
        self.assertEqual(run.queries[0]["level"], "ADVANCED")

    def test_offset_is_respected_and_partial_even_if_last_page(self):
        run = queued(SIEMENS, {
            "strategy": "keywordSearch", "parameter": "Siemens",
            "start_index": 200, "max_pages": 1,
        })
        seen = []
        def fetch(strategy, parameter, start, pacer):
            seen.append(start)
            return response([product("uuid-c", "siemens", "simatic_s7-1200_cpu_1215c")],
                            total=201)
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(seen, [200])
        self.assertTrue(run.result_truncated)
        self.assertEqual(run.queries[0]["status"], "PARTIAL")
        self.assertEqual(run.queries[0]["stop_reason"], "ADVANCED_OFFSET")

    def test_page_limit_and_pagination_continue_with_persisted_index(self):
        run = queued(SIEMENS, {
            "strategy": "keywordSearch", "parameter": "Siemens",
            "start_index": 100, "max_pages": 2,
        })
        seen = []
        def fetch(strategy, parameter, start, pacer):
            seen.append(start)
            return response([
                product(f"uuid-{start}-{i}", "siemens", "simatic_s7-1200_cpu_1215c")
                for i in range(100)
            ], total=500)
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(seen, [100, 200])
        self.assertEqual(run.queries[0]["pages"], 2)
        self.assertEqual(run.queries[0]["stop_reason"], "ADVANCED_PAGE_LIMIT")
        self.assertTrue(run.result_truncated)

    def test_timeout_remains_failed_and_preserves_original_request(self):
        plan = {"strategy": "keywordSearch", "parameter": "Siemens", "start_index": 0, "max_pages": 1}
        run = queued(SIEMENS, plan)
        def fail(*args):
            raise TimeoutError("NVD timeout")
        execute_run(run, object(), fetcher=fail)
        self.assertEqual(run.status, "FAILED")
        self.assertEqual(run.queries[0]["parameter"], "Siemens")
        self.assertEqual(run.queries[0]["status"], "FAILED")
        self.assertEqual(run.queries[0]["stop_reason"], "REQUEST_FAILED")

    def test_invalid_queued_json_does_not_call_nvd(self):
        run = queued(ROCKWELL, {"strategy": "cpeMatchString", "parameter": "cpe:2.3:h:evil"})
        fetch = lambda *args: self.fail("NVD must never be called")
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "FAILED")
        self.assertIn("fabricante", run.error_message.lower())


class RetiredAdvancedApiTests(TestCase):
    """Manual CPE queries cannot be created through HTTP anymore."""

    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(username="retired-advanced-analyst", role=User.Role.ANALYST)
        self.operator = User.objects.create_user(username="retired-advanced-operator", role=User.Role.OPERATOR)
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.asset = register_hardware_asset(
            data={"asset_type": "HARDWARE", "name": "PLC Siemens",
                  "hardware": {"manufacturer": "Siemens", "model": "SIMATIC S7-1200",
                               "cpu_model": "1215C", "role": "PLC"}},
            user=self.operator,
        )

    def test_retired_endpoint_is_unavailable_and_creates_nothing(self):
        url = f"/api/vulnerabilities/assets/{self.asset.pk}/cpe-searches/advanced/"
        result = self.client.post(url, {"strategy": "keywordSearch",
                                        "parameter": "Siemens"}, format="json")
        self.assertEqual(result.status_code, 404)
        self.assertFalse(CpeSearchRun.objects.exists())

    def test_new_search_does_not_accept_broad_scope(self):
        url = f"/api/vulnerabilities/assets/{self.asset.pk}/cpe-searches/"
        response = self.client.post(url, {"scope": "BROAD"}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(CpeSearchRun.objects.exists())
        response = self.client.post(url, {"scope": "SPECIFIC"}, format="json")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(CpeSearchRun.objects.count(), 1)
