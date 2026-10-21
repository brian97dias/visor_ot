"""Legacy progressive-engine regressions, retained for historical compatibility."""
from types import SimpleNamespace

from django.test import SimpleTestCase

from .services.identity import (
    build_level_queries, family_term, vendor_variants, catalog_code_prefix, fingerprint,
)
from .services.candidate_matching import normalize_candidate, is_pertinent, is_manufacturer_related
from .services.cpe_search import execute_legacy_run as execute_run, MAX_TOTAL_PAGE_FETCHES


SIEMENS = {
    "asset_type": "HARDWARE", "manufacturer": "Siemens",
    "model": "SIMATIC S7-1200", "cpu_model": "1215C", "role": "PLC",
}
ADAM = {
    "asset_type": "HARDWARE", "manufacturer": "Advantech",
    "model": "ADAM-5000 Series", "cpu_model": "", "role": "PLC",
}


def product(uuid, vendor, name, kind="h"):
    return {"cpe": {
        "cpeNameId": uuid,
        "cpeName": f"cpe:2.3:{kind}:{vendor}:{name}:-:*:*:*:*:*:*:*",
        "deprecated": False,
        "titles": [{"lang": "en", "title": f"{vendor} {name}"}],
    }}


def response(products, total=None):
    return {"products": products, "totalResults": len(products) if total is None else total}


def queued(identity, scope="SPECIFIC"):
    # No database dependency: execute_run only mutates and saves this object.
    return SimpleNamespace(
        identity_snapshot=identity, scope=scope, status="QUEUED",
        queries=[], candidates=[], result_truncated=False, error_message="",
        save=lambda update_fields: None,
    )


class ProgressiveDiscoveryTests(SimpleTestCase):
    def test_siemens_specific_success_keeps_two_original_strategies(self):
        run = queued(SIEMENS)
        seen = []
        match = product("official-1215c", "siemens", "simatic_s7-1200_cpu_1215c")
        def fetch(strategy, parameter, index, pacer):
            seen.append((strategy, parameter, index))
            return response([match])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(seen), 2)
        self.assertEqual([q["level"] for q in run.queries], ["SPECIFIC", "SPECIFIC"])
        self.assertEqual(run.queries[-1]["level_result"], "SUFFICIENT_PERTINENT_CANDIDATES")
        self.assertEqual(run.candidates[0]["methods"], ["cpeMatchString", "keywordSearch"])
        self.assertEqual(run.candidates[0]["discovery_levels"], ["SPECIFIC"])
        self.assertFalse(run.result_truncated)

    def test_specific_without_strong_match_expands_to_adam_family(self):
        run = queued(ADAM)
        seen = []
        related = product("adam-5550", "advantech", "adam-5550")
        irrelevant = product("firmware", "advantech", "adam-5550_firmware", kind="o")
        def fetch(strategy, parameter, index, pacer):
            seen.append((strategy, parameter))
            return response([related, irrelevant]) if "advantech:adam*" in parameter or parameter == "Advantech ADAM" else response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(seen), 5)
        self.assertIn(("cpeMatchString", "cpe:2.3:h:advantech"), seen)
        self.assertIn(("keywordSearch", "Advantech ADAM"), seen)
        self.assertIn(("cpeMatchString", "cpe:2.3:h:advantech:adam*"), seen)
        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(run.candidates[0]["match_level"], "RELATED")
        self.assertEqual(run.candidates[0]["discovery_levels"], ["FAMILY"])
        self.assertEqual(run.queries[0]["next_level_reason"], "NO_PERTINENT_CANDIDATES")
        self.assertEqual(run.queries[2]["related_results"], 1)
        self.assertFalse(is_pertinent(run.candidates[0], ADAM))

    def test_broad_starts_at_family_without_specific(self):
        run = queued(ADAM, scope="BROAD")
        execute_run(run, object(), fetcher=lambda *args: response([]))
        self.assertEqual(len(run.queries), 3)
        self.assertEqual([q["level"] for q in run.queries], ["FAMILY", "FAMILY", "MANUFACTURER"])
        self.assertIn("advantech:adam*", run.queries[1]["parameter"])
        self.assertEqual(run.queries[2]["parameter"], "cpe:2.3:h:advantech")

    def test_missing_cpu_and_no_broader_family_does_not_repeat_queries(self):
        run = queued({**SIEMENS, "cpu_model": ""})
        seen = []
        def fetch(strategy, parameter, index, pacer):
            seen.append((strategy, parameter))
            return response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(len(seen), 3)
        self.assertFalse(run.result_truncated)
        self.assertEqual(run.queries[1]["next_level_reason"], "NO_NEW_PARAMETERS")
        self.assertEqual(run.queries[-1]["level"], "MANUFACTURER")

    def test_model_numbers_are_never_silently_equal(self):
        self.assertEqual(family_term("ADAM-5000 Series"), "ADAM")
        self.assertEqual(family_term("ADAM-5000"), "ADAM-5000")
        self.assertEqual(family_term("SIMATIC S7-1200"), "SIMATIC S7-1200")
        self.assertEqual(build_level_queries(ADAM, "FAMILY")[1]["parameter"],
                         "cpe:2.3:h:advantech:adam*")
        item = normalize_candidate(product("x", "siemens", "simatic_s7-1200_cpu_12_1215c"),
                                   SIEMENS, "keywordSearch")
        self.assertFalse(is_pertinent(item, SIEMENS))

    def test_partial_specific_pages_do_not_trigger_family(self):
        run = queued(ADAM)
        seen = []
        ignored = product("fw", "advantech", "adam-5000", kind="o")
        def fetch(strategy, parameter, index, pacer):
            seen.append((strategy, index))
            return response([ignored] * 100, total=900)
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertTrue(run.result_truncated)
        self.assertEqual(len(seen), 3)
        self.assertEqual({q["level"] for q in run.queries}, {"SPECIFIC"})
        self.assertEqual(run.queries[0]["status"], "PARTIAL")
        self.assertEqual(run.queries[0]["stop_reason"], "PER_STRATEGY_PAGE_LIMIT")

    def test_failed_request_preserves_partial_evidence_and_never_falls_back(self):
        run = queued(ADAM)
        first = product("adam-5550", "advantech", "adam-5550")
        calls = []
        def fetch(strategy, parameter, index, pacer):
            calls.append(strategy)
            if strategy == "keywordSearch":
                return response([first])
            raise TimeoutError("NVD timeout")
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "FAILED")
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(run.candidates), 1)
        self.assertIn("timeout", run.error_message)
        self.assertEqual(run.queries[-1]["status"], "FAILED")
        self.assertEqual(run.queries[-1]["stop_reason"], "REQUEST_FAILED")

    def test_page_budget_is_global_across_levels(self):
        run = queued(ADAM)
        seen = []
        # 3 pages for both precise strategies (totalResults=201), then only
        # 2 available out of the family strategy's 3 required pages.
        other = product("wrong-vendor", "somevendor", "other")
        def fetch(strategy, parameter, index, pacer):
            seen.append((strategy, parameter, index))
            return response([other] * (1 if index == 200 else 100), total=201)
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(len(seen), MAX_TOTAL_PAGE_FETCHES)
        self.assertTrue(run.result_truncated)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(run.queries[-1]["stop_reason"], "GLOBAL_PAGE_LIMIT")
        self.assertEqual(run.queries[-1]["level_result"], "PARTIAL_RESULTS")

    def test_concrete_model_without_cpu_is_sufficient_when_exact(self):
        run = queued({**SIEMENS, "cpu_model": ""})
        exact = product("exact", "siemens", "simatic_s7-1200")
        execute_run(run, object(), fetcher=lambda *args: response([exact]))
        self.assertEqual(run.queries[0]["level_result"], "SUFFICIENT_PERTINENT_CANDIDATES")
        self.assertEqual(len(run.queries), 2)

class ManufacturerDiscoveryTests(SimpleTestCase):
    """Phase 2: bounded manufacturer-level hardware discovery, fully offline."""

    def test_manufacturer_query_is_hardware_only_and_product_agnostic(self):
        self.assertEqual(
            build_level_queries(ADAM, "MANUFACTURER"),
            [{"strategy": "cpeMatchString", "parameter": "cpe:2.3:h:advantech"}],
        )
        rockwell = build_level_queries(
            {**SIEMENS, "manufacturer": "Rockwell Automation"}, "MANUFACTURER"
        )
        self.assertEqual(rockwell[0]["parameter"], "cpe:2.3:h:rockwellautomation")
        self.assertIn(
            {"strategy": "cpeMatchString", "parameter": "cpe:2.3:h:rockwell_automation"},
            rockwell,
        )

    def test_specific_and_family_insufficient_discover_related_adam_5550_by_manufacturer(self):
        run = queued(ADAM)
        calls = []
        related = product("uuid-5550", "advantech", "adam-5550")
        unrelated = product("uuid-different-model", "advantech", "pcm_700")
        wrong_vendor = product("uuid-wrong-vendor", "someone_else", "adam-5550")
        firmware = product("uuid-firmware", "advantech", "adam-5550_firmware", kind="o")

        def fetch(strategy, parameter, index, pacer):
            calls.append((strategy, parameter, index))
            if parameter == "cpe:2.3:h:advantech":
                return response([related, unrelated, wrong_vendor, firmware])
            return response([])

        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertFalse(run.result_truncated)
        self.assertEqual(len(calls), 5)
        self.assertEqual([r["cpe_name_id"] for r in run.candidates], ["uuid-5550"])
        self.assertEqual(run.candidates[0]["match_level"], "RELATED")
        self.assertEqual(run.candidates[0]["discovery_levels"], ["MANUFACTURER"])
        details = run.queries[-1]
        self.assertEqual(details["status"], "COMPLETED")
        self.assertEqual(details["level_result"], "NO_PERTINENT_CANDIDATES")
        self.assertEqual(details["hardware_results"], 3)
        self.assertEqual(details["filtered_hardware_results"], 2)
        self.assertEqual(details["related_results"], 1)

    def test_broad_begins_with_family_and_falls_back_to_manufacturer(self):
        run = queued(ADAM, scope="BROAD")
        seen = []
        def fetch(strategy, parameter, index, pacer):
            seen.append(parameter)
            return response([product("uuid-related", "advantech", "adam-5550")]) \
                if parameter == "cpe:2.3:h:advantech" else response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(
            [q["level"] for q in run.queries], ["FAMILY", "FAMILY", "MANUFACTURER"]
        )
        self.assertNotIn("Advantech ADAM-5000 Series", seen)
        self.assertEqual(run.candidates[0]["discovery_levels"], ["MANUFACTURER"])

    def test_strong_family_candidate_prevents_costly_manufacturer_search(self):
        run = queued(ADAM, scope="BROAD")
        exact = product("uuid-full-family", "advantech", "adam5000series")
        seen = []
        def fetch(strategy, parameter, index, pacer):
            seen.append(parameter)
            return response([exact])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertTrue(run.queries[0]["level_result"] == "SUFFICIENT_PERTINENT_CANDIDATES"
                        or run.queries[-1]["level_result"] == "SUFFICIENT_PERTINENT_CANDIDATES")
        self.assertEqual(len(seen), 2)
        self.assertNotIn("cpe:2.3:h:advantech", seen)

    def test_manufacturer_pagination_is_partial_not_no_results(self):
        run = queued(ADAM)
        pages = []
        # 300 manufacturer CPEs: only the first 2 pages may be read.
        unrelated = [
            product(f"unrelated-{i}", "advantech", f"pcm_model_{i}")
            for i in range(100)
        ]
        def fetch(strategy, parameter, index, pacer):
            pages.append((parameter, index))
            if parameter == "cpe:2.3:h:advantech":
                return response(unrelated, total=300)
            return response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertTrue(run.result_truncated)
        self.assertEqual([p[1] for p in pages if p[0] == "cpe:2.3:h:advantech"], [0, 100])
        self.assertEqual(len(run.candidates), 0)
        last = run.queries[-1]
        self.assertEqual(last["status"], "PARTIAL")
        self.assertEqual(last["stop_reason"], "MANUFACTURER_PAGE_LIMIT")
        self.assertEqual(last["level_result"], "PARTIAL_RESULTS")
        self.assertEqual(last["filtered_hardware_results"], 200)

    def test_manufacturer_http_failure_does_not_claim_no_results(self):
        run = queued(ADAM)
        def fetch(strategy, parameter, index, pacer):
            if parameter == "cpe:2.3:h:advantech":
                raise TimeoutError("NVD manufacturer lookup timeout")
            return response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "FAILED")
        self.assertIn("timeout", run.error_message)
        self.assertEqual(run.queries[-1]["status"], "FAILED")
        self.assertEqual(run.queries[-1]["stop_reason"], "REQUEST_FAILED")

    def test_shared_page_budget_includes_manufacturer_level(self):
        from unittest.mock import patch
        from .services import cpe_search

        run = queued(ADAM)
        pages = []
        related = product("uuid-r", "advantech", "adam-5550")
        def fetch(strategy, parameter, index, pacer):
            pages.append((parameter, index))
            if parameter == "cpe:2.3:h:advantech":
                return response([related] * 100, total=500)
            return response([])
        with patch.object(cpe_search, "MAX_TOTAL_PAGE_FETCHES", 5):
            execute_run(run, object(), fetcher=fetch)
        self.assertEqual(len(pages), 5)
        self.assertTrue(run.result_truncated)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(run.candidates[0]["cpe_name_id"], "uuid-r")
        self.assertEqual(run.queries[-1]["stop_reason"], "GLOBAL_PAGE_LIMIT")
        self.assertEqual(run.queries[-1]["level_result"], "PARTIAL_RESULTS")

    def test_same_uuid_from_three_levels_keeps_one_candidate_with_full_provenance(self):
        run = queued(ADAM)
        related = product("uuid-same", "advantech", "adam-5550")
        def fetch(strategy, parameter, index, pacer):
            return response([related])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(
            run.candidates[0]["discovery_levels"], ["FAMILY", "MANUFACTURER", "SPECIFIC"]
        )
        self.assertEqual(run.candidates[0]["methods"], ["cpeMatchString", "keywordSearch"])
        self.assertEqual(len(run.queries), 5)


class ManufacturerAliasRefinementTests(SimpleTestCase):
    """Hardware vendor aliases, numeric catalog codes and global NVD budgets."""

    ROCKWELL = {
        "asset_type": "HARDWARE", "manufacturer": "Rockwell Automation",
        "model": "1783-EMS08T/B", "cpu_model": "", "role": "SWITCH",
    }
    AXIS = {
        "asset_type": "HARDWARE", "manufacturer": "Axis Communications",
        "model": "AXIS 206", "cpu_model": "", "role": "CAMERA",
    }

    def test_vendor_variants_are_bounded_and_do_not_change_identity(self):
        self.assertEqual(vendor_variants("Rockwell Automation"), [
            "rockwellautomation", "rockwell_automation", "rockwell-automation",
        ])
        self.assertEqual(vendor_variants("Axis Communications"), [
            "axis", "axis_communications", "axiscommunications", "axis-communications",
        ])
        self.assertEqual(vendor_variants("Siemens"), ["siemens"])
        old = fingerprint(self.ROCKWELL)
        build_level_queries(self.ROCKWELL, "MANUFACTURER")
        self.assertEqual(fingerprint(self.ROCKWELL), old)

    def test_numeric_catalog_prefix_does_not_infer_numeric_proximity(self):
        self.assertEqual(catalog_code_prefix("1783-EMS08T/B"), "1783")
        self.assertEqual(catalog_code_prefix("AXIS 206"), "")
        self.assertEqual(catalog_code_prefix("SIMATIC S7-1200"), "")
        self.assertEqual(catalog_code_prefix("206"), "")

    def test_rockwell_queries_prefer_specific_catalog_variants(self):
        params = [q["parameter"] for q in build_level_queries(self.ROCKWELL, "MANUFACTURER")]
        self.assertEqual(params[:3], [
            "cpe:2.3:h:rockwellautomation:1783*",
            "cpe:2.3:h:rockwell_automation:1783*",
            "cpe:2.3:h:rockwell-automation:1783*",
        ])
        self.assertEqual(params[3], "cpe:2.3:h:rockwellautomation")
        self.assertEqual(len(set(params)), len(params))

    def test_1783_natr_only_related_and_other_catalog_rejected(self):
        related = normalize_candidate(
            product("natr", "rockwellautomation", "1783-natr"),
            self.ROCKWELL, "cpeMatchString",
        )
        self.assertEqual(related["match_level"], "RELATED")
        self.assertFalse(is_pertinent(related, self.ROCKWELL))
        self.assertTrue(is_manufacturer_related(related, self.ROCKWELL))
        other = normalize_candidate(
            product("other", "rockwellautomation", "1784-natr"),
            self.ROCKWELL, "cpeMatchString",
        )
        self.assertEqual(other["match_level"], "POSSIBLE_INCOMPATIBILITY")
        self.assertFalse(is_manufacturer_related(other, self.ROCKWELL))

    def test_realistic_rockwell_alias_retrieves_related_device_and_marks_partial(self):
        run = queued(self.ROCKWELL)
        calls = []
        related = product("natr", "rockwellautomation", "1783-natr")
        def fetch(strategy, parameter, index, pacer):
            calls.append((strategy, parameter, index))
            return response([related]) if parameter == "cpe:2.3:h:rockwellautomation:1783*" else response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(run.candidates[0]["match_level"], "RELATED")
        self.assertEqual(run.candidates[0]["discovery_levels"], ["MANUFACTURER"])
        self.assertTrue(run.result_truncated)
        self.assertEqual(run.queries[-1]["stop_reason"], "MANUFACTURER_LEVEL_LIMIT")
        self.assertLessEqual(len(calls), MAX_TOTAL_PAGE_FETCHES)

    def test_axis_207_is_never_an_axis_206_candidate(self):
        run = queued(self.AXIS)
        wrong = product("axis-207", "axis", "207_network_camera")
        seen = []
        def fetch(strategy, parameter, index, pacer):
            seen.append(parameter)
            return response([wrong]) if parameter == "cpe:2.3:h:axis" else response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(run.candidates, [])
        self.assertIn("cpe:2.3:h:axis", seen)
        self.assertEqual(
            normalize_candidate(wrong, self.AXIS, "cpeMatchString")["match_level"],
            "POSSIBLE_INCOMPATIBILITY",
        )

    def test_siemens_cpu_1215c_remains_specific_no_manufacturer_queries(self):
        run = queued(SIEMENS)
        found = product("siemens", "siemens", "simatic_s7-1200_cpu_1215c")
        calls = []
        def fetch(strategy, parameter, index, pacer):
            calls.append(parameter)
            return response([found])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(calls), 2)
        self.assertEqual({q["level"] for q in run.queries}, {"SPECIFIC"})

    def test_alias_timeout_preserves_failed_not_absence(self):
        run = queued(self.ROCKWELL)
        def fetch(strategy, parameter, index, pacer):
            if parameter == "cpe:2.3:h:rockwellautomation:1783*":
                raise TimeoutError("Rockwell NVD timeout")
            return response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "FAILED")
        self.assertIn("timeout", run.error_message)
        self.assertEqual(run.queries[-1]["stop_reason"], "REQUEST_FAILED")

    def test_manufacturer_pages_are_shared_by_all_variants(self):
        from unittest.mock import patch
        from .services import cpe_search
        run = queued(self.ROCKWELL, scope="BROAD")
        calls = []
        def fetch(strategy, parameter, index, pacer):
            calls.append((parameter, index))
            return response([])
        with patch.object(cpe_search, "MAX_MANUFACTURER_LEVEL_PAGES", 2):
            execute_run(run, object(), fetcher=fetch)
        manufacturer = [q for q in run.queries if q["level"] == "MANUFACTURER"]
        self.assertEqual(sum(q["pages"] for q in manufacturer), 2)
        self.assertTrue(run.result_truncated)
        self.assertEqual(manufacturer[-1]["stop_reason"], "MANUFACTURER_LEVEL_LIMIT")
        self.assertLessEqual(len(calls), MAX_TOTAL_PAGE_FETCHES)
