"""Phase 1 regression tests. All NVD responses are simulated, never HTTP."""
from types import SimpleNamespace

from django.test import SimpleTestCase

from .services.identity import build_level_queries, family_term
from .services.candidate_matching import normalize_candidate, is_pertinent
from .services.cpe_search import execute_run, MAX_TOTAL_PAGE_FETCHES


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
        self.assertEqual(len(seen), 4)
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
        self.assertEqual(len(run.queries), 2)
        self.assertEqual({q["level"] for q in run.queries}, {"FAMILY"})
        self.assertIn("advantech:adam*", run.queries[1]["parameter"])

    def test_missing_cpu_and_no_broader_family_does_not_repeat_queries(self):
        run = queued({**SIEMENS, "cpu_model": ""})
        seen = []
        def fetch(strategy, parameter, index, pacer):
            seen.append((strategy, parameter))
            return response([])
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(len(seen), 2)
        self.assertFalse(run.result_truncated)
        self.assertEqual(run.queries[-1]["next_level_reason"], "NO_NEW_PARAMETERS")

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