"""Increment 1: pure cpeMatchString planning, no NVD or database requests."""
from copy import deepcopy

from django.test import SimpleTestCase

from .services.identity import (
    MAX_CPE_PLAN_QUERIES, build_cpe_match_plan, build_queries,
    build_level_queries, fingerprint, normalized, build_alternative_keyword_plan,
)
from .services.cpe_catalogue import canonical_query

SIEMENS = {
    "asset_type": "HARDWARE", "manufacturer": "Siemens",
    "model": "SIMATIC S7-1200", "cpu_model": "1215C", "role": "PLC",
}
ADAM = {
    "asset_type": "HARDWARE", "manufacturer": "Advantech",
    "model": "ADAM-5000 Series", "cpu_model": "", "role": "PLC",
}
ROCKWELL = {
    "asset_type": "HARDWARE", "manufacturer": "Rockwell Automation",
    "model": "1783-EMS08T/B", "cpu_model": "", "role": "SWITCH",
}


class AutomaticCpeMatchPlanTests(SimpleTestCase):
    def test_siemens_cpu_model_family_then_manufacturer(self):
        plan = build_cpe_match_plan(SIEMENS)
        params = [row["parameter"] for row in plan]
        self.assertEqual(params[0], "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c*")
        self.assertEqual(params[1], "cpe:2.3:h:siemens:simatic_s7_1200_cpu_1215c*")
        self.assertIn("cpe:2.3:h:siemens:simatic_s7-1200*", params)
        self.assertIn("cpe:2.3:h:siemens:simatic*", params)
        self.assertEqual(params[-1], "cpe:2.3:h:siemens:*")
        levels = [p["level"] for p in plan]
        self.assertEqual(levels, sorted(levels, key={"SPECIFIC": 0, "FAMILY": 1,
                                                    "MANUFACTURER": 2}.get))
        self.assertFalse(any("1215c" in p["parameter"] for p in plan
                             if p["level"] != "SPECIFIC"))

    def test_advantech_preserves_5000_and_reaches_adam_family(self):
        plan = build_cpe_match_plan(ADAM)
        params = [p["parameter"] for p in plan]
        self.assertEqual(params[:2], [
            "cpe:2.3:h:advantech:adam-5000*",
            "cpe:2.3:h:advantech:adam_5000*",
        ])
        self.assertIn("cpe:2.3:h:advantech:adam5000*", params)
        self.assertIn("cpe:2.3:h:advantech:adam*", params)
        self.assertEqual(params[-1], "cpe:2.3:h:advantech:*")
        self.assertNotIn("cpe:2.3:h:advantech:adam-3600*", params)

    def test_rockwell_aliases_preserve_model_suffix_b(self):
        plan = build_cpe_match_plan(ROCKWELL)
        params = [p["parameter"] for p in plan]
        self.assertEqual(params[0], "cpe:2.3:h:rockwellautomation:1783-ems08t_b*")
        self.assertIn("cpe:2.3:h:rockwellautomation:1783_ems08t_b*", params)
        self.assertIn("cpe:2.3:h:rockwell_automation:1783-ems08t_b*", params)
        self.assertIn("cpe:2.3:h:rockwell-automation:1783-ems08t_b*", params)
        self.assertIn("cpe:2.3:h:rockwellautomation:1783*", params)
        self.assertEqual(params[-3:], [
            "cpe:2.3:h:rockwellautomation:*",
            "cpe:2.3:h:rockwell_automation:*",
            "cpe:2.3:h:rockwell-automation:*",
        ])
        self.assertNotIn("cpe:2.3:h:rockwellautomation:1783-ems08t*", params)

    def test_plan_bounded_unique_and_matches_existing_catalogue_grammar(self):
        for identity in (SIEMENS, ADAM, ROCKWELL,
                         {"asset_type": "HARDWARE", "manufacturer": "Axis Communications",
                          "model": "AXIS 206", "cpu_model": "", "role": "OTHER"}):
            with self.subTest(model=identity["model"]):
                plan = build_cpe_match_plan(identity)
                self.assertLessEqual(len(plan), MAX_CPE_PLAN_QUERIES)
                self.assertEqual(len(plan), len({p["parameter"] for p in plan}))
                self.assertTrue(all(p["strategy"] == "cpeMatchString" for p in plan))
                for p in plan:
                    self.assertEqual(
                        canonical_query("cpeMatchString", p["parameter"])[1],
                        p["parameter"],
                    )

    def test_models_do_not_become_neighboring_numbers(self):
        base = {"asset_type": "HARDWARE", "manufacturer": "Axis Communications",
                "model": "AXIS 206", "cpu_model": "", "role": "OTHER"}
        params = [p["parameter"] for p in build_cpe_match_plan(base)]
        self.assertFalse(any("207" in p or "axis:axis*" in p for p in params))
        self.assertIn("cpe:2.3:h:axis:axis_206*", params)

    def test_cpu_already_in_model_is_not_repeated(self):
        data = {**SIEMENS, "model": "SIMATIC S7-1200 CPU 1215C"}
        plan = build_cpe_match_plan(data)
        self.assertEqual(plan[0]["parameter"].count("1215c"), 1)
        self.assertIn("cpe:2.3:h:siemens:simatic_s7-1200*",
                      [p["parameter"] for p in plan])

    def test_invalid_identity_never_degrades_to_manufacturer_query(self):
        for data in [
            {**SIEMENS, "asset_type": "SOFTWARE"},
            {**SIEMENS, "manufacturer": ""},
            {**SIEMENS, "manufacturer": "!!!"},
            {**SIEMENS, "model": ""},
            {**SIEMENS, "model": "PLC;https://evil.test"},
            {**SIEMENS, "model": "A" * 130},
            {**SIEMENS, "cpu_model": ["1215C"]},
            {**SIEMENS, "cpu_model": "!!!"},
        ]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                build_cpe_match_plan(data)
        with self.assertRaises(ValueError):
            build_cpe_match_plan(None)

    def test_generator_is_pure_and_legacy_search_plan_is_unchanged(self):
        for data in (SIEMENS, ADAM, ROCKWELL):
            original = deepcopy(data)
            before = fingerprint(data)
            plan = build_cpe_match_plan(data)
            self.assertGreater(len(plan), 0)
            self.assertEqual(data, original)
            self.assertEqual(fingerprint(data), before)
        # Legacy automatic worker remains unchanged until Increment 2.
        self.assertEqual([q["strategy"] for q in build_queries(SIEMENS)],
                         ["keywordSearch", "cpeMatchString"])
        self.assertEqual([q["strategy"] for q in build_level_queries(SIEMENS, "SPECIFIC")],
                         ["keywordSearch", "cpeMatchString"])

class AlternativeBrandKeywordPlanTests(SimpleTestCase):
    def test_fallback_terms_are_bounded_brand_plus_model_then_brand(self):
        data = {"asset_type":"HARDWARE", "manufacturer":"Hirschmann",
                "model":"EAGLE20", "cpu_model":"", "role":"FIREWALL"}
        before = deepcopy(data)
        plan = build_alternative_keyword_plan(data)
        self.assertEqual([(q["level"], q["strategy"], q["parameter"]) for q in plan], [
            ("ALTERNATIVE", "keywordSearch", "Hirschmann EAGLE20"),
            ("ALTERNATIVE", "keywordSearch", "Hirschmann"),
        ])
        self.assertEqual(data, before)
        for q in plan:
            self.assertEqual(canonical_query(q["strategy"], q["parameter"])[1],
                             q["parameter"])

    def test_unrepresentable_optional_keyword_plan_does_not_break_main_search(self):
        data = {"asset_type":"HARDWARE", "manufacturer":"Example & Co",
                "model":"EAGLE20", "cpu_model":"", "role":"OTHER"}
        self.assertEqual(build_alternative_keyword_plan(data), [])

    def test_moxa_progressive_family_probes_from_industrial_model(self):
        data = {"asset_type": "HARDWARE", "manufacturer": "Moxa",
                "model": "EDS-508A", "cpu_model": "", "role": "SWITCH"}
        params = [p["parameter"] for p in build_cpe_match_plan(data)]
        expected = ["cpe:2.3:h:moxa:eds-508*",
                    "cpe:2.3:h:moxa:eds-50*",
                    "cpe:2.3:h:moxa:eds-5*"]
        self.assertEqual(
            [p["parameter"] for p in build_cpe_match_plan(data)
             if p["level"] == "FAMILY"], expected
        )
        self.assertEqual(params[-1], "cpe:2.3:h:moxa:*")
        self.assertNotIn("cpe:2.3:h:moxa:eds*", params)
        self.assertLessEqual(len(params), MAX_CPE_PLAN_QUERIES)

    def test_moxa_spaced_variant_generates_the_same_bounded_family_probes(self):
        base = {"asset_type": "HARDWARE", "manufacturer": "Moxa",
                "model": "EDS 508A", "cpu_model": "", "role": "SWITCH"}
        family = [p["parameter"] for p in build_cpe_match_plan(base)
                  if p["level"] == "FAMILY"]
        self.assertEqual(family, ["cpe:2.3:h:moxa:eds-508*",
                                  "cpe:2.3:h:moxa:eds-50*",
                                  "cpe:2.3:h:moxa:eds-5*"])

    def test_existing_series_and_vendor_numeric_models_keep_their_plans(self):
        axis = {"asset_type":"HARDWARE", "manufacturer":"Axis Communications",
                "model":"AXIS 206", "cpu_model":"", "role":"OTHER"}
        axis_plan = build_cpe_match_plan(axis)
        self.assertFalse(any(x["level"] == "FAMILY" for x in axis_plan))
        adam_plan = build_cpe_match_plan(ADAM)
        self.assertEqual([p["parameter"] for p in adam_plan
                          if p["level"] == "FAMILY"],
                         ["cpe:2.3:h:advantech:adam*"])

    def test_phoenix_multi_segment_model_gets_three_guarded_family_prefixes(self):
        identity = {"asset_type": "HARDWARE", "manufacturer": "Phoenix Contact",
                    "model": "FL IL 24 BK PAC", "cpu_model": "", "role": "SWITCH"}
        original = deepcopy(identity)
        planned = build_cpe_match_plan(identity)
        expected = ["fl_il_24", "fl_il", "fl"]
        by_vendor = [
            p["parameter"] for p in planned
            if p["level"] == "FAMILY" and p["parameter"].startswith(
                "cpe:2.3:h:phoenixcontact:"
            )
        ]
        self.assertEqual(by_vendor, [
            f"cpe:2.3:h:phoenixcontact:{part}*" for part in expected
        ])
        self.assertEqual(planned[-1]["parameter"], "cpe:2.3:h:phoenix-contact:*")
        self.assertLessEqual(len(planned), MAX_CPE_PLAN_QUERIES)
        self.assertEqual(len(planned), len({p["parameter"] for p in planned}))
        self.assertEqual(identity, original)
        for item in planned:
            canonical_query(item["strategy"], item["parameter"])

    def test_short_series_queries_do_not_affect_other_inventory_models(self):
        for identity in (
            SIEMENS, ADAM, ROCKWELL,
            {"asset_type": "HARDWARE", "manufacturer": "Axis Communications",
             "model": "AXIS 206", "cpu_model": "", "role": "OTHER"},
            {"asset_type": "HARDWARE", "manufacturer": "Moxa",
             "model": "EDS-508A", "cpu_model": "", "role": "SWITCH"},
        ):
            with self.subTest(model=identity["model"]):
                plan = build_cpe_match_plan(identity)
                from vulnerabilities.services.identity import (
                    _planned_short_series_prefixes, _planned_model_core,
                )
                self.assertEqual(
                    _planned_short_series_prefixes(
                        _planned_model_core(identity["model"]),
                        identity["manufacturer"],
                    ), []
                )
        short = {"asset_type": "HARDWARE", "manufacturer": "Phoenix Contact",
                 "model": "FL", "cpu_model": "", "role": "OTHER"}
        self.assertFalse(any(
            q["level"] == "FAMILY" for q in build_cpe_match_plan(short)
        ))
