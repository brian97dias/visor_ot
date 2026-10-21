"""Increment 3: candidate ranking and conservative inventory correspondence."""
from django.test import SimpleTestCase

from vulnerabilities.services.candidate_matching import (
    classify, merge_candidates, normalize_candidate, classify_alternative_vendor,
)


def identity(vendor, model, cpu=""):
    return {"asset_type": "HARDWARE", "manufacturer": vendor,
            "model": model, "cpu_model": cpu, "role": "PLC"}


def candidate(vendor, model, *, deprecated=False, name_id=None):
    value = f"cpe:2.3:h:{vendor}:{model}:-:*:*:*:*:*:*:*"
    return {"cpe": {"cpeNameId": name_id or value, "cpeName": value,
                    "deprecated": deprecated,
                    "titles": [{"lang": "en", "title": model}]}}


class CandidateMatchingIncrement3Tests(SimpleTestCase):
    def test_siemens_exact_cpu_outranks_family(self):
        device = identity("Siemens", "SIMATIC S7-1200", "1215C")
        exact = normalize_candidate(candidate(
            "siemens", "simatic_s7-1200_cpu_1215c"), device, "cpeMatchString")
        family = normalize_candidate(candidate(
            "siemens", "simatic_s7-1200"), device, "cpeMatchString")
        ranked = merge_candidates([family, exact])
        self.assertEqual([c["match_level"] for c in ranked], ["SPECIFIC", "FAMILY"])

    def test_advantech_neighbour_is_related_not_exact(self):
        device = identity("Advantech", "ADAM-5000 Series")
        other = normalize_candidate(candidate("advantech", "adam-5550"),
                                    device, "cpeMatchString")
        self.assertEqual(other["match_level"], "RELATED")

    def test_rockwell_catalogue_prefix_is_only_related(self):
        device = identity("Rockwell Automation", "1783-EMS08T/B")
        other = normalize_candidate(candidate("rockwellautomation", "1783-natr"),
                                    device, "cpeMatchString")
        self.assertEqual(other["match_level"], "RELATED")

    def test_axis_numeric_model_never_matches_longer_number(self):
        device = identity("Axis Communications", "206")
        other = normalize_candidate(candidate("axis", "2060"),
                                    device, "cpeMatchString")
        self.assertEqual(other["match_level"], "POSSIBLE_INCOMPATIBILITY")

    def test_current_cpe_ranks_above_deprecated_suggestion(self):
        device = identity("Siemens", "SIMATIC S7-1200", "1215C")
        deprecated = normalize_candidate(candidate(
            "siemens", "simatic_s7-1200_cpu_1215c", deprecated=True),
            device, "cpeMatchString")
        current = normalize_candidate(candidate("siemens", "simatic_s7-1200"),
                                      device, "cpeMatchString")
        ranked = merge_candidates([deprecated, current])
        self.assertFalse(ranked[0]["deprecated"])
        self.assertTrue(ranked[1]["deprecated"])

    def test_axis_207_is_exploratory_not_specific_for_axis_206(self):
        device = identity("Axis Communications", "206")
        item = normalize_candidate(candidate("axis", "207w"), device, "cpeMatchString")
        self.assertEqual(item["match_level"], "EXPLORATORY")
        self.assertEqual(item["exploratory_distance"], 1)
        self.assertIn("Solo correspondencia exploratoria", item["match_reason"])

    def test_axis_2060_and_unrelated_manufacturer_are_not_exploratory(self):
        device = identity("Axis Communications", "206")
        longer = normalize_candidate(candidate("axis", "2060"), device, "cpeMatchString")
        other_brand = normalize_candidate(candidate("other", "207"), device, "cpeMatchString")
        self.assertEqual(longer["match_level"], "POSSIBLE_INCOMPATIBILITY")
        self.assertEqual(other_brand["match_level"], "POSSIBLE_INCOMPATIBILITY")

    def test_beckhoff_cx_neighbour_but_not_arbitrary_model(self):
        device = identity("Beckhoff", "CX1010")
        near = normalize_candidate(candidate("beckhoff", "cx1020"), device, "cpeMatchString")
        far = normalize_candidate(candidate("beckhoff", "cx2010"), device, "cpeMatchString")
        self.assertEqual(near["match_level"], "EXPLORATORY")
        self.assertEqual(far["match_level"], "EXPLORATORY")

    def test_exploratory_ranking_after_existing_categories(self):
        device = identity("Axis Communications", "206")
        exact = normalize_candidate(candidate("axis", "206"), device, "cpeMatchString")
        near = normalize_candidate(candidate("axis", "207"), device, "cpeMatchString")
        ranked = merge_candidates([near, exact])
        self.assertEqual([c["match_level"] for c in ranked], ["FAMILY", "EXPLORATORY"])

    def test_inventory_axis_206_and_real_nvd_207w_are_exploratory(self):
        device = identity("Axis Communications", "AXIS 206")
        official = candidate("axis", "207w")
        official["cpe"]["cpeNameId"] = "479A554E-F206-4566-8901-935F8E29DB58"
        item = normalize_candidate(official, device, "cpeMatchString")
        self.assertEqual(item["match_level"], "EXPLORATORY")
        self.assertEqual(item["exploratory_distance"], 1)
        self.assertEqual(item["cpe_name_id"], official["cpe"]["cpeNameId"])

    def test_inventory_axis_206_and_vendor_prefixed_nvd_product_are_exploratory(self):
        device = identity("Axis Communications", "AXIS 206")
        item = normalize_candidate(candidate("axis", "axis_207_network_camera"),
                                   device, "cpeMatchString")
        self.assertEqual(item["match_level"], "EXPLORATORY")

    def test_inventory_axis_206_rejects_2060_and_no_numeric_guessing(self):
        device = identity("Axis Communications", "AXIS 206")
        for name in ("2060", "axis_2067_network_camera", "m1125", "216"):
            with self.subTest(name=name):
                item = normalize_candidate(candidate("axis", name), device, "cpeMatchString")
                self.assertEqual(item["match_level"], "POSSIBLE_INCOMPATIBILITY")
        wrong_vendor = normalize_candidate(candidate("other", "207w"), device, "cpeMatchString")
        self.assertEqual(wrong_vendor["match_level"], "POSSIBLE_INCOMPATIBILITY")

    def test_exact_cpe_axis_206_can_stop_but_neighbour_cannot(self):
        from vulnerabilities.services.candidate_matching import is_pertinent
        device = identity("Axis Communications", "AXIS 206")
        exact = normalize_candidate(candidate("axis", "206"), device, "cpeMatchString")
        neighbor = normalize_candidate(candidate("axis", "207w"), device, "cpeMatchString")
        self.assertTrue(is_pertinent(exact, device))
        self.assertFalse(is_pertinent(neighbor, device))
        self.assertNotEqual(neighbor["match_level"], "SPECIFIC")

    def test_beckhoff_inventory_suffix_matches_named_cx_series_weakly(self):
        device = identity("Beckhoff", "CX 1010-0012")
        near = normalize_candidate(candidate("beckhoff", "cx1020"), device, "cpeMatchString")
        published = normalize_candidate(candidate("beckhoff", "cx9020"), device, "cpeMatchString")
        unrelated = normalize_candidate(candidate("beckhoff", "ek9020"), device, "cpeMatchString")
        for row in (near, published):
            self.assertEqual(row["match_level"], "EXPLORATORY")
            self.assertIn("serie CX", row["match_reason"])
        self.assertEqual(unrelated["match_level"], "POSSIBLE_INCOMPATIBILITY")

    def test_axis_200_is_weak_while_axis_2060_is_not(self):
        device = identity("Axis Communications", "AXIS 206")
        same_decade = normalize_candidate(candidate("axis", "200"), device, "cpeMatchString")
        longer = normalize_candidate(candidate("axis", "2060"), device, "cpeMatchString")
        self.assertEqual(same_decade["match_level"], "EXPLORATORY")
        self.assertEqual(longer["match_level"], "POSSIBLE_INCOMPATIBILITY")

    def test_named_family_is_reusable_not_hardcoded_to_beckhoff(self):
        device = identity("Example Industrial", "EAGLE 20")
        neighbour = normalize_candidate(candidate("example_industrial", "eagle_30"), device,
                                        "cpeMatchString")
        unrelated = normalize_candidate(candidate("example_industrial", "switch_30"), device,
                                        "cpeMatchString")
        self.assertEqual(neighbour["match_level"], "EXPLORATORY")
        self.assertEqual(unrelated["match_level"], "POSSIBLE_INCOMPATIBILITY")

    def test_cross_vendor_belden_hirschmann_eagle20_has_explainable_evidence(self):
        device = identity("Hirschmann", "EAGLE20")
        item = normalize_candidate(candidate("belden", "hirschmann_eagle20"),
                                   device, "keywordSearch")
        reason = classify_alternative_vendor(item, device)
        self.assertIn("belden", reason)
        self.assertIn("Hirschmann", reason)
        self.assertEqual(item["match_level"], "POSSIBLE_INCOMPATIBILITY")

    def test_cross_vendor_fallback_rejects_partial_model_and_only_brand(self):
        device = identity("Hirschmann", "EAGLE20")
        for model in ("hirschmann_eagle200", "hirschmann_dragon", "other_eagle20"):
            with self.subTest(model=model):
                item = normalize_candidate(candidate("belden", model),
                                           device, "keywordSearch")
                self.assertIsNone(classify_alternative_vendor(item, device))

    def test_cross_vendor_fallback_requires_complete_model_not_title_only(self):
        device = identity("Hirschmann", "EAGLE20")
        record = candidate("belden", "generic_router")
        record["cpe"]["titles"] = [{"lang": "en", "title": "Hirschmann EAGLE20 guide"}]
        item = normalize_candidate(record, device, "keywordSearch")
        self.assertIsNone(classify_alternative_vendor(item, device))

    def test_moxa_model_suffix_and_nearby_family_are_exploratory(self):
        asset = identity("Moxa", "EDS-508A")
        close = normalize_candidate(candidate("moxa", "eds-510a"), asset, "cpeMatchString")
        revision = normalize_candidate(candidate("moxa", "eds-508b"), asset, "cpeMatchString")
        remote = normalize_candidate(candidate("moxa", "eds-589a"), asset, "cpeMatchString")
        other = normalize_candidate(candidate("moxa", "iks-g6824a"), asset, "cpeMatchString")
        self.assertEqual(close["match_level"], "EXPLORATORY")
        self.assertEqual(revision["match_level"], "EXPLORATORY")
        self.assertEqual(remote["match_level"], "EXPLORATORY")
        self.assertEqual(other["match_level"], "POSSIBLE_INCOMPATIBILITY")
        self.assertIn("serie EDS", close["match_reason"])
        self.assertEqual(
            [item["cpe_name"].split(":")[4] for item in
             merge_candidates([remote, close, revision])],
            ["eds-508b", "eds-510a", "eds-589a"],
        )

    def test_moxa_510a_never_stops_search_for_508a(self):
        from vulnerabilities.services.candidate_matching import is_pertinent
        asset = identity("Moxa", "EDS-508A")
        candidate_510 = normalize_candidate(candidate("moxa", "eds-510a"),
                                            asset, "cpeMatchString")
        candidate_508 = normalize_candidate(candidate("moxa", "eds-508a"),
                                            asset, "cpeMatchString")
        self.assertFalse(is_pertinent(candidate_510, asset))
        self.assertTrue(is_pertinent(candidate_508, asset))

    def test_moxa_spaced_model_uses_same_rule_without_special_vendor_cases(self):
        asset = identity("Moxa", "EDS 508A")
        candidate_510 = normalize_candidate(candidate("moxa", "eds-510a"),
                                            asset, "cpeMatchString")
        self.assertEqual(candidate_510["match_level"], "EXPLORATORY")
