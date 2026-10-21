"""Increment 3: candidate ranking and conservative inventory correspondence."""
from django.test import SimpleTestCase

from vulnerabilities.services.candidate_matching import (
    classify, merge_candidates, normalize_candidate,
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
        self.assertIn("modelos distintos", item["match_reason"])

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
        self.assertEqual(far["match_level"], "POSSIBLE_INCOMPATIBILITY")

    def test_exploratory_ranking_after_existing_categories(self):
        device = identity("Axis Communications", "206")
        exact = normalize_candidate(candidate("axis", "206"), device, "cpeMatchString")
        near = normalize_candidate(candidate("axis", "207"), device, "cpeMatchString")
        ranked = merge_candidates([near, exact])
        self.assertEqual([c["match_level"] for c in ranked], ["FAMILY", "EXPLORATORY"])
