"""No-database tests for candidate hardware-name searches."""

from django.test import SimpleTestCase

from .name_search import (
    group_mac_candidates, normalize_device_query, unique_name_candidates,
)


MAC_A = "28:cf:e9:18:b5:ed"
MAC_B = "00:07:7c:1a:61:83"


class NameSearchTests(SimpleTestCase):
    def test_device_query_accepts_spacing_and_case(self):
        self.assertEqual(normalize_device_query("Direct Logic"), "directlogic")
        self.assertEqual(
            normalize_device_query("  Phoenix Contact FL  "),
            "phoenixcontactfl",
        )

    def test_one_mac_with_four_ips_can_match_all_four(self):
        rows = [{
            "ingestion_id": 7,
            "mac": MAC_A.upper(),
            "ips": ["10.0.1.82", "10.100.159.38", "172.20.10.4",
                    "192.168.88.52"],
        }]
        result = unique_name_candidates(rows, rows)
        self.assertEqual(len(result), 4)
        self.assertEqual(result[(MAC_A, "192.168.88.52")], {7})

    def test_shared_ip_in_same_capture_is_not_attributed(self):
        matched = [{
            "ingestion_id": 7, "mac": MAC_A, "ips": ["192.168.88.1"],
        }]
        all_rows = matched + [{
            "ingestion_id": 7, "mac": MAC_B, "ips": ["192.168.88.1"],
        }]
        self.assertEqual(unique_name_candidates(matched, all_rows), {})

    def test_same_ip_in_separate_captures_is_allowed_when_individually_unique(self):
        matched = [
            {"ingestion_id": 5, "mac": MAC_A, "ips": ["192.168.88.52"]},
            {"ingestion_id": 7, "mac": MAC_A, "ips": ["192.168.88.52"]},
        ]
        result = unique_name_candidates(matched, matched)
        self.assertEqual(result[(MAC_A, "192.168.88.52")], {5, 7})

    def test_invalid_mac_cannot_support_name_search(self):
        matched = [{"ingestion_id": 7, "mac": "UNKNOWN",
                    "ips": ["192.168.88.15"]}]
        self.assertEqual(unique_name_candidates(matched, matched), {})

    def test_candidate_without_ip_does_not_match(self):
        matched = [{"ingestion_id": 7, "mac": MAC_A, "ips": []}]
        self.assertEqual(unique_name_candidates(matched, matched), {})

    def test_group_candidates_by_mac_without_losing_capture_provenance(self):
        candidate_pairs = {
            (MAC_A, "192.168.88.52"): {5, 7},
            (MAC_A, "10.0.1.82"): {7},
            (MAC_B, "192.168.88.1"): {5},
        }
        result = group_mac_candidates(candidate_pairs)
        self.assertEqual(set(result), {MAC_A, MAC_B})
        self.assertEqual(result[MAC_A]["192.168.88.52"], {5, 7})
        self.assertEqual(result[MAC_A]["10.0.1.82"], {7})
        self.assertEqual(result[MAC_B]["192.168.88.1"], {5})

    def test_grouping_does_not_merge_different_macs_on_same_ip(self):
        data = {
            (MAC_A, "192.168.88.1"): {5},
            (MAC_B, "192.168.88.1"): {7},
        }
        result = group_mac_candidates(data)
        self.assertNotEqual(result[MAC_A], result[MAC_B])
        self.assertEqual(result[MAC_A]["192.168.88.1"], {5})
        self.assertEqual(result[MAC_B]["192.168.88.1"], {7})
