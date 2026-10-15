"""Device participation filter rules that do not require creating a test DB."""

from django.test import SimpleTestCase
from rest_framework.exceptions import ValidationError

from .device_pair_filter import (
    allowed_observation_clause, direction_pairs, group_by_mac,
    parse_asset_ids,
)


MAC_A = "00:e0:62:00:17:0a"
MAC_B = "00:a0:45:6f:4b:83"
IP_A = "192.168.88.15"
IP_B = "192.168.88.20"


class DevicePairFilterTests(SimpleTestCase):
    def test_no_selected_device_keeps_existing_listing(self):
        self.assertEqual(parse_asset_ids(None), ())
        self.assertEqual(parse_asset_ids(""), ())

    def test_one_or_two_valid_distinct_ids(self):
        self.assertEqual(parse_asset_ids("1"), (1,))
        self.assertEqual(parse_asset_ids(" 1, 3 "), (1, 3))

    def test_invalid_or_duplicate_ids_rejected(self):
        for value in ("0", "-1", "1,1", "1,2,3", "1,,2", "abc", "1.5"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    parse_asset_ids(value)

    def test_same_capture_supports_both_endpoints(self):
        first = {(MAC_A, IP_A): {5, 7}}
        second = {(MAC_B, IP_B): {7, 8}}
        pairs = list(direction_pairs(first, second))
        self.assertEqual(pairs, [(MAC_A, IP_A, MAC_B, IP_B, {7})])

    def test_different_captures_cannot_be_combined_into_a_communication(self):
        first = {(MAC_A, IP_A): {5}}
        second = {(MAC_B, IP_B): {7}}
        self.assertEqual(list(direction_pairs(first, second)), [])

    def test_reverse_direction_supported(self):
        a = {(MAC_A, IP_A): {7}}
        b = {(MAC_B, IP_B): {7}}
        forward = list(direction_pairs(a, b))
        reverse = list(direction_pairs(b, a))
        self.assertEqual(forward[0][:4], (MAC_A, IP_A, MAC_B, IP_B))
        self.assertEqual(reverse[0][:4], (MAC_B, IP_B, MAC_A, IP_A))

    def test_mac_can_have_multiple_ips_without_changing_identity(self):
        groups = group_by_mac({
            (MAC_A, "192.168.88.15"): {5, 7},
            (MAC_A, "10.0.1.82"): {7},
        })
        self.assertEqual(groups[MAC_A]["192.168.88.15"], {5, 7})
        self.assertEqual(groups[MAC_A]["10.0.1.82"], {7})

    def test_both_endpoints_are_required_in_same_observation_clause(self):
        clause = allowed_observation_clause(
            MAC_A, IP_A, MAC_B, IP_B, {7}
        )
        as_dict = dict(clause.children)
        self.assertEqual(as_dict["client_ip"], IP_A)
        self.assertEqual(as_dict["server_ip"], IP_B)
        self.assertEqual(as_dict["client_macs"], [MAC_A])
        self.assertEqual(as_dict["server_macs"], [MAC_B])
        self.assertEqual(as_dict["ingestion_id__in"], (7,))
