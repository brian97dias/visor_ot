"""No-database checks of the shared Communications search criteria."""

from unittest.mock import patch

from django.db.models import Q
from django.test import SimpleTestCase
from rest_framework.exceptions import ValidationError

from .search_filters import build_communication_search_criteria


class CommunicationSearchCriteriaTests(SimpleTestCase):
    @patch("network.search_filters.device_name_filter", return_value=None)
    def test_ip_protocol_service_search_without_device_candidate(self, _mock):
        criteria = build_communication_search_criteria("192.168.88")
        query = str(criteria)
        self.assertIn("source_ip__icontains", query)
        self.assertIn("destination_ip__icontains", query)
        self.assertIn("transport_protocol__icontains", query)
        self.assertIn("service__icontains", query)

    @patch("network.search_filters.device_name_filter", return_value=Q(pk__in=[42]))
    def test_name_filter_is_combined_without_replacing_generic_search(self, _mock):
        criteria = build_communication_search_criteria("dire")
        query = str(criteria)
        self.assertIn("source_ip__icontains", query)
        self.assertIn("pk__in", query)

    @patch("network.search_filters.device_name_filter", return_value=None)
    def test_numeric_search_preserves_exact_service_port(self, _mock):
        criteria = build_communication_search_criteria("502")
        self.assertIn("service_port", str(criteria))

    @patch("network.search_filters.device_name_filter")
    def test_exact_ip_uses_only_equality_for_source_or_destination(self, name_filter):
        criteria = build_communication_search_criteria(
            "192.168.88.1", match_mode="EXACT_IP"
        )
        self.assertEqual(criteria.connector, "OR")
        self.assertEqual(
            set(criteria.children),
            {("source_ip", "192.168.88.1"), ("destination_ip", "192.168.88.1")},
        )
        self.assertNotIn("icontains", str(criteria))
        name_filter.assert_not_called()

    @patch("network.search_filters.device_name_filter")
    def test_exact_ipv6_is_normalized_before_equality(self, name_filter):
        criteria = build_communication_search_criteria(
            "2001:0DB8:0000:0:0:0:0:0001", "EXACT_IP"
        )
        self.assertEqual(set(criteria.children), {
            ("source_ip", "2001:db8::1"),
            ("destination_ip", "2001:db8::1"),
        })
        name_filter.assert_not_called()

    def test_exact_ip_rejects_partial_empty_and_non_address_input(self):
        for value in ("", "192.168.88", "192.168.88.999", "DirectLogic", "502"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError) as error:
                    build_communication_search_criteria(value, "EXACT_IP")
                self.assertIn("search", error.exception.detail)

    def test_unknown_match_mode_rejected(self):
        with self.assertRaises(ValidationError) as error:
            build_communication_search_criteria("192.168.88.1", "NOT_A_MODE")
        self.assertIn("match_mode", error.exception.detail)

    @patch("network.search_filters.device_name_filter", return_value=None)
    def test_partial_mode_keeps_previous_search_rules(self, _mock):
        default = build_communication_search_criteria("192.168.88.1")
        explicit = build_communication_search_criteria("192.168.88.1", "PARTIAL")
        self.assertEqual(str(default), str(explicit))
        self.assertIn("source_ip__icontains", str(explicit))
