"""No-database checks of the shared Communications search criteria."""

from unittest.mock import patch

from django.db.models import Q
from django.test import SimpleTestCase

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
