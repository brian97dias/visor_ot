"""Integration tests for exact IP search with existing list filters."""

from unittest.mock import patch

from django.db.models import Q
from django.test import TestCase
from rest_framework.test import APIClient

from ingestion.models import CommunicationObservation, Ingestion
from network.models import Communication
from users.models import User


class ExactIPCommunicationAPITests(TestCase):
    URL = "/api/network/communications/"

    def setUp(self):
        user = User.objects.create_user(
            username="network-search-test", password="test-password"
        )
        self.client = APIClient()
        self.client.force_authenticate(user=user)
        ingestion = Ingestion.objects.create(
            pcap_id="fixture-exact-ip",
            filename="fixture.pcap",
            relative_path="fixture.pcap",
            schema_version="0.2",
            imported_by=user,
            interfaces_detected=0,
            communications_detected=3,
        )

        self.first = Communication.objects.create(
            source_ip="192.168.88.1", destination_ip="10.0.0.1",
            transport_protocol="TCP", service_port=80,
            status=Communication.Status.AUTHORIZED,
        )
        self.partial = Communication.objects.create(
            source_ip="192.168.88.100", destination_ip="10.0.0.2",
            transport_protocol="TCP", service_port=80,
            status=Communication.Status.UNCLASSIFIED,
        )
        self.reverse = Communication.objects.create(
            source_ip="10.0.0.3", destination_ip="192.168.88.1",
            transport_protocol="TCP", service_port=102,
            status=Communication.Status.UNCLASSIFIED,
        )

        for communication, count in (
            (self.first, 150), (self.partial, 200), (self.reverse, 10),
        ):
            CommunicationObservation.objects.create(
                ingestion=ingestion, communication=communication,
                client_ip=communication.source_ip,
                server_ip=communication.destination_ip,
                transport_protocol=communication.transport_protocol,
                service_port=communication.service_port,
                packet_count=count,
                first_seen="2015-10-20 10:10:34",
                last_seen="2015-10-20 10:11:34",
            )

    def ids(self, response):
        return {item["id"] for item in response.data["results"]}

    def test_exact_ip_matches_both_directions_but_not_prefixes(self):
        result = self.client.get(self.URL, {
            "search": "192.168.88.1", "match_mode": "EXACT_IP",
        })
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.ids(result), {self.first.pk, self.reverse.pk})
        self.assertEqual(result.data["count"], 2)

    def test_partial_search_keeps_prefix_behavior(self):
        result = self.client.get(self.URL, {
            "search": "192.168.88.1", "match_mode": "PARTIAL",
        })
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data["count"], 3)

    def test_invalid_ip_and_match_mode_are_rejected(self):
        for search in ("192.168.88", "", "192.168.88.999"):
            with self.subTest(search=search):
                result = self.client.get(self.URL, {
                    "search": search, "match_mode": "EXACT_IP",
                })
                self.assertEqual(result.status_code, 400)
                self.assertIn("search", result.data)

        result = self.client.get(self.URL, {"match_mode": "NOT_VALID"})
        self.assertEqual(result.status_code, 400)
        self.assertIn("match_mode", result.data)

    def test_status_and_minimum_packets_still_combine_with_exact_ip(self):
        result = self.client.get(self.URL, {
            "search": "192.168.88.1",
            "match_mode": "EXACT_IP",
            "status": "AUTORIZADA",
            "min_packets": "100",
        })
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.ids(result), {self.first.pk})

        excluded = self.client.get(self.URL, {
            "search": "192.168.88.1",
            "match_mode": "EXACT_IP",
            "status": "NO_CLASIFICADA",
            "min_packets": "100",
        })
        self.assertEqual(excluded.data["count"], 0)

    @patch("network.views.hardware_participation_filter")
    def test_existing_device_filter_is_combined_not_replaced(self, hardware_filter):
        hardware_filter.return_value = Q(pk=self.reverse.pk)
        result = self.client.get(self.URL, {
            "search": "192.168.88.1", "match_mode": "EXACT_IP",
            "asset_ids": "5",
        })
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.ids(result), {self.reverse.pk})
        hardware_filter.assert_called_once_with((5,))
