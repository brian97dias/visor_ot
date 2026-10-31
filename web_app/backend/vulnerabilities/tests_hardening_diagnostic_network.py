"""Phase A: real SQL aggregation and conservative per-device IP/MAC attribution."""
from unittest.mock import patch

from django.test import TestCase

from ingestion.models import Ingestion, InterfaceObservation, CommunicationObservation
from network.models import Communication
from vulnerabilities.services.hardening_diagnostic_communications import (
    collect_prioritized_communications,
)
from vulnerabilities.tests_hardening_report_data import HardeningReportDataTests


class DiagnosticCommunicationTests(TestCase):
    def setUp(self):
        # Current context and manual interface assignment from the existing
        # successful Siemens inventory/CVE fixture.
        HardeningReportDataTests.setUp(self)
        self.hardware_id = self.hw.asset_id
        self.hardware_by_id = {
            self.hardware_id: {"id": self.hardware_id, "name": self.hw.asset.name}
        }
        self.active = self._ingestion("a", Ingestion.Status.ACTIVE)
        self.excluded = self._ingestion("b", Ingestion.Status.EXCLUDED)
        InterfaceObservation.objects.create(
            network_interface=self.interface,
            ingestion=self.active,
            mac=self.interface.mac,
            ips=["192.168.88.61"],
            first_seen="2015-10-20 10:00:00",
            last_seen="2015-10-20 11:00:00",
        )

    def _ingestion(self, prefix, status):
        return Ingestion.objects.create(
            pcap_id=f"report-{prefix}", analysis_hash=prefix * 64,
            filename=f"report-{prefix}.pcap", relative_path="report.pcap",
            schema_version="0.2", imported_by=self.user,
            status=status, interfaces_detected=1, communications_detected=2,
        )

    def _comm(self, n, packets, macs=None, *, ingestion=None):
        comm = Communication.objects.create(
            source_ip="192.168.88.61",
            destination_ip="192.168.88.80",
            transport_protocol="TCP", service_port=2000 + n,
            service="S7",
        )
        CommunicationObservation.objects.create(
            communication=comm,
            ingestion=ingestion or self.active,
            client_ip=comm.source_ip,
            server_ip=comm.destination_ip,
            client_macs=[self.interface.mac] if macs is None else macs,
            server_macs=None, transport_protocol="TCP",
            service_port=comm.service_port, service="S7",
            packet_count=packets,
            first_seen="2015-10-20 10:00:00",
            last_seen="2015-10-20 11:00:00",
        )
        return comm

    def _collect(self):
        return collect_prioritized_communications(
            self.hardware_by_id, [self.hardware_id]
        )[self.hardware_id]

    def test_top_three_use_sql_packet_ranking_and_confirmed_attribution(self):
        scores = [11, 40, 31, 22]
        rows = [self._comm(index, value) for index, value in enumerate(scores)]
        result = self._collect()
        self.assertEqual(result["status"], "ATTRIBUTED")
        self.assertFalse(result["search_limited"])
        self.assertEqual(
            [row["id"] for row in result["communications"]],
            [rows[1].pk, rows[2].pk, rows[3].pk],
        )
        self.assertEqual(
            [row["packets_observed"] for row in result["communications"]],
            [40, 31, 22],
        )

    def test_excluded_ingestion_never_inflates_packets(self):
        comm = self._comm(1, 8)
        CommunicationObservation.objects.create(
            communication=comm, ingestion=self.excluded,
            client_ip=comm.source_ip, server_ip=comm.destination_ip,
            client_macs=[self.interface.mac], server_macs=None,
            transport_protocol="TCP", service_port=comm.service_port,
            packet_count=9999999, first_seen="2015-10-01 00:00:00",
            last_seen="2015-10-01 01:00:00",
        )
        result = self._collect()
        self.assertEqual(len(result["communications"]), 1)
        self.assertEqual(result["communications"][0]["packets_observed"], 8)

    def test_matching_ip_alone_does_not_attribute_wrong_mac(self):
        self._comm(1, 800, ["aa:bb:cc:dd:ee:ff"])
        result = self._collect()
        self.assertEqual(result["communications"], [])
        self.assertEqual(result["status"], "INSUFFICIENT_ATTRIBUTION_EVIDENCE")

    def test_large_observation_count_skips_unbounded_resolution(self):
        self._comm(1, 999)
        with patch(
            "vulnerabilities.services.hardening_diagnostic_communications."
            "MAX_RESOLVED_OBSERVATIONS_PER_COMMUNICATION", 0
        ), patch(
            "vulnerabilities.services.hardening_diagnostic_communications."
            "resolve_communication_endpoints"
        ) as resolver:
            result = self._collect()
        resolver.assert_not_called()
        self.assertEqual(result["communications"], [])

    def test_no_confirmed_capture_ip_makes_limitation_explicit(self):
        InterfaceObservation.objects.all().delete()
        self._comm(1, 100)
        result = self._collect()
        self.assertEqual(result["status"], "INSUFFICIENT_ATTRIBUTION_EVIDENCE")
        self.assertFalse(result["search_limited"])

    def test_unrelated_hardware_cannot_inherit_same_capture(self):
        self._comm(1, 100)
        other = 999999
        result = collect_prioritized_communications(
            {**self.hardware_by_id, other: {"id": other, "name": "Other"}},
            [self.hardware_id, other],
        )
        self.assertEqual(len(result[self.hardware_id]["communications"]), 1)
        self.assertEqual(result[other]["communications"], [])
