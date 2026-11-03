"""Schema-0.2 regression for Ethernet PROFINET RT import and classification."""
from django.contrib.auth import get_user_model
from django.test import TestCase

from ingestion.models import CommunicationObservation, Ingestion
from network.models import Communication
from network.services.consolidation import consolidate_communication_observations
from network.views import get_communications_queryset


class ProfinetIngestionTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="profinet-test")
        self.one = self._ingestion("dia1", "a")
        self.two = self._ingestion("dia2", "b")

    def _ingestion(self, name, fingerprint):
        return Ingestion.objects.create(
            pcap_id=name, analysis_hash=fingerprint * 64,
            filename=name + ".pcap", relative_path="demo/" + name + ".pcap",
            schema_version="0.2", imported_by=self.user,
            interfaces_detected=12, communications_detected=12,
        )

    def _observe(self, ingestion, packets):
        return CommunicationObservation.objects.create(
            ingestion=ingestion, client_ip="192.168.88.30",
            server_ip="192.168.88.20",
            client_macs=["00:1c:06:01:d4:23"],
            server_macs=["00:0e:8c:a3:4e:cf"],
            transport_protocol="ETHERNET", service_port=0,
            service="PROFINET RT", role_source="ethernet_first_observed",
            packet_count=packets, first_seen="2026-11-01 08:00:00",
            last_seen="2026-11-01 15:00:00", network_scope="local_segment",
        )

    def test_two_days_share_canonical_pair_and_preserve_human_classification(self):
        first = self._observe(self.one, 32)
        second = self._observe(self.two, 32)
        consolidate_communication_observations([first])
        comm = Communication.objects.get(transport_protocol="ETHERNET")
        self.assertEqual(comm.service_port, 0)
        self.assertEqual(comm.service, "PROFINET RT")
        comm.status = Communication.Status.AUTHORIZED
        comm.save(update_fields=["status"])
        consolidate_communication_observations([second])
        self.assertEqual(Communication.objects.count(), 1)
        comm.refresh_from_db()
        self.assertEqual(comm.status, Communication.Status.AUTHORIZED)
        self.assertEqual(comm.observations.count(), 2)
        aggregate = get_communications_queryset().get(pk=comm.pk)
        self.assertEqual(aggregate.active_evidence_count, 2)
        self.assertEqual(aggregate.packets_observed, 64)
        self.one.status = Ingestion.Status.EXCLUDED
        self.one.save(update_fields=["status"])
        aggregate = get_communications_queryset().get(pk=comm.pk)
        self.assertEqual(aggregate.packets_observed, 32)

    def test_ethernet_sentinel_does_not_mix_with_modbus_or_tcp(self):
        packet = self._observe(self.one, 32)
        tcp = CommunicationObservation.objects.create(
            ingestion=self.one, client_ip="192.168.88.30",
            server_ip="192.168.88.20", transport_protocol="TCP",
            service_port=502, service="Modbus/TCP", packet_count=5,
            first_seen="2026-11-01 08:00:00",
            last_seen="2026-11-01 08:05:00",
        )
        consolidate_communication_observations([packet, tcp])
        self.assertEqual(Communication.objects.count(), 2)
        self.assertEqual(
            set(Communication.objects.values_list(
                "transport_protocol", "service_port"
            )), {("ETHERNET", 0), ("TCP", 502)},
        )
