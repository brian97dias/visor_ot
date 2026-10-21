"""Regression coverage for memory-bounded consolidation of OT observations."""
from django.contrib.auth import get_user_model
from django.test import TestCase

from ingestion.models import CommunicationObservation, Ingestion
from network.models import Communication
from network.services.consolidation import consolidate_communication_observations


class ChunkedConsolidationTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="network-importer")
        self.ingestion = Ingestion.objects.create(
            pcap_id="pcap-network", analysis_hash="a" * 64,
            filename="network.pcap", relative_path="network.pcap",
            schema_version="0.2", imported_by=user,
            interfaces_detected=0, communications_detected=0,
        )

    def _observation(self, index, *, service=None):
        return CommunicationObservation.objects.create(
            ingestion=self.ingestion,
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            transport_protocol="TCP", service_port=502 + index % 2,
            service=service,
            packet_count=1, first_seen="2015-10-22 00:00:00",
            last_seen="2015-10-22 01:00:00",
        )

    def test_batch_linking_and_idempotency_preserve_existing_manual_status(self):
        canonical = Communication.objects.create(
            source_ip="10.0.0.1", destination_ip="10.0.0.2",
            transport_protocol="TCP", service_port=502,
            service=None, status=Communication.Status.AUTHORIZED,
        )
        self._observation(0, service="Modbus")
        for i in range(1, 206):
            self._observation(i, service=None)
        queryset = CommunicationObservation.objects.filter(ingestion=self.ingestion)
        first = consolidate_communication_observations(queryset, batch_size=50)
        self.assertEqual(first["observations_linked"], 206)
        self.assertEqual(Communication.objects.count(), 2)
        canonical.refresh_from_db()
        self.assertEqual(canonical.status, Communication.Status.AUTHORIZED)
        self.assertEqual(canonical.service, "Modbus")
        self.assertFalse(queryset.filter(communication__isnull=True).exists())

        second = consolidate_communication_observations(queryset, batch_size=50)
        self.assertEqual(second["observations_linked"], 0)
        self.assertEqual(Communication.objects.count(), 2)
