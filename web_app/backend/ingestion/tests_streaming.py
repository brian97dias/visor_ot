"""Regression tests for bounded PCAP ingestion (no Passive Analyzer needed)."""
import json
from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from ingestion.models import CommunicationObservation, Ingestion, InterfaceObservation
from ingestion.services.json_importer import ImportValidationError, import_analysis
from network.models import Communication


def _communication(index, *, port=502):
    return {
        "client_ip": "192.168.88.10",
        "server_ip": "192.168.88.20",
        "transport_protocol": "TCP",
        "service_port": port,
        "service": "Modbus",
        "packet_count": 10 + index,
        "first_seen": "2015-10-22 01:00:00",
        "last_seen": "2015-10-22 02:00:00",
    }


def _stream(items, *, include_trailer=True):
    @contextmanager
    def streamed(_pcap_id):
        def rows():
            counts = {"interface": 0, "communication": 0}
            for item in items:
                if item["type"] in counts:
                    counts[item["type"]] += 1
                yield json.dumps(item).encode("utf-8")
            if include_trailer:
                yield json.dumps({
                    "type": "complete", "analysis_hash": "a" * 64,
                    "interfaces": counts["interface"],
                    "communications": counts["communication"],
                }).encode("utf-8")
        yield rows()
    return streamed


class StreamedImportTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="import-operator", password="test-password"
        )
        self.manifest = {
            "schema_version": "0.2",
            "analysis_hash": "a" * 64,
            "capture": {
                "pcap_id": "pcap-big", "filename": "big.pcap",
                "relative_path": "lab/big.pcap",
            },
        }

    def _import(self, items, *, manifest=None):
        info = manifest or self.manifest
        with patch(
            "ingestion.services.json_importer.get_pcap_import_manifest",
            return_value=info,
        ), patch(
            "ingestion.services.json_importer.stream_pcap_analysis", _stream(items)
        ):
            return import_analysis(info["capture"]["pcap_id"], self.user)

    def test_250_observations_are_persisted_linked_and_deduplicated_in_batches(self):
        items = [{
            "type": "interface",
            "data": {"mac": "00:11:22:33:44:55",
                     "ips": ["192.168.88.10"],
                     "first_seen": "2015-10-22 01:00:00",
                     "last_seen": "2015-10-22 02:00:00"},
        }]
        items.extend(
            {"type": "communication", "data": _communication(i, port=502 + (i % 2))}
            for i in range(250)
        )
        ingestion, status = self._import(items)
        self.assertEqual(status, "CREATED")
        self.assertEqual(ingestion.interfaces_detected, 1)
        self.assertEqual(ingestion.communications_detected, 250)
        self.assertEqual(InterfaceObservation.objects.filter(ingestion=ingestion).count(), 1)
        self.assertEqual(CommunicationObservation.objects.filter(ingestion=ingestion).count(), 250)
        self.assertEqual(Communication.objects.count(), 2)
        self.assertFalse(CommunicationObservation.objects.filter(
            ingestion=ingestion, communication__isnull=True
        ).exists())

        same, repeated = self._import([])
        self.assertEqual(repeated, "ALREADY_IMPORTED")
        self.assertEqual(same.pk, ingestion.pk)
        self.assertEqual(CommunicationObservation.objects.count(), 250)

        ingestion.status = Ingestion.Status.EXCLUDED
        ingestion.save(update_fields=["status"])
        reactivated, action = self._import([])
        self.assertEqual(action, "REACTIVATED")
        self.assertEqual(reactivated.pk, ingestion.pk)
        self.assertEqual(CommunicationObservation.objects.count(), 250)

    def test_partial_stream_is_rolled_back_without_deleting_previous_ingestion(self):
        original, _ = self._import([
            {"type": "communication", "data": _communication(0)}
        ])
        newer = {
            **self.manifest, "analysis_hash": "b" * 64,
        }
        rows = [
            {"type": "communication", "data": _communication(1, port=503)},
            {"type": "bad-type", "data": {"foo": "bar"}},
        ]
        with self.assertRaises(ImportValidationError):
            self._import(rows, manifest=newer)
        original.refresh_from_db()
        self.assertEqual(original.status, Ingestion.Status.ACTIVE)
        self.assertEqual(Ingestion.objects.count(), 1)
        self.assertEqual(CommunicationObservation.objects.count(), 1)

    def test_manifest_change_reverts_streaming_import(self):
        next_manifest = {
            **self.manifest, "analysis_hash": "b" * 64,
        }
        with patch(
            "ingestion.services.json_importer.get_pcap_import_manifest",
            side_effect=[self.manifest, next_manifest],
        ), patch(
            "ingestion.services.json_importer.stream_pcap_analysis",
            _stream([{"type": "communication", "data": _communication(0)}]),
        ):
            with self.assertRaises(ImportValidationError):
                import_analysis("pcap-big", self.user)
        self.assertEqual(Ingestion.objects.count(), 0)
        self.assertEqual(CommunicationObservation.objects.count(), 0)

    def test_missing_trailer_rolls_back_even_when_rows_are_valid(self):
        with patch(
            "ingestion.services.json_importer.get_pcap_import_manifest",
            return_value=self.manifest,
        ), patch(
            "ingestion.services.json_importer.stream_pcap_analysis",
            _stream([{"type": "communication", "data": _communication(0)}],
                    include_trailer=False),
        ):
            with self.assertRaisesRegex(ImportValidationError, "sin confirmación"):
                import_analysis("pcap-big", self.user)
        self.assertFalse(Ingestion.objects.exists())
        self.assertFalse(CommunicationObservation.objects.exists())
