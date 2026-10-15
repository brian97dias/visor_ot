"""Database-backed checks of consolidation and automatic PCAP import."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from assets.interface_consolidation import consolidate_interface_observations
from assets.models import Asset, Hardware, NetworkInterface
from ingestion.models import Ingestion, InterfaceObservation
from ingestion.services.json_importer import import_analysis


class InterfaceConsolidationTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="analyst-consolidation-test",
            role=User.Role.ANALYST,
        )
        self.ingestion = self.create_ingestion("pcap-a")

    def create_ingestion(self, pcap_id):
        return Ingestion.objects.create(
            pcap_id=pcap_id,
            analysis_hash=pcap_id.ljust(64, "a"),
            filename=pcap_id + ".pcap",
            relative_path=pcap_id + ".pcap",
            schema_version="0.2",
            imported_by=self.analyst,
            interfaces_detected=0,
            communications_detected=0,
        )

    def add_observation(self, ingestion, mac):
        return InterfaceObservation.objects.create(
            ingestion=ingestion,
            mac=mac,
            ips=["192.168.88.15"],
            first_seen="2015-10-20 10:10:34",
            last_seen="2015-10-20 10:12:00",
        )

    def test_same_mac_across_ingestions_is_one_identity(self):
        second_ingestion = self.create_ingestion("pcap-b")
        first = self.add_observation(self.ingestion, "AA:BB:CC:DD:EE:FF")
        second = self.add_observation(second_ingestion, "aa-bb-cc-dd-ee-ff")

        stats = consolidate_interface_observations(
            InterfaceObservation.objects.all()
        )
        first.refresh_from_db()
        second.refresh_from_db()

        self.assertEqual(NetworkInterface.objects.count(), 1)
        self.assertEqual(first.network_interface_id, second.network_interface_id)
        self.assertEqual(stats.created, 1)
        self.assertEqual(stats.linked, 2)
        self.assertIsNone(first.network_interface.hardware_id)
        self.assertIsNone(first.network_interface.created_by_id)

        again = consolidate_interface_observations(
            InterfaceObservation.objects.all()
        )
        self.assertEqual(again.created, 0)
        self.assertEqual(again.linked, 0)
        self.assertEqual(again.already_linked, 2)

    def test_invalid_mac_keeps_observation_unlinked(self):
        observation = self.add_observation(self.ingestion, "unknown")
        stats = consolidate_interface_observations(
            InterfaceObservation.objects.all()
        )
        observation.refresh_from_db()

        self.assertIsNone(observation.network_interface_id)
        self.assertEqual(stats.skipped_invalid_mac, 1)
        self.assertEqual(NetworkInterface.objects.count(), 0)

    def test_existing_manual_hardware_association_is_preserved(self):
        asset = Asset.objects.create(
            name="DirectLogic 205",
            asset_type=Asset.AssetType.HARDWARE,
            created_by=self.analyst,
        )
        hardware = Hardware.objects.create(asset=asset, role=Hardware.Role.PLC)
        interface = NetworkInterface.objects.create(
            mac="aa:bb:cc:dd:ee:ff",
            hardware=hardware,
            identified_by=self.analyst,
        )
        observation = self.add_observation(self.ingestion, "AA:BB:CC:DD:EE:FF")

        stats = consolidate_interface_observations(
            InterfaceObservation.objects.all()
        )
        observation.refresh_from_db()
        interface.refresh_from_db()

        self.assertEqual(stats.reused, 1)
        self.assertEqual(observation.network_interface_id, interface.pk)
        self.assertEqual(interface.hardware_id, hardware.pk)
        self.assertEqual(interface.identified_by_id, self.analyst.pk)

    def test_conflicting_foreign_key_is_not_overwritten(self):
        expected = NetworkInterface.objects.create(mac="aa:bb:cc:dd:ee:ff")
        other = NetworkInterface.objects.create(mac="11:22:33:44:55:66")
        observation = self.add_observation(self.ingestion, expected.mac)
        observation.network_interface = other
        observation.save(update_fields=["network_interface"])

        stats = consolidate_interface_observations(
            InterfaceObservation.objects.all()
        )
        observation.refresh_from_db()

        self.assertEqual(stats.conflicting_links, 1)
        self.assertEqual(observation.network_interface_id, other.pk)


class AutomaticInterfaceConsolidationTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="analyst-import-test", role=User.Role.ANALYST
        )

    def test_new_import_links_observations_without_identifying_hardware(self):
        pcap_id = "lab-4sics"
        analysis = {
            "schema_version": "0.2",
            "capture": {
                "pcap_id": pcap_id,
                "filename": "lab.pcap",
                "relative_path": "lab.pcap",
            },
            "interfaces": [
                {
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "ips": ["192.168.88.15"],
                    "first_seen": "2015-10-20 10:10:34",
                    "last_seen": "2015-10-20 10:12:00",
                },
            ],
            "communications": [],
        }

        with patch(
            "ingestion.services.json_importer.get_pcap_analysis",
            return_value=analysis,
        ):
            ingestion, result = import_analysis(pcap_id, self.analyst)
            repeated, repeated_result = import_analysis(pcap_id, self.analyst)

        observation = ingestion.interface_observations.get()
        self.assertEqual(result, "CREATED")
        self.assertEqual(repeated_result, "ALREADY_IMPORTED")
        self.assertEqual(repeated.pk, ingestion.pk)
        self.assertIsNotNone(observation.network_interface_id)
        self.assertEqual(NetworkInterface.objects.count(), 1)
        self.assertIsNone(observation.network_interface.hardware_id)
