from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase

from .models import Asset, Hardware


class AssetHardwareModelTests(TestCase):
    def setUp(self):
        # TestCase usa una base de datos temporal: no modifica al usuario real.
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="operador-paula",
            role=User.Role.OPERATOR,
        )

    def build_asset(self, **overrides):
        values = {
            "name": "DirectLogic 205",
            "asset_type": Asset.AssetType.HARDWARE,
            "created_by": self.operator,
            "updated_by": self.operator,
        }
        values.update(overrides)
        return Asset(**values)

    def create_asset(self, **overrides):
        asset = self.build_asset(**overrides)
        asset.save()
        return asset

    def test_operator_has_correct_role(self):
        self.assertEqual(self.operator.role, "OPERATOR")

    def test_register_hardware_with_unknown_optional_values(self):
        asset = self.create_asset(
            description="Controlador industrial del laboratorio 4SICS",
            impact="Su indisponibilidad detendria el proceso del sistema",
        )
        hardware = Hardware.objects.create(
            asset=asset,
            role=Hardware.Role.PLC,
        )

        self.assertEqual(hardware.asset_id, asset.pk)
        self.assertEqual(asset.criticality, Asset.Criticality.UNDEFINED)
        self.assertEqual(asset.impact, "Su indisponibilidad detendria el proceso del sistema")
        self.assertIsNone(asset.replacement_cost)
        self.assertEqual(hardware.manufacturer, "")
        self.assertEqual(hardware.serial_number, "")
        self.assertEqual(asset.hardware, hardware)
        self.assertEqual(asset.created_by, self.operator)
        self.assertEqual(asset.updated_by, self.operator)

    def test_hardware_is_one_to_one_with_asset(self):
        asset = self.create_asset(name="PLC-01")
        Hardware.objects.create(asset=asset, role=Hardware.Role.PLC)

        # Savepoint para que el IntegrityError no rompa la transacción del test.
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Hardware.objects.create(asset=asset, role=Hardware.Role.RTU)

        self.assertEqual(Hardware.objects.filter(asset=asset).count(), 1)

    def test_replacement_cost_with_currency_is_valid(self):
        asset = self.create_asset(
            replacement_cost=Decimal("400000.00"),
            replacement_currency=Asset.Currency.COP,
        )
        asset.full_clean()

    def test_replacement_cost_without_currency_is_invalid(self):
        asset = self.build_asset(
            replacement_cost=Decimal("400000.00"),
        )
        with self.assertRaises(ValidationError):
            asset.full_clean()

    def test_currency_without_replacement_cost_is_invalid(self):
        asset = self.build_asset(
            replacement_currency=Asset.Currency.USD,
        )
        with self.assertRaises(ValidationError):
            asset.full_clean()

    def test_negative_replacement_cost_is_invalid(self):
        asset = self.build_asset(
            replacement_cost=Decimal("-1.00"),
            replacement_currency=Asset.Currency.COP,
        )
        with self.assertRaises(ValidationError) as error:
            asset.full_clean()

        self.assertIn("replacement_cost", error.exception.message_dict)

    def test_replacement_cost_and_currency_may_be_unknown(self):
        asset = self.create_asset()
        asset.full_clean()


from django.test import SimpleTestCase

from ingestion.models import Ingestion, InterfaceObservation
from .models import NetworkInterface
from .models.network_interface import normalize_mac


class MACNormalizationTests(SimpleTestCase):
    def test_accepts_common_mac_formats(self):
        for raw in (
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "AABBCCDDEEFF",
        ):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_mac(raw), "aa:bb:cc:dd:ee:ff")

    def test_unknown_mac_is_none(self):
        self.assertIsNone(normalize_mac(None))
        self.assertIsNone(normalize_mac("  "))

    def test_rejects_invalid_mac(self):
        for raw in ("gg:bb:cc:dd:ee:ff", "aa:bb", "invalid"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValidationError):
                    normalize_mac(raw)


class NetworkInterfaceModelTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="operator-network-interface",
            role=User.Role.OPERATOR,
        )
        asset = Asset.objects.create(
            name="DirectLogic 205",
            asset_type=Asset.AssetType.HARDWARE,
            created_by=self.operator,
            updated_by=self.operator,
        )
        self.hardware = Hardware.objects.create(
            asset=asset,
            role=Hardware.Role.PLC,
        )

    def test_normalizes_mac_on_save(self):
        interface = NetworkInterface.objects.create(
            mac="AA-BB-CC-DD-EE-FF",
            created_by=self.operator,
        )
        self.assertEqual(interface.mac, "aa:bb:cc:dd:ee:ff")
        self.assertFalse(interface.is_identified)

    def test_same_mac_cannot_create_another_interface(self):
        NetworkInterface.objects.create(mac="aa:bb:cc:dd:ee:ff")
        with self.assertRaises(ValidationError):
            NetworkInterface.objects.create(mac="AA:BB:CC:DD:EE:FF")

    def test_interface_requires_mac_or_declared_ip(self):
        for values in ({}, {"mac": "", "declared_ip": ""}):
            with self.subTest(values=values):
                with self.assertRaises(ValidationError):
                    NetworkInterface.objects.create(**values)

    def test_declared_ip_can_exist_without_mac(self):
        first = NetworkInterface.objects.create(
            declared_ip="192.168.88.15",
            hardware=self.hardware,
            created_by=self.operator,
        )
        second = NetworkInterface.objects.create(
            declared_ip="192.168.88.15"
        )
        self.assertIsNone(first.mac)
        self.assertTrue(first.is_identified)
        self.assertFalse(second.is_identified)
        self.assertNotEqual(first.pk, second.pk)

    def test_observations_survive_interface_removal(self):
        ingestion = Ingestion.objects.create(
            pcap_id="test-4sics",
            analysis_hash="a" * 64,
            filename="test.pcap",
            relative_path="test.pcap",
            schema_version="0.2",
            imported_by=self.operator,
            interfaces_detected=1,
            communications_detected=0,
        )
        interface = NetworkInterface.objects.create(
            mac="aa:bb:cc:dd:ee:ff",
            hardware=self.hardware,
        )
        observation = InterfaceObservation.objects.create(
            ingestion=ingestion,
            network_interface=interface,
            mac="aa:bb:cc:dd:ee:ff",
            ips=["192.168.88.15"],
            first_seen="2015-10-20 10:10:34",
            last_seen="2015-10-20 10:12:00",
        )

        interface.delete()
        observation.refresh_from_db()
        self.assertIsNone(observation.network_interface_id)
        self.assertEqual(observation.ips, ["192.168.88.15"])
