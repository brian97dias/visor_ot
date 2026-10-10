from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from .models import Asset, Hardware


class AssetHardwareModelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="operador-test", password="test-password-123"
        )

    def test_register_hardware_with_unknown_optional_values(self):
        asset = Asset.objects.create(
            name="DirectLogic 205",
            asset_type=Asset.AssetType.HARDWARE,
            created_by=self.user,
            updated_by=self.user,
        )
        hardware = Hardware.objects.create(
            asset=asset,
            role=Hardware.Role.PLC,
        )
        self.assertEqual(hardware.asset_id, asset.pk)
        self.assertEqual(asset.criticality, Asset.Criticality.UNDEFINED)
        self.assertEqual(hardware.manufacturer, "")
        self.assertEqual(asset.hardware, hardware)

    def test_hardware_is_one_to_one_with_asset(self):
        asset = Asset.objects.create(
            name="PLC-01",
            asset_type=Asset.AssetType.HARDWARE,
            created_by=self.user,
        )
        Hardware.objects.create(asset=asset, role=Hardware.Role.PLC)
        with self.assertRaises(Exception):
            Hardware.objects.create(asset=asset, role=Hardware.Role.RTU)

    def test_replacement_cost_has_currency(self):
        asset = Asset(
            name="PLC-02",
            asset_type=Asset.AssetType.HARDWARE,
            replacement_cost=Decimal("400000.00"),
            replacement_currency=Asset.Currency.COP,
            created_by=self.user,
        )
        asset.full_clean()
