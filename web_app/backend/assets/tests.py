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

    def create_asset(self, **overrides):
        values = {
            "name": "DirectLogic 205",
            "asset_type": Asset.AssetType.HARDWARE,
            "created_by": self.operator,
            "updated_by": self.operator,
        }
        values.update(overrides)
        return Asset.objects.create(**values)

    def test_operator_has_correct_role(self):
        self.assertEqual(self.operator.role, "OPERATOR")

    def test_register_hardware_with_unknown_optional_values(self):
        asset = self.create_asset(
            description="Controlador industrial del laboratorio 4SICS",
            impact="Su indisponibilidad detendria el proceso de bombeo.",
        )
        hardware = Hardware.objects.create(
            asset=asset,
            role=Hardware.Role.PLC,
        )

        self.assertEqual(hardware.asset_id, asset.pk)
        self.assertEqual(asset.criticality, Asset.Criticality.UNDEFINED)
        self.assertEqual(asset.impact, "Su indisponibilidad detendria el proceso de bombeo.")
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
        asset = self.create_asset(
            replacement_cost=Decimal("400000.00"),
        )
        with self.assertRaises(ValidationError):
            asset.full_clean()

    def test_currency_without_replacement_cost_is_invalid(self):
        asset = self.create_asset(
            replacement_currency=Asset.Currency.USD,
        )
        with self.assertRaises(ValidationError):
            asset.full_clean()

    def test_negative_replacement_cost_is_invalid(self):
        asset = self.create_asset(
            replacement_cost=Decimal("-1.00"),
            replacement_currency=Asset.Currency.COP,
        )
        with self.assertRaises(ValidationError) as error:
            asset.full_clean()

        self.assertIn("replacement_cost", error.exception.message_dict)

    def test_replacement_cost_and_currency_may_be_unknown(self):
        asset = self.create_asset()
        asset.full_clean()
