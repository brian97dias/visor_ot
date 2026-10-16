"""Real database tests for software integrity and transaction boundaries.

Requires a disposable PostgreSQL test database (and permission to create it).
Never run these against the inventory's production database.
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.test import TestCase
from rest_framework.exceptions import PermissionDenied, ValidationError

from .models import Asset, Hardware, Software, SoftwareInstallation
from .services import change_inventory_status, register_hardware_asset
from .software_services import (
    associate_software, register_software_asset,
    unlink_software, update_software_asset,
)


class SoftwareDomainTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="operador", role=User.Role.OPERATOR
        )
        self.analyst = User.objects.create_user(
            username="analista", role=User.Role.ANALYST
        )

    def register(self, *, name="TIA Portal V18", manufacturer="Siemens",
                 product="TIA Portal", version="V18", software_type="APPLICATION"):
        return register_software_asset(data={
            "name": name,
            "software": {
                "software_type": software_type,
                "manufacturer": manufacturer,
                "product": product,
                "version": version,
            },
        }, user=self.operator)

    def hardware(self, name):
        return register_hardware_asset(data={
            "name": name,
            "asset_type": Asset.AssetType.HARDWARE,
            "hardware": {"role": Hardware.Role.WORKSTATION},
        }, user=self.operator)

    def test_software_is_asset_and_can_exist_without_installation(self):
        asset = self.register()
        self.assertEqual(asset.asset_type, Asset.AssetType.SOFTWARE)
        self.assertEqual(asset.software.product, "TIA Portal")
        self.assertFalse(hasattr(asset, "hardware"))
        self.assertEqual(asset.software.installations.count(), 0)

    def test_one_software_can_install_on_two_hardware(self):
        sw = self.register()
        eng1, eng2 = self.hardware("ENG-01"), self.hardware("ENG-02")
        a = associate_software(
            software_id=sw.pk, hardware_asset_id=eng1.pk, user=self.operator
        )
        b = associate_software(
            software_id=sw.pk, hardware_asset_id=eng2.pk, user=self.operator
        )
        self.assertNotEqual(a.pk, b.pk)
        self.assertEqual(sw.software.installations.filter(
            unlinked_at__isnull=True
        ).count(), 2)
        self.assertEqual(Software.objects.count(), 1)
        self.assertEqual(eng1.hardware.software.get(), sw.software)

    def test_one_hardware_can_have_different_software_variants(self):
        eng = self.hardware("ENG-01")
        sw1 = self.register()
        sw2 = self.register(name="TIA V19", version="V19")
        for sw in (sw1, sw2):
            associate_software(
                software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
            )
        self.assertEqual(eng.hardware.software.count(), 2)

    def test_cannot_duplicate_active_installation(self):
        sw, eng = self.register(), self.hardware("ENG-01")
        associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
        )
        with self.assertRaises(ValidationError):
            associate_software(
                software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
            )
        self.assertEqual(SoftwareInstallation.objects.count(), 1)

    def test_unlink_preserves_history_and_can_reinstall(self):
        sw, eng = self.register(), self.hardware("ENG-01")
        first = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
        )
        unlink_software(installation_id=first.pk, user=self.operator)
        first.refresh_from_db()
        self.assertFalse(first.is_active)
        self.assertEqual(eng.hardware.active_software.count(), 0)
        self.assertEqual(sw.software.active_hardware.count(), 0)
        self.assertIsNotNone(first.unlinked_at)
        self.assertEqual(first.unlinked_by, self.operator)
        second = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
        )
        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(SoftwareInstallation.objects.count(), 2)
        self.assertEqual(eng.hardware.active_software.count(), 1)
        self.assertEqual(sw.software.active_hardware.count(), 1)
        self.assertTrue(Asset.objects.filter(pk=sw.pk).exists())

    def test_cannot_unlink_twice(self):
        sw, eng = self.register(), self.hardware("ENG-01")
        inst = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
        )
        unlink_software(installation_id=inst.pk, user=self.operator)
        with self.assertRaises(ValidationError):
            unlink_software(installation_id=inst.pk, user=self.operator)

    def test_known_variant_reuses_existing_asset_instead_of_duplicate(self):
        original = self.register()
        with self.assertRaises(ValidationError):
            self.register(
                name="TIA copia",
                manufacturer=" SIEMENS ",
                product=" tia   portal ",
                version=" v18 ",
            )
        self.assertEqual(Software.objects.count(), 1)
        self.assertEqual(Asset.objects.count(), 1)
        self.assertEqual(original.software.product, "TIA Portal")

    def test_unknown_version_can_be_registered_without_merging(self):
        self.register(name="ADAM firmware A", manufacturer="Advantech",
                      product="ADAM Firmware", version="",
                      software_type="FIRMWARE")
        self.register(name="ADAM firmware B", manufacturer="Advantech",
                      product="ADAM Firmware", version="",
                      software_type="FIRMWARE")
        self.assertEqual(Software.objects.count(), 2)

    def test_mismatch_between_software_and_asset_type_is_invalid(self):
        eng = self.hardware("ENG-01")
        software = Software(asset=eng, software_type="OS",
                            product="Windows 11")
        with self.assertRaises(DjangoValidationError):
            software.full_clean()

    def test_whitespace_only_product_rolls_back_asset(self):
        with self.assertRaises(ValidationError):
            self.register(product="  ")
        self.assertFalse(Asset.objects.exists())

    def test_cannot_assign_archived_parent(self):
        sw = self.register()
        eng = self.hardware("ENG-01")
        change_inventory_status(
            asset=sw, new_status=Asset.InventoryStatus.ARCHIVED,
            user=self.operator,
        )
        with self.assertRaises(ValidationError):
            associate_software(
                software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
            )
        change_inventory_status(
            asset=sw, new_status=Asset.InventoryStatus.ACTIVE,
            user=self.operator,
        )
        change_inventory_status(
            asset=eng, new_status=Asset.InventoryStatus.ARCHIVED,
            user=self.operator,
        )
        with self.assertRaises(ValidationError):
            associate_software(
                software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
            )

    def test_updating_shared_version_is_blocked_and_transaction_rolls_back(self):
        sw = self.register()
        eng1, eng2 = self.hardware("ENG-01"), self.hardware("ENG-02")
        for eng in (eng1, eng2):
            associate_software(
                software_id=sw.pk, hardware_asset_id=eng.pk,
                user=self.operator,
            )
        with self.assertRaises(ValidationError):
            update_software_asset(
                asset_id=sw.pk,
                data={"name": "Nuevo nombre", "software": {"version": "V19"}},
                user=self.operator,
            )
        sw.refresh_from_db()
        self.assertEqual(sw.name, "TIA Portal V18")
        self.assertEqual(sw.software.version, "V18")
        self.assertEqual(sw.software.installations.filter(
            unlinked_at__isnull=True
        ).count(), 2)

    def test_past_installations_also_protect_variant_identity(self):
        sw, eng = self.register(), self.hardware("ENG-01")
        inst = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
        )
        unlink_software(installation_id=inst.pk, user=self.operator)
        with self.assertRaises(ValidationError):
            update_software_asset(
                asset_id=sw.pk, data={"software": {"version": "V19"}},
                user=self.operator,
            )
        sw.refresh_from_db()
        self.assertEqual(sw.software.version, "V18")

    def test_version_can_change_before_any_installation(self):
        sw = self.register()
        update_software_asset(
            asset_id=sw.pk,
            data={"software": {"version": "V19"},
                  "correction_reason": "Versión registrada incorrectamente"},
            user=self.operator,
        )
        sw.refresh_from_db()
        self.assertEqual(sw.software.version, "V19")

    def test_analyst_cannot_register_or_associate(self):
        with self.assertRaises(PermissionDenied):
            register_software_asset(
                data={"name": "Firmware", "software": {
                    "software_type": "FIRMWARE", "product": "test",
                }},
                user=self.analyst,
            )
        sw, eng = self.register(), self.hardware("ENG-01")
        with self.assertRaises(PermissionDenied):
            associate_software(
                software_id=sw.pk, hardware_asset_id=eng.pk,
                user=self.analyst,
            )

    def test_analyst_can_update_noncritical_data_but_not_criticality(self):
        sw = self.register()
        update_software_asset(
            asset_id=sw.pk, data={"description": "Nuevo detalle"},
            user=self.analyst,
        )
        sw.refresh_from_db()
        self.assertEqual(sw.description, "Nuevo detalle")
        with self.assertRaises(PermissionDenied):
            update_software_asset(
                asset_id=sw.pk, data={"criticality": Asset.Criticality.HIGH},
                user=self.analyst,
            )

    def test_registration_rolls_back_if_software_type_invalid(self):
        with self.assertRaises(ValidationError):
            self.register(software_type="INVALID")
        self.assertEqual(Asset.objects.count(), 0)


    def test_correction_after_unlink_preserves_snapshot_and_creates_audit(self):
        from .models import SoftwareCorrection
        sw, eng = self.register(), self.hardware("ENG-01")
        inst = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator,
        )
        unlink_software(installation_id=inst.pk, user=self.operator)
        update_software_asset(
            asset_id=sw.pk,
            data={
                "software": {"version": "V19"},
                "correction_reason": "Versión anterior mal transcrita",
            },
            user=self.operator,
        )
        inst.refresh_from_db()
        sw.refresh_from_db()
        self.assertEqual(sw.software.version, "V19")
        self.assertEqual(inst.identity_snapshot["version"], "V18")
        change = SoftwareCorrection.objects.get(software_id=sw.pk)
        self.assertEqual(change.reason, "Versión anterior mal transcrita")
        self.assertEqual(change.identity_before["version"], "V18")
        self.assertEqual(change.identity_after["version"], "V19")
        self.assertEqual(change.affected_active_installations, 0)

    def test_correction_preserves_current_installation_snapshot(self):
        from .models import SoftwareCorrection
        sw, eng = self.register(), self.hardware("ENG-01")
        inst = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator,
        )
        update_software_asset(
            asset_id=sw.pk,
            data={"software": {"product": "TIA Portal corregido"},
                  "correction_reason": "Error de captura"},
            user=self.operator,
        )
        inst.refresh_from_db()
        self.assertEqual(inst.identity_snapshot["product"], "TIA Portal")
        self.assertEqual(SoftwareCorrection.objects.get().affected_active_installations, 1)

    def test_multiple_active_installations_need_explicit_confirmation(self):
        from .models import SoftwareCorrection
        sw = self.register()
        for name in ("ENG-01", "ENG-02"):
            eng = self.hardware(name)
            associate_software(
                software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator,
            )
        with self.assertRaises(ValidationError):
            update_software_asset(
                asset_id=sw.pk,
                data={"software": {"version": "V18.1"},
                      "correction_reason": "Corrección revisada"},
                user=self.operator,
            )
        self.assertEqual(SoftwareCorrection.objects.count(), 0)
        update_software_asset(
            asset_id=sw.pk,
            data={"software": {"version": "V18.1"},
                  "correction_reason": "Corrección revisada",
                  "confirm_shared_correction": True},
            user=self.operator,
        )
        self.assertEqual(SoftwareCorrection.objects.get().affected_active_installations, 2)
        self.assertEqual(sw.software.installations.filter(
            unlinked_at__isnull=True
        ).count(), 2)

    def test_upgrade_never_overwrites_an_existing_variant(self):
        sw = self.register()
        with self.assertRaises(ValidationError):
            update_software_asset(
                asset_id=sw.pk,
                data={"software": {"version": "V19"},
                      "software_change_type": "UPGRADE",
                      "correction_reason": "Actualización real"},
                user=self.operator,
            )
        sw.refresh_from_db()
        self.assertEqual(sw.software.version, "V18")

    def test_correction_does_not_create_duplicate_known_variant(self):
        from .models import SoftwareCorrection
        sw_v18 = self.register()
        sw_v19 = self.register(name="TIA Portal V19", version="V19")
        with self.assertRaises(ValidationError):
            update_software_asset(
                asset_id=sw_v18.pk,
                data={"software": {"version": "V19"},
                      "correction_reason": "Error de inventario"},
                user=self.operator,
            )
        self.assertEqual(SoftwareCorrection.objects.count(), 0)
        self.assertEqual(sw_v19.software.version, "V19")
        self.assertEqual(sw_v18.software.version, "V18")

    def test_reinstallation_uses_corrected_identity_snapshot(self):
        sw, eng = self.register(), self.hardware("ENG-01")
        first = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator,
        )
        unlink_software(installation_id=first.pk, user=self.operator)
        update_software_asset(
            asset_id=sw.pk,
            data={"software": {"version": "V19"},
                  "correction_reason": "Error de transcripción"},
            user=self.operator,
        )
        newer = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator,
        )
        first.refresh_from_db()
        self.assertEqual(first.identity_snapshot["version"], "V18")
        self.assertEqual(newer.identity_snapshot["version"], "V19")


    def test_register_software_without_any_hardware(self):
        from .software_services import register_installed_software_asset
        asset = register_installed_software_asset(
            data={
                "name": "Firmware sin host identificado",
                "asset_type": Asset.AssetType.SOFTWARE,
                "software": {"software_type": "FIRMWARE", "product": "Firmware OT"},
            },
            user=self.operator,
        )
        self.assertEqual(asset.asset_type, Asset.AssetType.SOFTWARE)
        self.assertEqual(SoftwareInstallation.objects.count(), 0)

    def test_correction_requires_reason_even_after_unlinking(self):
        from .models import SoftwareCorrection
        sw, eng = self.register(), self.hardware("ENG-01")
        installation = associate_software(
            software_id=sw.pk, hardware_asset_id=eng.pk, user=self.operator
        )
        unlink_software(installation_id=installation.pk, user=self.operator)
        with self.assertRaises(ValidationError):
            update_software_asset(
                asset_id=sw.pk,
                data={"software": {"version": "V19"}},
                user=self.operator,
            )
        self.assertEqual(SoftwareCorrection.objects.count(), 0)
        sw.refresh_from_db()
        self.assertEqual(sw.software.version, "V18")
