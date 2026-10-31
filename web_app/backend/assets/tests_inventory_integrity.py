"""Phase 1: explicit new-inventory requirements, lifecycle and legacy audit."""
import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .inventory_integrity import inventory_integrity_issues
from .models import Asset, Hardware, OTSystem, SystemMembership
from .tests_excel_import import xlsx, upload


class InventoryIntegrityPhaseOneTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="phase1-operator", role=User.Role.OPERATOR
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)
        self.system = self.create_system("Control principal")

    def create_system(self, name):
        response = self.client.post("/api/assets/systems/", {
            "name": name, "criticality": "HIGH",
        }, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        return OTSystem.objects.get(pk=response.data["id"])

    def hardware_body(self, **updates):
        return {
            "name": "PLC ensayado", "asset_type": "HARDWARE",
            "criticality": "MEDIUM", "hardware": {
                "manufacturer": "Siemens", "model": "CPU 1215C", "role": "PLC",
            }, "system_ids": [self.system.pk], **updates,
        }

    def create_hardware(self, **updates):
        response = self.client.post("/api/assets/", self.hardware_body(**updates),
                                    format="json")
        self.assertEqual(response.status_code, 201, response.data)
        return Asset.objects.get(pk=response.data["id"])

    def test_creation_requires_explicit_criticality_and_active_system(self):
        for invalid in (
            {"criticality": "UNDEFINED"},
            {"criticality": ""},
            {"system_ids": []},
            {"system_ids": [999999]},
            {"hardware": {"role": "PLC", "model": "CPU 1215C"}},
        ):
            with self.subTest(invalid=invalid):
                response = self.client.post("/api/assets/",
                    self.hardware_body(**invalid), format="json")
                self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(Asset.objects.count(), 0)

    def test_software_criticality_required_but_system_is_not(self):
        no_criticality = self.client.post("/api/assets/", {
            "name": "Firmware", "asset_type": "SOFTWARE",
            "software": {"software_type": "FIRMWARE", "product": "Firmware"},
        }, format="json")
        self.assertEqual(no_criticality.status_code, 400)
        result = self.client.post("/api/assets/", {
            "name": "Firmware", "asset_type": "SOFTWARE",
            "criticality": "LOW",
            "software": {"software_type": "FIRMWARE", "product": "Firmware"},
        }, format="json")
        self.assertEqual(result.status_code, 201, result.data)

    def test_system_creation_and_edit_require_defined_criticality(self):
        rejected = self.client.post("/api/assets/systems/", {"name": "Inválido"},
                                    format="json")
        self.assertEqual(rejected.status_code, 400)
        invalid = self.client.patch(
            f"/api/assets/systems/{self.system.pk}/",
            {"criticality": "UNDEFINED"}, format="json"
        )
        self.assertEqual(invalid.status_code, 400)

    def test_last_system_cannot_be_unlinked_but_history_is_retained(self):
        asset = self.create_hardware()
        link = SystemMembership.objects.get(hardware_id=asset.pk, unlinked_at=None)
        url = f"/api/assets/{asset.pk}/systems/{link.pk}/"
        denied = self.client.delete(url)
        self.assertEqual(denied.status_code, 400, denied.data)
        self.assertIsNone(SystemMembership.objects.get(pk=link.pk).unlinked_at)
        second = self.create_system("Respaldo")
        added = self.client.post(f"/api/assets/{asset.pk}/systems/",
                                 {"system_id": second.pk}, format="json")
        self.assertEqual(added.status_code, 201, added.data)
        self.assertEqual(self.client.delete(url).status_code, 204)
        self.assertIsNotNone(SystemMembership.objects.get(pk=link.pk).unlinked_at)
        self.assertEqual(
            SystemMembership.objects.filter(hardware_id=asset.pk,
                unlinked_at__isnull=True).count(), 1
        )

    def test_system_archive_does_not_strand_hardware(self):
        asset = self.create_hardware()
        url = f"/api/assets/systems/{self.system.pk}/archive/"
        denied = self.client.post(url)
        self.assertEqual(denied.status_code, 400, denied.data)
        self.system.refresh_from_db()
        self.assertEqual(self.system.status, "ACTIVE")
        second = self.create_system("Segundo sistema")
        attached = self.client.post(f"/api/assets/{asset.pk}/systems/",
                                    {"system_id": second.pk}, format="json")
        self.assertEqual(attached.status_code, 201, attached.data)
        self.assertEqual(self.client.post(url).status_code, 200)
        self.assertTrue(SystemMembership.objects.filter(
            hardware_id=asset.pk, system_id=self.system.pk,
            unlinked_at__isnull=True
        ).exists())

    def test_restore_archived_hardware_with_explicit_active_system(self):
        asset = self.create_hardware()
        self.assertEqual(self.client.post(
            f"/api/assets/{asset.pk}/archive/"
        ).status_code, 200)
        self.assertEqual(self.client.post(
            f"/api/assets/systems/{self.system.pk}/archive/"
        ).status_code, 200)
        denied = self.client.post(f"/api/assets/{asset.pk}/restore/",
                                  format="json")
        self.assertEqual(denied.status_code, 400, denied.data)
        other = self.create_system("Restauración")
        restored = self.client.post(f"/api/assets/{asset.pk}/restore/",
                                    {"system_ids": [other.pk]}, format="json")
        self.assertEqual(restored.status_code, 200, restored.data)
        self.assertEqual(
            SystemMembership.objects.filter(
                hardware_id=asset.pk, system_id=other.pk,
                unlinked_at__isnull=True
            ).count(), 1
        )

    def test_legacy_incomplete_records_are_reported_not_reclassified(self):
        old = Asset.objects.create(
            name="Activo histórico", asset_type="HARDWARE",
            created_by=self.operator, criticality="UNDEFINED",
        )
        Hardware.objects.create(asset=old, role="PLC", manufacturer="Siemens",
                                model="CPU 1215C")
        self.system.criticality = "UNDEFINED"
        self.system.save(update_fields=["criticality"])
        problems = inventory_integrity_issues()
        self.assertIn(("asset", old.pk, "criticality"),
                      [(x["entity"], x["id"], x["field"]) for x in problems])
        self.assertIn(("asset", old.pk, "system_ids"),
                      [(x["entity"], x["id"], x["field"]) for x in problems])
        self.assertIn(("system", self.system.pk, "criticality"),
                      [(x["entity"], x["id"], x["field"]) for x in problems])
        old.refresh_from_db()
        self.assertEqual(old.criticality, "UNDEFINED")

    def test_excel_hardware_create_needs_explicit_system_in_actions(self):
        body = {
            "nombre_activo": "PLC importado", "fabricante": "Siemens",
            "modelo": "1215C", "rol": "PLC", "criticidad": "HIGH",
        }
        blob = xlsx(hardware=[body])
        preview = self.client.post("/api/assets/import/preview/",
                                   {"file": upload(blob)}, format="multipart")
        self.assertEqual(preview.status_code, 200, preview.data)
        plan = next(row for row in preview.data["rows"] if row["sheet"] == "Hardware")
        self.assertEqual(plan["status"], "CREATE")
        actions = {row["key"]: {"action": (
            "CREATE" if row["sheet"] == "Hardware" else "SKIP"
        )} for row in preview.data["rows"]}
        payload = {"file": upload(blob), "token": preview.data["token"],
                   "actions": json.dumps(actions)}
        missing = self.client.post("/api/assets/import/confirm/", payload,
                                   format="multipart")
        self.assertEqual(missing.status_code, 400, missing.data)
        self.assertFalse(Asset.objects.filter(name="PLC importado").exists())
        actions[plan["key"]]["system_ids"] = [self.system.pk]
        payload = {"file": upload(blob), "token": preview.data["token"],
                   "actions": json.dumps(actions)}
        valid = self.client.post("/api/assets/import/confirm/", payload,
                                 format="multipart")
        self.assertEqual(valid.status_code, 200, valid.data)
        created = Asset.objects.get(name="PLC importado")
        self.assertTrue(SystemMembership.objects.filter(
            hardware_id=created.pk, system_id=self.system.pk,
            unlinked_at__isnull=True
        ).exists())
