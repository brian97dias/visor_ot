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

    def test_creation_requires_criticality_and_valid_optional_system(self):
        for invalid in (
            {"criticality": "UNDEFINED"},
            {"criticality": ""},
            {"system_ids": [999999]},
            {"hardware": {"role": "PLC", "model": "CPU 1215C"}},
        ):
            with self.subTest(invalid=invalid):
                response = self.client.post("/api/assets/",
                    self.hardware_body(**invalid), format="json")
                self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(Asset.objects.count(), 0)
        without_system = self.create_hardware(system_ids=[])
        self.assertFalse(SystemMembership.objects.filter(
            hardware_id=without_system.pk, unlinked_at__isnull=True
        ).exists())
        omitted = self.hardware_body()
        omitted.pop("system_ids")
        omitted["name"] = "PLC sin sistema"
        self.assertEqual(
            self.client.post("/api/assets/", omitted, format="json").status_code, 201
        )

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

    def test_last_system_can_be_unlinked_and_history_remains(self):
        asset = self.create_hardware()
        link = SystemMembership.objects.get(hardware_id=asset.pk, unlinked_at=None)
        response = self.client.delete(f"/api/assets/{asset.pk}/systems/{link.pk}/")
        self.assertEqual(response.status_code, 204, response.data)
        link.refresh_from_db()
        self.assertIsNotNone(link.unlinked_at)
        self.assertFalse(SystemMembership.objects.filter(
            hardware_id=asset.pk, unlinked_at__isnull=True
        ).exists())
        self.assertFalse(any(
            issue["field"] == "system_ids" and issue["id"] == asset.pk
            for issue in inventory_integrity_issues()
        ))

    def test_archiving_system_preserves_historical_links(self):
        asset = self.create_hardware()
        response = self.client.post(f"/api/assets/systems/{self.system.pk}/archive/")
        self.assertEqual(response.status_code, 200, response.data)
        self.system.refresh_from_db()
        self.assertEqual(self.system.status, "ARCHIVED")
        self.assertTrue(SystemMembership.objects.filter(
            hardware_id=asset.pk, system_id=self.system.pk,
            unlinked_at__isnull=True
        ).exists())

    def test_restore_without_system_and_optional_reassociation(self):
        asset = self.create_hardware()
        self.assertEqual(self.client.post(
            f"/api/assets/{asset.pk}/archive/"
        ).status_code, 200)
        self.assertEqual(self.client.post(
            f"/api/assets/systems/{self.system.pk}/archive/"
        ).status_code, 200)
        restored = self.client.post(f"/api/assets/{asset.pk}/restore/", format="json")
        self.assertEqual(restored.status_code, 200, restored.data)
        other = self.create_system("Restauración")
        second = self.create_hardware(name="Nuevo activo", system_ids=[other.pk])
        self.assertTrue(SystemMembership.objects.filter(
            hardware_id=second.pk, system_id=other.pk,
            unlinked_at__isnull=True
        ).exists())

    def test_archived_legacy_system_can_fix_criticality_then_restore(self):
        archive = self.client.post(
            f"/api/assets/systems/{self.system.pk}/archive/"
        )
        self.assertEqual(archive.status_code, 200, archive.data)
        OTSystem.objects.filter(pk=self.system.pk).update(criticality="UNDEFINED")
        invalid = self.client.post(
            f"/api/assets/systems/{self.system.pk}/restore/"
        )
        self.assertEqual(invalid.status_code, 400, invalid.data)
        repair = self.client.patch(
            f"/api/assets/systems/{self.system.pk}/", {
                "name": self.system.name, "description": self.system.description,
                "criticality": "LOW",
                "criticality_justification": self.system.criticality_justification,
                "impact": self.system.impact,
            }, format="json"
        )
        self.assertEqual(repair.status_code, 200, repair.data)
        restored = self.client.post(
            f"/api/assets/systems/{self.system.pk}/restore/"
        )
        self.assertEqual(restored.status_code, 200, restored.data)
        self.assertEqual(restored.data["criticality"], "LOW")

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
        self.assertNotIn(("asset", old.pk, "system_ids"),
                         [(x["entity"], x["id"], x["field"]) for x in problems])
        self.assertIn(("system", self.system.pk, "criticality"),
                      [(x["entity"], x["id"], x["field"]) for x in problems])
        old.refresh_from_db()
        self.assertEqual(old.criticality, "UNDEFINED")

    def test_integrity_command_reports_legacy_gaps_without_writing(self):
        from io import StringIO
        from django.core.management import call_command
        asset = Asset.objects.create(
            name="Hardware incompleto", asset_type="HARDWARE",
            criticality="UNDEFINED", created_by=self.operator,
        )
        Hardware.objects.create(asset=asset, role="PLC")
        output = StringIO()
        call_command("audit_inventory_integrity", "--json", stdout=output)
        data = json.loads(output.getvalue())
        self.assertFalse(data["valid"])
        fields = {row["field"] for row in data["issues"]
                  if row["entity"] == "asset" and row["id"] == asset.pk}
        self.assertTrue({"criticality", "manufacturer", "model"} <= fields)
        asset.refresh_from_db()
        self.assertEqual(asset.criticality, "UNDEFINED")

    def test_excel_hardware_import_does_not_assign_system(self):
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
        valid = self.client.post("/api/assets/import/confirm/", payload,
                                 format="multipart")
        self.assertEqual(valid.status_code, 200, valid.data)
        created = Asset.objects.get(name="PLC importado")
        self.assertFalse(SystemMembership.objects.filter(
            hardware_id=created.pk, unlinked_at__isnull=True
        ).exists())

