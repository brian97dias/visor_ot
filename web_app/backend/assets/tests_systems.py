"""OT system administration: API, authorization, audit, and isolation from Assets."""
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from rest_framework.test import APIClient

from .models import Asset, Hardware, OTSystem


class OTSystemAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin_user = User.objects.create_user("sys-admin", role=User.Role.ADMIN)
        self.operator = User.objects.create_user("sys-operator", role=User.Role.OPERATOR)
        self.analyst = User.objects.create_user("sys-analyst", role=User.Role.ANALYST)
        self.client = APIClient()
        self.client.force_authenticate(user=self.operator)

    def register(self, **data):
        return self.client.post("/api/assets/systems/", {
            "name": "Entorno experimental 4SICS Geek Lounge", **data,
        }, format="json")

    def test_create_with_no_hardware_and_default_criticality(self):
        response = self.register()
        self.assertEqual(response.status_code, 201, response.data)
        system = OTSystem.objects.get(pk=response.data["id"])
        self.assertEqual(system.criticality, OTSystem.Criticality.UNDEFINED)
        self.assertEqual(system.status, OTSystem.Status.ACTIVE)
        self.assertEqual(system.created_by, self.operator)
        self.assertEqual(system.updated_by, self.operator)
        self.assertEqual(response.data["created_by"], "sys-operator")
        self.assertNotIn("hardware", response.data)

    def test_name_is_trimmed_and_empty_name_is_rejected(self):
        created = self.register(name="  Sistema de bombeo  ")
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(created.data["name"], "Sistema de bombeo")
        for invalid in ("", "   "):
            result = self.register(name=invalid)
            self.assertEqual(result.status_code, 400)
        self.assertEqual(OTSystem.objects.count(), 1)

    def test_model_prevents_whitespace_only_name(self):
        system = OTSystem(name="   ", created_by=self.operator)
        with self.assertRaises(ValidationError):
            system.full_clean()

    def test_duplicate_names_are_allowed(self):
        self.assertEqual(self.register(name="Bombeo").status_code, 201)
        self.assertEqual(self.register(name="Bombeo").status_code, 201)
        self.assertEqual(OTSystem.objects.filter(name="Bombeo").count(), 2)

    def test_list_filters_and_detail(self):
        first = self.register(name="Sistema uno").data["id"]
        second = self.register(name="Sistema dos").data["id"]
        self.assertEqual(self.client.post(
            f"/api/assets/systems/{second}/archive/"
        ).status_code, 200)
        self.assertEqual(len(self.client.get("/api/assets/systems/").data["systems"]), 1)
        self.assertEqual(len(self.client.get("/api/assets/systems/?status=ARCHIVED").data["systems"]), 1)
        self.assertEqual(len(self.client.get("/api/assets/systems/?status=ALL").data["systems"]), 2)
        self.assertEqual(self.client.get(f"/api/assets/systems/{first}/").status_code, 200)
        self.assertEqual(self.client.get("/api/assets/systems/?status=INVALID").status_code, 400)

    def test_update_and_archive_restore_audit(self):
        system_id = self.register(name="Sistema uno").data["id"]
        changed = self.client.patch(
            f"/api/assets/systems/{system_id}/",
            {"criticality": "HIGH", "criticality_justification": "Impacto operacional",
             "impact": "Parada de planta"}, format="json",
        )
        self.assertEqual(changed.status_code, 200, changed.data)
        archived = self.client.post(f"/api/assets/systems/{system_id}/archive/")
        self.assertEqual(archived.status_code, 200, archived.data)
        self.assertEqual(archived.data["archived_by"], "sys-operator")
        self.assertIsNotNone(archived.data["archived_at"])
        self.assertEqual(self.client.patch(
            f"/api/assets/systems/{system_id}/", {"name": "No permitido"}, format="json",
        ).status_code, 400)
        self.assertEqual(self.client.post(f"/api/assets/systems/{system_id}/archive/").status_code, 400)
        restored = self.client.post(f"/api/assets/systems/{system_id}/restore/")
        self.assertEqual(restored.status_code, 200, restored.data)
        self.assertIsNone(restored.data["archived_at"])
        self.assertIsNone(restored.data["archived_by"])
        self.assertEqual(restored.data["criticality"], "HIGH")
        self.assertEqual(self.client.post(f"/api/assets/systems/{system_id}/restore/").status_code, 400)

    def test_unknown_and_system_managed_fields_cannot_be_written(self):
        self.assertEqual(self.register(status="ARCHIVED").status_code, 400)
        system_id = self.register().data["id"]
        response = self.client.patch(
            f"/api/assets/systems/{system_id}/", {"created_by": "sys-admin"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(OTSystem.objects.get(pk=system_id).created_by, self.operator)

    def test_roles_allow_read_but_not_analyst_write(self):
        self.assertEqual(self.register().status_code, 201)
        self.client.force_authenticate(user=self.analyst)
        self.assertEqual(self.client.get("/api/assets/systems/").status_code, 200)
        self.assertEqual(self.client.get("/api/assets/systems/1/").status_code, 200)
        self.assertEqual(self.register().status_code, 403)
        self.assertEqual(self.client.patch("/api/assets/systems/1/",
                                            {"name": "Cambio"}, format="json").status_code, 403)
        self.assertEqual(self.client.post("/api/assets/systems/1/archive/").status_code, 403)
        self.client.force_authenticate(user=self.admin_user)
        self.assertEqual(self.register(name="Sistema administrador").status_code, 201)

    def test_authentication_is_required(self):
        self.client.force_authenticate(user=None)
        self.assertIn(self.client.get("/api/assets/systems/").status_code, (401, 403))
        self.assertIn(self.register().status_code, (401, 403))

    def test_asset_inventory_is_not_modified(self):
        asset = Asset.objects.create(
            name="DirectLogic 205", asset_type=Asset.AssetType.HARDWARE,
            created_by=self.operator, updated_by=self.operator,
        )
        Hardware.objects.create(asset=asset, role=Hardware.Role.PLC)
        self.assertEqual(self.register().status_code, 201)
        self.assertEqual(Asset.objects.count(), 1)
        self.assertEqual(Hardware.objects.count(), 1)
        self.assertEqual(Asset.objects.get(pk=asset.pk).criticality, "UNDEFINED")
