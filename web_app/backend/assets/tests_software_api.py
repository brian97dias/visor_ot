"""Software endpoints: integration tests on isolated SQLite test database.

Run:
    python manage.py test assets.tests_software_api --settings=config.settings_test_sqlite -v 2
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .models import Asset, Software
from .software_services import associate_software, register_software_asset


class SoftwareAssetAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="operador-api", password="test-password",
            role=User.Role.OPERATOR,
        )
        self.analyst = User.objects.create_user(
            username="analista-api", password="test-password",
            role=User.Role.ANALYST,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)

    @staticmethod
    def payload(version="V18"):
        return {
            "name": "TIA Portal " + version if version else "ADAM Firmware",
            "asset_type": "SOFTWARE",
            "description": "Software OT inventariado",
            "software": {
                "software_type": "APPLICATION",
                "manufacturer": "Siemens",
                "product": "TIA Portal",
                "version": version,
            },
        }

    def test_create_software_and_read_on_same_asset_api(self):
        response = self.client.post("/api/assets/", self.payload(), format="json")
        self.assertEqual(response.status_code, 201, response.data)
        asset_id = response.data["id"]
        self.assertEqual(response.data["asset_type"], "SOFTWARE")
        self.assertEqual(response.data["software"]["version"], "V18")
        self.assertNotIn("interfaces", response.data)
        self.assertEqual(Software.objects.count(), 1)
        self.assertEqual(Asset.objects.get(pk=asset_id).software.product, "TIA Portal")

        detail = self.client.get(f"/api/assets/{asset_id}/")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["software"]["manufacturer"], "Siemens")

        listing = self.client.get("/api/assets/")
        self.assertEqual(listing.status_code, 200)
        self.assertTrue(any(x["id"] == asset_id and x["software"]["product"]
                            == "TIA Portal" for x in listing.data["assets"]))

    def test_software_unknown_version_is_allowed(self):
        response = self.client.post("/api/assets/", self.payload(version=""), format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["software"]["version"], "")

    def test_duplicate_known_variant_is_rejected_atomically(self):
        a = self.client.post("/api/assets/", self.payload(), format="json")
        self.assertEqual(a.status_code, 201, a.data)
        other = self.payload()
        other["name"] = "TIA Portal Copia"
        other["software"]["manufacturer"] = "SIEMENS"
        other["software"]["product"] = "tia portal"
        other["software"]["version"] = "v18"
        b = self.client.post("/api/assets/", other, format="json")
        self.assertEqual(b.status_code, 400, b.data)
        self.assertEqual(Software.objects.count(), 1)
        self.assertEqual(Asset.objects.count(), 1)

    def test_patch_software_and_keep_other_fields(self):
        response = self.client.post("/api/assets/", self.payload(), format="json")
        asset_id = response.data["id"]
        updated = self.client.patch(
            f"/api/assets/{asset_id}/",
            {"software": {"version": "V19"}, "description": "Version actualizada"},
            format="json",
        )
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertEqual(updated.data["software"]["product"], "TIA Portal")
        self.assertEqual(updated.data["software"]["version"], "V19")
        self.assertEqual(updated.data["description"], "Version actualizada")

    def test_patch_shared_variant_cannot_change_version(self):
        software = self.client.post("/api/assets/", self.payload(), format="json").data
        hardware = self.client.post("/api/assets/", {
            "name": "ENG-01", "asset_type": "HARDWARE",
            "hardware": {"role": "WORKSTATION"},
        }, format="json")
        self.assertEqual(hardware.status_code, 201, hardware.data)
        associate_software(
            software_id=software["id"],
            hardware_asset_id=hardware.data["id"],
            user=self.operator,
        )
        changed = self.client.patch(
            f"/api/assets/{software['id']}/",
            {"software": {"version": "V19"}},
            format="json",
        )
        self.assertEqual(changed.status_code, 400, changed.data)
        self.assertEqual(
            Software.objects.get(pk=software["id"]).version, "V18"
        )

    def test_analyst_cannot_create_but_may_edit_description(self):
        software = self.client.post("/api/assets/", self.payload(), format="json")
        self.assertEqual(software.status_code, 201)
        self.client.force_authenticate(self.analyst)
        forbidden = self.client.post("/api/assets/", self.payload(version="V19"), format="json")
        self.assertEqual(forbidden.status_code, 403)

        change = self.client.patch(
            f"/api/assets/{software.data['id']}/",
            {"description": "Revisión de versión"},
            format="json",
        )
        self.assertEqual(change.status_code, 200, change.data)
        deny = self.client.patch(
            f"/api/assets/{software.data['id']}/",
            {"criticality": "HIGH"}, format="json",
        )
        self.assertEqual(deny.status_code, 403)

    def test_reject_mixed_hardware_software_payload(self):
        bad = self.payload()
        bad["interface_assignment"] = {"mode": "EXISTING", "interface_id": 10}
        response = self.client.post("/api/assets/", bad, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Asset.objects.count(), 0)

    def test_hardware_api_continues_to_work(self):
        response = self.client.post("/api/assets/", {
            "name": "PLC del laboratorio", "asset_type": "HARDWARE",
            "hardware": {"role": "PLC", "manufacturer": "AutomationDirect"},
        }, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["hardware"]["role"], "PLC")
        self.assertEqual(response.data["asset_type"], "HARDWARE")

    def test_software_archiving_uses_same_lifecycle(self):
        sw = self.client.post("/api/assets/", self.payload(), format="json")
        asset_id = sw.data["id"]
        archived = self.client.post(f"/api/assets/{asset_id}/archive/")
        self.assertEqual(archived.status_code, 200, archived.data)
        self.assertEqual(archived.data["inventory_status"], "ARCHIVED")
        restored = self.client.post(f"/api/assets/{asset_id}/restore/")
        self.assertEqual(restored.status_code, 200, restored.data)
        self.assertEqual(restored.data["inventory_status"], "ACTIVE")
