"""Software endpoints: integration tests on isolated SQLite test database.

Run:
    python manage.py test assets.tests_software_api --settings=config.settings_test_sqlite -v 2
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .models import Asset, Software
from .software_services import associate_software
from .services import register_hardware_asset


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
        self.host = register_hardware_asset(
            data={
                "name": "Hardware principal",
                "asset_type": Asset.AssetType.HARDWARE,
                "hardware": {"role": "PLC"},
            },
            user=self.operator,
        )

    def payload(self, version="V18"):
        return {
            "name": "TIA Portal " + version if version else "ADAM Firmware",
            "asset_type": "SOFTWARE",
            "hardware_asset_id": self.host.pk,
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
        installations = self.client.get(
            f"/api/assets/{self.host.pk}/software-installations/"
        )
        self.assertEqual(installations.status_code, 200)
        self.assertEqual(len(installations.data["results"]), 1)
        self.assertEqual(
            installations.data["results"][0]["software_asset_id"], asset_id
        )

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
        self.assertEqual(Asset.objects.count(), 2)

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
        self.assertEqual(Asset.objects.count(), 1)

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


    def test_missing_host_is_rejected_without_creating_software(self):
        payload = self.payload()
        payload.pop("hardware_asset_id")
        response = self.client.post("/api/assets/", payload, format="json")
        self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(Software.objects.exists())

    def test_missing_hardware_target_rolls_back_entire_registration(self):
        payload = self.payload()
        payload["hardware_asset_id"] = 999999
        response = self.client.post("/api/assets/", payload, format="json")
        self.assertIn(response.status_code, (400, 404))
        self.assertFalse(Software.objects.exists())
        self.assertEqual(Asset.objects.count(), 1)

    def test_software_can_be_associated_with_another_hardware(self):
        software = self.client.post("/api/assets/", self.payload(), format="json")
        second = self.client.post("/api/assets/", {
            "name": "ENG-02", "asset_type": "HARDWARE",
            "hardware": {"role": "WORKSTATION"},
        }, format="json")
        self.assertEqual(second.status_code, 201, second.data)
        url = f"/api/assets/{second.data['id']}/software-installations/"
        association = self.client.post(
            url, {"software_asset_id": software.data["id"]}, format="json"
        )
        self.assertEqual(association.status_code, 201, association.data)
        self.assertEqual(association.data["software_asset_id"], software.data["id"])
        listing = self.client.get(url)
        self.assertEqual(len(listing.data["results"]), 1)
        self.assertEqual(Software.objects.count(), 1)

    def test_unlink_preserves_record_and_list_hides_it(self):
        software = self.client.post("/api/assets/", self.payload(), format="json")
        url = f"/api/assets/{self.host.pk}/software-installations/"
        rows = self.client.get(url).data["results"]
        self.assertEqual(len(rows), 1)
        deletion = self.client.delete(url + str(rows[0]["id"]) + "/")
        self.assertEqual(deletion.status_code, 204)
        self.assertEqual(self.client.get(url).data["results"], [])
        from .models import SoftwareInstallation
        self.assertEqual(SoftwareInstallation.objects.count(), 1)
        self.assertFalse(SoftwareInstallation.objects.get().is_active)
        self.assertTrue(Software.objects.filter(pk=software.data["id"]).exists())

    def test_analyst_can_read_installations_but_cannot_associate_or_unlink(self):
        software = self.client.post("/api/assets/", self.payload(), format="json")
        url = f"/api/assets/{self.host.pk}/software-installations/"
        installation_id = self.client.get(url).data["results"][0]["id"]
        self.client.force_authenticate(self.analyst)
        self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(
            self.client.post(url, {"software_asset_id": software.data["id"]}, format="json").status_code,
            403,
        )
        self.assertEqual(self.client.delete(url + str(installation_id) + "/").status_code, 403)

    def test_duplicate_active_installation_is_rejected(self):
        software = self.client.post("/api/assets/", self.payload(), format="json")
        url = f"/api/assets/{self.host.pk}/software-installations/"
        response = self.client.post(
            url, {"software_asset_id": software.data["id"]}, format="json"
        )
        self.assertEqual(response.status_code, 400)

    def test_cannot_install_software_on_archived_hardware(self):
        sw = self.client.post("/api/assets/", self.payload(), format="json")
        archive = self.client.post(f"/api/assets/{self.host.pk}/archive/")
        self.assertEqual(archive.status_code, 200, archive.data)
        attempt = self.client.post(
            f"/api/assets/{self.host.pk}/software-installations/",
            {"software_asset_id": sw.data["id"]},
            format="json",
        )
        self.assertEqual(attempt.status_code, 400)
