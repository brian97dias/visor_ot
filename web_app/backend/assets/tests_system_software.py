"""System software is a derived read model, never a direct OTSystem relationship."""
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from .models import Asset, Software, SoftwareInstallation, SystemMembership
from .services import change_inventory_status
from .system_services import register_system, change_system_status
from .services import register_hardware_asset
from .system_membership_services import associate_hardware_to_system, unlink_hardware_from_system
from .software_services import associate_software, unlink_software


class SystemSoftwareAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user("sys-sw-operator", role=User.Role.OPERATOR)
        self.analyst = User.objects.create_user("sys-sw-analyst", role=User.Role.ANALYST)
        self.client = APIClient()
        self.client.force_authenticate(user=self.operator)
        self.system = register_system(data={"name": "Planta experimental"}, user=self.operator)
        self.system2 = register_system(data={"name": "Otro sistema"}, user=self.operator)
        self.hw1 = self.hardware("PLC 1")
        self.hw2 = self.hardware("HMI 2")
        self.hw3 = self.hardware("Dispositivo externo")
        self.url = f"/api/assets/systems/{self.system.pk}/software/"

    def hardware(self, name):
        return register_hardware_asset(
            data={"name": name, "asset_type": Asset.AssetType.HARDWARE,
                  "hardware": {"role": "PLC"}}, user=self.operator,
        )

    def software(self, name, product, version, kind="FIRMWARE"):
        asset = Asset.objects.create(
            name=name, asset_type=Asset.AssetType.SOFTWARE,
            created_by=self.operator, updated_by=self.operator,
        )
        return Software.objects.create(
            asset=asset, software_type=kind,
            manufacturer="Pruebas OT", product=product, version=version,
        )

    def membership(self, hardware, system=None):
        return associate_hardware_to_system(
            system_id=(system or self.system).pk,
            hardware_asset_id=hardware.pk, user=self.operator,
        )

    def install(self, hardware, software):
        return associate_software(
            software_id=software.pk, hardware_asset_id=hardware.pk, user=self.operator,
        )

    def read(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        return response.data

    def test_empty_system_has_zero_software(self):
        result = self.read()
        self.assertEqual(result["participant_hardware_count"], 0)
        self.assertEqual(result["software_count"], 0)
        self.assertEqual(result["installation_count"], 0)
        self.assertEqual(result["results"], [])

    def test_member_without_installations_is_counted_but_has_no_software(self):
        self.membership(self.hw1)
        result = self.read()
        self.assertEqual(result["participant_hardware_count"], 1)
        self.assertEqual(result["results"], [])

    def test_two_hosts_same_variant_are_deduplicated_with_host_provenance(self):
        self.membership(self.hw1)
        self.membership(self.hw2)
        firmware = self.software("Firmware controlador", "CPU firmware", "1.0")
        self.install(self.hw1, firmware)
        self.install(self.hw2, firmware)
        result = self.read()
        self.assertEqual(result["participant_hardware_count"], 2)
        self.assertEqual(result["software_count"], 1)
        self.assertEqual(result["installation_count"], 2)
        row = result["results"][0]
        self.assertEqual(row["software_asset_id"], firmware.pk)
        self.assertEqual(row["software_type"], "FIRMWARE")
        self.assertEqual(row["version"], "1.0")
        self.assertEqual(row["hardware_count"], 2)
        self.assertEqual({host["hardware_asset_id"] for host in row["hardware"]},
                         {self.hw1.pk, self.hw2.pk})
        self.assertTrue(all(host["installation_id"] for host in row["hardware"]))

    def test_multiple_variants_and_software_types_remain_distinct(self):
        self.membership(self.hw1)
        one = self.software("Firmware 1", "CPU", "1.0")
        two = self.software("Firmware 2", "CPU", "2.0")
        three = self.software("Supervisión", "SCADA", "3.0", "APPLICATION")
        for software in (one, two, three):
            self.install(self.hw1, software)
        rows = self.read()["results"]
        self.assertEqual(len(rows), 3)
        self.assertEqual({row["software_asset_id"] for row in rows},
                         {one.pk, two.pk, three.pk})
        self.assertIn("APPLICATION", [row["software_type"] for row in rows])

    def test_excludes_unlinked_installation_and_system_membership(self):
        membership = self.membership(self.hw1)
        self.membership(self.hw2)
        keep = self.software("Software activo", "Producto A", "1")
        old = self.software("Software retirado", "Producto B", "1")
        self.install(self.hw2, keep)
        installation = self.install(self.hw1, old)
        unlink_software(installation_id=installation.pk, user=self.operator)
        self.assertEqual([r["software_asset_id"] for r in self.read()["results"]], [keep.pk])
        # Re-installation is current, but no longer in the system after member unlink.
        self.install(self.hw1, old)
        unlink_hardware_from_system(membership_id=membership.pk, user=self.operator)
        self.assertEqual([r["software_asset_id"] for r in self.read()["results"]], [keep.pk])

    def test_nonmember_installations_and_other_systems_do_not_leak(self):
        self.membership(self.hw1)
        self.membership(self.hw3, self.system2)
        known = self.software("Dentro", "PLC", "1")
        outside = self.software("Fuera", "RTU", "1")
        self.install(self.hw1, known)
        self.install(self.hw3, outside)
        self.assertEqual([r["software_asset_id"] for r in self.read()["results"]], [known.pk])

    def test_archived_assets_and_system_preserve_current_relationships(self):
        self.membership(self.hw1)
        sw = self.software("Firmware aún instalado", "Firmware", "1")
        self.install(self.hw1, sw)
        change_inventory_status(asset=self.hw1, new_status=Asset.InventoryStatus.ARCHIVED,
                                user=self.operator)
        change_inventory_status(asset=sw.asset, new_status=Asset.InventoryStatus.ARCHIVED,
                                user=self.operator)
        change_system_status(system_id=self.system.pk, new_status="ARCHIVED", user=self.operator)
        row = self.read()["results"][0]
        self.assertEqual(row["inventory_status"], "ARCHIVED")
        self.assertEqual(row["hardware"][0]["inventory_status"], "ARCHIVED")

    def test_changes_are_reflected_without_snapshot_storage(self):
        self.membership(self.hw1)
        self.assertEqual(self.read()["software_count"], 0)
        sw = self.software("Firmware nuevo", "Control", "1.0")
        installation = self.install(self.hw1, sw)
        self.assertEqual(self.read()["software_count"], 1)
        unlink_software(installation_id=installation.pk, user=self.operator)
        self.assertEqual(self.read()["software_count"], 0)

    def test_analyst_read_and_unauthenticated_and_unknown_system(self):
        self.client.force_authenticate(user=self.analyst)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        self.assertEqual(self.client.post(self.url, {}, format="json").status_code, 403)
        self.assertEqual(self.client.get("/api/assets/systems/999999/software/").status_code, 404)
        self.client.force_authenticate(user=None)
        self.assertIn(self.client.get(self.url).status_code, (401, 403))

    def test_constant_query_count_for_many_current_installations(self):
        self.membership(self.hw1)
        with CaptureQueriesContext(connection) as no_install_queries:
            self.read()
        for number in range(10):
            self.install(self.hw1, self.software(f"Aplicación {number}", f"App {number}", "1",
                                                  "APPLICATION"))
        with CaptureQueriesContext(connection) as many_install_queries:
            self.read()
        self.assertLessEqual(len(many_install_queries), len(no_install_queries) + 1)
