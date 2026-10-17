"""Relationship counts for both inventory lists (current links, distinct variants)."""
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from .models import Asset, NetworkInterface
from .services import register_hardware_asset, change_inventory_status
from .software_services import (
    register_installed_software_asset, associate_software, unlink_software,
)
from .system_services import register_system, change_system_status
from .system_membership_services import (
    associate_hardware_to_system, unlink_hardware_from_system,
)


class SystemRelationshipSummaryTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            "system-summary-operator", role=User.Role.OPERATOR,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.system = register_system(
            data={"name": "Entorno experimental"}, user=self.user,
        )
        self.other_system = register_system(
            data={"name": "Sistema compartido"}, user=self.user,
        )
        self.hardware_a = self.make_hardware("PLC")
        self.hardware_b = self.make_hardware("HMI")
        self.software = register_installed_software_asset(
            data={"name": "Firmware", "asset_type": "SOFTWARE",
                  "software": {"software_type": "FIRMWARE",
                               "product": "Firmware PLC", "version": "1.0"}},
            user=self.user,
        )

    def make_hardware(self, name):
        return register_hardware_asset(
            data={"name": name, "asset_type": "HARDWARE",
                  "hardware": {"role": "PLC"}},
            user=self.user,
        )

    def join(self, hardware, system=None):
        return associate_hardware_to_system(
            hardware_asset_id=hardware.pk,
            system_id=(system or self.system).pk, user=self.user,
        )

    def systems(self):
        response = self.client.get("/api/assets/systems/?status=ALL")
        self.assertEqual(response.status_code, 200, response.data)
        return {record["id"]: record for record in response.data["systems"]}

    def assets(self):
        response = self.client.get("/api/assets/?inventory_status=ALL")
        self.assertEqual(response.status_code, 200, response.data)
        return {record["id"]: record for record in response.data["assets"]}

    def test_counts_start_at_zero_and_software_is_not_a_system_member(self):
        sys = self.systems()[self.system.pk]
        self.assertEqual(sys["hardware_count"], 0)
        self.assertEqual(sys["software_count"], 0)
        inv = self.assets()
        self.assertEqual(inv[self.hardware_a.pk]["system_count"], 0)
        self.assertEqual(inv[self.software.pk]["system_count"], 0)

    def test_multiple_hardware_with_one_shared_software_variant(self):
        self.join(self.hardware_a)
        self.join(self.hardware_b)
        self.join(self.hardware_a, self.other_system)
        associate_software(software_id=self.software.pk,
                           hardware_asset_id=self.hardware_a.pk, user=self.user)
        associate_software(software_id=self.software.pk,
                           hardware_asset_id=self.hardware_b.pk, user=self.user)
        NetworkInterface.objects.create(
            hardware=self.hardware_a.hardware, mac="02:ab:cd:ef:00:01",
        )
        sys = self.systems()
        self.assertEqual(sys[self.system.pk]["hardware_count"], 2)
        self.assertEqual(sys[self.system.pk]["software_count"], 1)
        self.assertEqual(sys[self.other_system.pk]["hardware_count"], 1)
        self.assertEqual(sys[self.other_system.pk]["software_count"], 1)
        inv = self.assets()
        self.assertEqual(inv[self.hardware_a.pk]["system_count"], 2)
        self.assertEqual(inv[self.hardware_a.pk]["software_count"], 1)
        self.assertEqual(inv[self.hardware_a.pk]["interface_count"], 1)
        self.assertEqual(inv[self.hardware_b.pk]["system_count"], 1)
        self.assertEqual(inv[self.software.pk]["system_count"], 0)

    def test_unlinked_membership_is_not_counted_but_relink_counts_once(self):
        first = self.join(self.hardware_a)
        self.assertEqual(self.systems()[self.system.pk]["hardware_count"], 1)
        unlink_hardware_from_system(membership_id=first.pk, user=self.user)
        self.assertEqual(self.systems()[self.system.pk]["hardware_count"], 0)
        self.assertEqual(self.assets()[self.hardware_a.pk]["system_count"], 0)
        self.join(self.hardware_a)
        self.assertEqual(self.systems()[self.system.pk]["hardware_count"], 1)

    def test_unlinked_software_is_excluded_from_system_variant_count(self):
        self.join(self.hardware_a)
        inst = associate_software(
            software_id=self.software.pk,
            hardware_asset_id=self.hardware_a.pk, user=self.user,
        )
        self.assertEqual(self.systems()[self.system.pk]["software_count"], 1)
        unlink_software(installation_id=inst.pk, user=self.user)
        self.assertEqual(self.systems()[self.system.pk]["software_count"], 0)

    def test_archive_does_not_erase_current_relationships(self):
        self.join(self.hardware_a)
        associate_software(
            software_id=self.software.pk,
            hardware_asset_id=self.hardware_a.pk, user=self.user,
        )
        change_inventory_status(
            asset=self.hardware_a, new_status=Asset.InventoryStatus.ARCHIVED,
            user=self.user,
        )
        change_inventory_status(
            asset=self.software, new_status=Asset.InventoryStatus.ARCHIVED,
            user=self.user,
        )
        change_system_status(
            system_id=self.system.pk, new_status="ARCHIVED", user=self.user,
        )
        self.assertEqual(self.systems()[self.system.pk]["software_count"], 1)
        self.assertEqual(self.assets()[self.hardware_a.pk]["system_count"], 1)

    def test_count_queries_do_not_grow_with_records(self):
        with CaptureQueriesContext(connection) as empty:
            self.systems()
            self.assets()
        self.join(self.hardware_a)
        self.join(self.hardware_b)
        for idx in range(8):
            sw = register_installed_software_asset(
                data={"name": f"Aplicación {idx}", "asset_type": "SOFTWARE",
                      "software": {"software_type": "APPLICATION",
                                   "product": f"App {idx}", "version": "1.0"}},
                user=self.user,
            )
            associate_software(
                software_id=sw.pk, hardware_asset_id=self.hardware_a.pk,
                user=self.user,
            )
        with CaptureQueriesContext(connection) as populated:
            self.systems()
            self.assets()
        self.assertLessEqual(len(populated), len(empty) + 1)
