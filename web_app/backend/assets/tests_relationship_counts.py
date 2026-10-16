"""Inventory list relationship counters: current associations only.

Run:
    python manage.py test assets.tests_relationship_counts \
      --settings=config.settings_test_sqlite -v 2

Aggregations should also be checked against PostgreSQL in the running app.
"""
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from .models import Asset, NetworkInterface, SoftwareInstallation
from .services import register_hardware_asset, change_inventory_status
from .software_services import (
    associate_software,
    register_installed_software_asset,
    unlink_software,
)


class InventoryRelationshipCountsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="operator-counts", password="pw", role=User.Role.OPERATOR,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)

        self.hardware_a = register_hardware_asset(
            data={
                "asset_type": "HARDWARE", "name": "PLC principal",
                "hardware": {"role": "PLC", "manufacturer": "AutomationDirect"},
            }, user=self.operator,
        )
        self.hardware_b = register_hardware_asset(
            data={
                "asset_type": "HARDWARE", "name": "PLC secundario",
                "hardware": {"role": "PLC"},
            }, user=self.operator,
        )
        self.software_a = register_installed_software_asset(
            data={
                "asset_type": "SOFTWARE", "name": "Firmware v1",
                "software": {
                    "software_type": "FIRMWARE", "manufacturer": "Fabricante A",
                    "product": "PLC Firmware", "version": "1.0",
                },
            }, user=self.operator,
        )
        self.software_b = register_installed_software_asset(
            data={
                "asset_type": "SOFTWARE", "name": "Firmware v2",
                "software": {
                    "software_type": "FIRMWARE", "manufacturer": "Fabricante A",
                    "product": "PLC Firmware", "version": "2.0",
                },
            }, user=self.operator,
        )

    def inventory(self, inventory_status="ALL"):
        response = self.client.get(
            "/api/assets/", {"inventory_status": inventory_status},
        )
        self.assertEqual(response.status_code, 200, response.data)
        return {item["id"]: item for item in response.data["assets"]}

    def add_link(self, software, hardware):
        return associate_software(
            software_id=software.pk,
            hardware_asset_id=hardware.pk,
            user=self.operator,
        )

    def test_zero_counts_for_hardware_and_software_without_links(self):
        data = self.inventory()
        for pk in (self.hardware_a.pk, self.hardware_b.pk,
                   self.software_a.pk, self.software_b.pk):
            self.assertEqual(data[pk]["software_count"], 0)
            self.assertEqual(data[pk]["interface_count"], 0)
            self.assertEqual(data[pk]["hardware_count"], 0)

    def test_distinct_counts_with_two_software_and_multiple_interfaces(self):
        # A regular joined COUNT would multiply 2 installations by 3 NICs.
        self.add_link(self.software_a, self.hardware_a)
        self.add_link(self.software_b, self.hardware_a)
        self.add_link(self.software_a, self.hardware_b)
        for i in range(3):
            NetworkInterface.objects.create(
                mac=f"02:11:22:33:44:{i+1:02x}",
                hardware=self.hardware_a.hardware,
                created_by=self.operator,
            )
        data = self.inventory()
        self.assertEqual(data[self.hardware_a.pk]["software_count"], 2)
        self.assertEqual(data[self.hardware_a.pk]["interface_count"], 3)
        self.assertEqual(data[self.hardware_a.pk]["hardware_count"], 0)
        self.assertEqual(data[self.hardware_b.pk]["software_count"], 1)
        self.assertEqual(data[self.software_a.pk]["hardware_count"], 2)
        self.assertEqual(data[self.software_b.pk]["hardware_count"], 1)
        self.assertEqual(data[self.software_a.pk]["interface_count"], 0)
        self.assertEqual(data[self.software_a.pk]["software_count"], 0)

    def test_unlinked_installation_is_not_counted_even_with_history(self):
        original = self.add_link(self.software_a, self.hardware_a)
        self.assertEqual(self.inventory()[self.hardware_a.pk]["software_count"], 1)
        unlink_software(installation_id=original.pk, user=self.operator)
        data = self.inventory()
        self.assertEqual(data[self.hardware_a.pk]["software_count"], 0)
        self.assertEqual(data[self.software_a.pk]["hardware_count"], 0)
        self.assertEqual(SoftwareInstallation.objects.count(), 1)
        self.add_link(self.software_a, self.hardware_a)
        data = self.inventory()
        self.assertEqual(data[self.hardware_a.pk]["software_count"], 1)
        self.assertEqual(data[self.software_a.pk]["hardware_count"], 1)
        self.assertEqual(SoftwareInstallation.objects.count(), 2)

    def test_archived_counterpart_remains_counted_if_link_is_current(self):
        self.add_link(self.software_a, self.hardware_a)
        change_inventory_status(
            asset=self.software_a,
            new_status=Asset.InventoryStatus.ARCHIVED,
            user=self.operator,
        )
        active = self.inventory("ACTIVE")
        self.assertNotIn(self.software_a.pk, active)
        self.assertEqual(active[self.hardware_a.pk]["software_count"], 1)
        archived = self.inventory("ARCHIVED")
        self.assertEqual(archived[self.software_a.pk]["hardware_count"], 1)
        self.assertEqual(self.inventory("ALL")[self.software_a.pk]["hardware_count"], 1)

    def test_interface_unlink_changes_count_without_deleting_interface(self):
        interface = NetworkInterface.objects.create(
            mac="02:00:00:00:00:01",
            hardware=self.hardware_a.hardware,
        )
        self.assertEqual(self.inventory()[self.hardware_a.pk]["interface_count"], 1)
        interface.hardware = None
        interface.save()
        self.assertEqual(self.inventory()[self.hardware_a.pk]["interface_count"], 0)
        self.assertTrue(NetworkInterface.objects.filter(pk=interface.pk).exists())

    def test_list_counts_are_calculated_in_one_inventory_query(self):
        self.add_link(self.software_a, self.hardware_a)
        for i in range(8):
            NetworkInterface.objects.create(
                mac=f"02:aa:bb:cc:dd:{i+1:02x}",
                hardware=self.hardware_a.hardware,
            )
        with CaptureQueriesContext(connection) as queries:
            data = self.inventory()
        self.assertEqual(data[self.hardware_a.pk]["interface_count"], 8)
        # The only query scanning the inventory is the joined aggregate.
        inventory_queries = [
            query["sql"] for query in queries.captured_queries
            if 'FROM "assets_asset"' in query["sql"]
        ]
        self.assertEqual(len(inventory_queries), 1, inventory_queries)
        self.assertIn("COUNT(", inventory_queries[0].upper())

    def test_detail_contract_is_unchanged(self):
        result = self.client.get(f"/api/assets/{self.hardware_a.pk}/")
        self.assertEqual(result.status_code, 200, result.data)
        self.assertNotIn("software_count", result.data)
        self.assertNotIn("hardware_count", result.data)
        self.assertNotIn("interface_count", result.data)
