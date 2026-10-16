"""Read-only inventory relation expansion: existing API contracts.

Run with isolated SQLite settings:
python manage.py test assets.tests_inventory_relations_expand --settings=config.settings_test_sqlite -v 2
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .models import Asset, NetworkInterface
from .services import register_hardware_asset, change_inventory_status
from .software_services import (
    associate_software,
    register_installed_software_asset,
    unlink_software,
)


class InventoryRelationsExpansionAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="operator-relations", password="pw", role=User.Role.OPERATOR
        )
        self.analyst = User.objects.create_user(
            username="analyst-relations", password="pw", role=User.Role.ANALYST
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)

        self.hardware = register_hardware_asset(
            data={
                "name": "PLC de laboratorio", "asset_type": "HARDWARE",
                "hardware": {"role": "PLC", "manufacturer": "AutomationDirect"},
            },
            user=self.operator,
        )
        self.software = register_installed_software_asset(
            data={
                "name": "Firmware v1", "asset_type": "SOFTWARE",
                "software": {
                    "software_type": "FIRMWARE", "manufacturer": "AutomationDirect",
                    "product": "Firmware PLC", "version": "1.0",
                },
            },
            user=self.operator,
        )
        self.installation = associate_software(
            software_id=self.software.pk, hardware_asset_id=self.hardware.pk,
            user=self.operator,
        )

    def test_hardware_expansion_uses_active_software_api(self):
        response = self.client.get(
            f"/api/assets/{self.hardware.pk}/software-installations/"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data["results"]), 1)
        row = response.data["results"][0]
        self.assertEqual(row["id"], self.installation.pk)
        self.assertEqual(row["software_asset_id"], self.software.pk)
        self.assertEqual(row["name"], self.software.name)
        self.assertEqual(row["inventory_status"], "ACTIVE")

        unlink_software(installation_id=self.installation.pk, user=self.operator)
        updated = self.client.get(
            f"/api/assets/{self.hardware.pk}/software-installations/"
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data["results"], [])

    def test_software_expansion_uses_current_hardware_api(self):
        response = self.client.get(
            f"/api/assets/{self.software.pk}/hardware-installations/"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data["results"]), 1)
        item = response.data["results"][0]
        self.assertEqual(item["hardware_asset_id"], self.hardware.pk)
        self.assertEqual(item["hardware_name"], self.hardware.name)
        self.assertEqual(item["hardware_role"], "PLC")

    def test_hardware_interfaces_include_manual_without_active_evidence(self):
        interface = NetworkInterface.objects.create(
            mac="02:00:00:bb:aa:01",
            declared_ip="192.168.88.15",
            hardware=self.hardware.hardware,
            created_by=self.operator,
        )
        active_only = self.client.get(
            "/api/assets/interfaces/",
            {"hardware_id": self.hardware.pk, "evidence": "ACTIVE"},
        )
        self.assertEqual(active_only.status_code, 200, active_only.data)
        self.assertEqual(active_only.data["count"], 0)

        all_evidence = self.client.get(
            "/api/assets/interfaces/",
            {"hardware_id": self.hardware.pk, "evidence": "ALL"},
        )
        self.assertEqual(all_evidence.status_code, 200, all_evidence.data)
        self.assertEqual(all_evidence.data["count"], 1)
        self.assertEqual(all_evidence.data["results"][0]["id"], interface.pk)
        self.assertEqual(all_evidence.data["results"][0]["mac"], interface.mac)
        self.assertEqual(all_evidence.data["results"][0]["declared_ip"], "192.168.88.15")

    def test_hardware_interfaces_remain_paginated(self):
        for i in range(27):
            NetworkInterface.objects.create(
                mac=f"02:bb:11:22:33:{i:02x}",
                hardware=self.hardware.hardware,
            )
        page1 = self.client.get("/api/assets/interfaces/", {
            "hardware_id": self.hardware.pk, "evidence": "ALL", "page": 1,
        })
        page2 = self.client.get("/api/assets/interfaces/", {
            "hardware_id": self.hardware.pk, "evidence": "ALL", "page": 2,
        })
        self.assertEqual(page1.status_code, 200, page1.data)
        self.assertEqual(page2.status_code, 200, page2.data)
        self.assertEqual(page1.data["count"], 27)
        self.assertEqual(page1.data["page_size"], 25)
        self.assertEqual(len(page1.data["results"]), 25)
        self.assertEqual(len(page2.data["results"]), 2)
        self.assertFalse({
            row["id"] for row in page1.data["results"]
        } & {row["id"] for row in page2.data["results"]})

    def test_archived_related_software_is_visible_and_marked(self):
        change_inventory_status(
            asset=self.software,
            new_status=Asset.InventoryStatus.ARCHIVED,
            user=self.operator,
        )
        response = self.client.get(
            f"/api/assets/{self.hardware.pk}/software-installations/"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["results"][0]["inventory_status"], "ARCHIVED")

    def test_analyst_can_read_all_relation_endpoints(self):
        self.client.force_authenticate(self.analyst)
        software = self.client.get(
            f"/api/assets/{self.hardware.pk}/software-installations/"
        )
        hardware = self.client.get(
            f"/api/assets/{self.software.pk}/hardware-installations/"
        )
        interfaces = self.client.get(
            "/api/assets/interfaces/", {
                "hardware_id": self.hardware.pk, "evidence": "ALL",
            },
        )
        self.assertEqual(software.status_code, 200)
        self.assertEqual(hardware.status_code, 200)
        self.assertEqual(interfaces.status_code, 200)
