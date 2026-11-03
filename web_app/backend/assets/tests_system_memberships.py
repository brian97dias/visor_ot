"""SystemMembership API permissions, lifecycle, history and atomic creation."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .models import Asset, Hardware, OTSystem, SystemMembership
from .services import register_hardware_asset, change_inventory_status
from .system_services import register_system, change_system_status


class SystemMembershipAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(
            "system-membership-admin", role=User.Role.ADMIN,
        )
        self.operator = User.objects.create_user(
            "system-membership-operator", role=User.Role.OPERATOR,
        )
        self.analyst = User.objects.create_user(
            "system-membership-analyst", role=User.Role.ANALYST,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)
        self.system = register_system(data={"name": "Sistema A", "criticality": "HIGH"}, user=self.operator)
        self.system_b = register_system(data={"name": "Sistema B", "criticality": "MEDIUM"}, user=self.operator)
        self.hardware = self.make_hardware("PLC-01")
        self.hardware_b = self.make_hardware("HMI-01")

    def make_hardware(self, name):
        return register_hardware_asset(
            data={"name": name, "asset_type": Asset.AssetType.HARDWARE,
                  "hardware": {"role": "PLC"}}, user=self.operator,
        )

    def system_path(self, system=None):
        return f"/api/assets/systems/{(system or self.system).pk}/hardware/"

    def hardware_path(self, asset=None):
        return f"/api/assets/{(asset or self.hardware).pk}/systems/"

    def attach(self, system=None, asset=None):
        return self.client.post(
            self.system_path(system),
            {"hardware_asset_id": (asset or self.hardware).pk},
            format="json",
        )

    def test_bidirectional_list_and_many_to_many(self):
        a = self.attach()
        self.assertEqual(a.status_code, 201, a.data)
        b = self.attach(system=self.system_b)
        self.assertEqual(b.status_code, 201, b.data)
        c = self.attach(asset=self.hardware_b)
        self.assertEqual(c.status_code, 201, c.data)
        self.assertEqual(SystemMembership.objects.count(), 3)
        current = self.client.get(self.hardware_path())
        self.assertEqual(current.status_code, 200)
        self.assertEqual(len(current.data["results"]), 2)
        self.assertEqual(len(self.client.get(self.system_path()).data["results"]), 2)
        self.assertEqual(current.data["history"], [])

    def test_duplicates_rejected_and_relink_creates_new_history(self):
        created = self.attach()
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(self.attach().status_code, 400)
        self.assertEqual(SystemMembership.objects.count(), 1)
        url = f"{self.system_path()}{created.data['id']}/"
        # A device can now lose its last active OT system association.
        self.assertEqual(self.client.delete(url).status_code, 204)
        self.assertEqual(self.client.delete(url).status_code, 400)
        again = self.attach()
        self.assertEqual(again.status_code, 201, again.data)
        self.assertNotEqual(created.data["id"], again.data["id"])
        self.assertEqual(len(self.client.get(self.system_path()).data["history"]), 1)
        history = SystemMembership.objects.get(pk=created.data["id"])
        self.assertEqual(history.unlinked_by, self.operator)
        self.assertIsNotNone(history.unlinked_at)

    def test_hardware_side_management_uses_same_membership(self):
        result = self.client.post(
            self.hardware_path(), {"system_id": self.system.pk}, format="json",
        )
        self.assertEqual(result.status_code, 201, result.data)
        self.assertEqual(result.data["hardware_asset_id"], self.hardware.pk)
        self.assertEqual(result.data["system_id"], self.system.pk)
        self.assertEqual(self.attach(system=self.system_b).status_code, 201)
        self.assertEqual(self.client.delete(
            f"{self.hardware_path()}{result.data['id']}/",
        ).status_code, 204)
        self.assertEqual(self.client.get(self.system_path()).data["results"], [])

    def test_archiving_preserves_memberships_and_blocks_new_links(self):
        first = self.attach()
        self.assertEqual(first.status_code, 201, first.data)
        self.assertEqual(self.attach(system=self.system_b).status_code, 201)
        change_system_status(
            system_id=self.system.pk, new_status=OTSystem.Status.ARCHIVED,
            user=self.operator,
        )
        self.assertEqual(len(self.client.get(self.system_path()).data["results"]), 1)
        self.assertEqual(self.attach(asset=self.hardware_b).status_code, 400)
        self.assertEqual(self.client.delete(
            f"{self.system_path()}{first.data['id']}/",
        ).status_code, 400)
        change_system_status(
            system_id=self.system.pk, new_status=OTSystem.Status.ACTIVE,
            user=self.operator,
        )
        self.assertEqual(len(self.client.get(self.system_path()).data["results"]), 1)

    def test_archived_hardware_cannot_be_newly_associated(self):
        change_inventory_status(
            asset=self.hardware, new_status=Asset.InventoryStatus.ARCHIVED,
            user=self.operator,
        )
        self.assertEqual(self.attach().status_code, 400)
        self.assertEqual(SystemMembership.objects.count(), 0)

    def test_archiving_hardware_does_not_unlink_existing(self):
        self.assertEqual(self.attach().status_code, 201)
        change_inventory_status(
            asset=self.hardware, new_status=Asset.InventoryStatus.ARCHIVED,
            user=self.operator,
        )
        rows = self.client.get(self.system_path()).data["results"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["hardware_status"], "ARCHIVED")

    def test_analyst_may_read_but_cannot_modify_from_either_side(self):
        created = self.attach()
        self.client.force_authenticate(self.analyst)
        self.assertEqual(self.client.get(self.system_path()).status_code, 200)
        self.assertEqual(self.client.get(self.hardware_path()).status_code, 200)
        self.assertEqual(self.attach(system=self.system_b).status_code, 403)
        self.assertEqual(self.client.post(
            self.hardware_path(), {"system_id": self.system_b.pk}, format="json",
        ).status_code, 403)
        self.assertEqual(self.client.delete(
            f"{self.system_path()}{created.data['id']}/",
        ).status_code, 403)

    def test_unauthenticated_requests_are_denied(self):
        self.client.force_authenticate(user=None)
        self.assertIn(self.client.get(self.system_path()).status_code, (401, 403))
        self.assertIn(self.attach().status_code, (401, 403))

    def test_invalid_hardware_system_and_scoped_delete(self):
        self.assertEqual(self.client.post(
            self.system_path(), {"hardware_asset_id": 987654}, format="json",
        ).status_code, 404)
        self.assertEqual(self.client.post(
            self.hardware_path(), {"system_id": 987654}, format="json",
        ).status_code, 404)
        row = self.attach().data
        self.assertEqual(self.client.delete(
            f"{self.system_path(self.system_b)}{row['id']}/",
        ).status_code, 404)
        self.assertIsNone(SystemMembership.objects.get(pk=row["id"]).unlinked_at)

    def test_atomic_optional_memberships_on_new_hardware(self):
        payload = {
            "name": "RTU asociado",
            "asset_type": "HARDWARE", "criticality": "LOW",
            "hardware": {"role": "RTU", "manufacturer": "Factory", "model": "RTU"},
            "system_ids": [self.system.pk, self.system_b.pk],
        }
        created = self.client.post("/api/assets/", payload, format="json")
        self.assertEqual(created.status_code, 201, created.data)
        rows = self.client.get(self.hardware_path(
            Asset.objects.get(pk=created.data["id"])
        )).data["results"]
        self.assertEqual(len(rows), 2)
        self.assertEqual({item["system_id"] for item in rows},
                         {self.system.pk, self.system_b.pk})

    def test_invalid_initial_selection_rolls_back_registration(self):
        start = Asset.objects.count()
        bad = self.client.post("/api/assets/", {
            "name": "No debe persistir", "asset_type": "HARDWARE",
            "criticality": "LOW",
            "hardware": {"role": "PLC", "manufacturer": "Siemens", "model": "1215C"},
            "system_ids": [self.system.pk, 999999],
        }, format="json")
        self.assertEqual(bad.status_code, 400, bad.data)
        self.assertEqual(Asset.objects.count(), start)
        duplicate = self.client.post("/api/assets/", {
            "name": "Repetido", "asset_type": "HARDWARE",
            "criticality": "LOW",
            "hardware": {"role": "PLC", "manufacturer": "Siemens", "model": "1215C"},
            "system_ids": [self.system.pk, self.system.pk],
        }, format="json")
        self.assertEqual(duplicate.status_code, 400, duplicate.data)
        self.assertEqual(Asset.objects.count(), start)

    def test_software_cannot_supply_system_ids(self):
        result = self.client.post("/api/assets/", {
            "name": "Firmware", "asset_type": "SOFTWARE",
            "software": {"software_type": "FIRMWARE", "product": "Firmware"},
            "system_ids": [self.system.pk],
        }, format="json")
        self.assertEqual(result.status_code, 400, result.data)

    def test_no_automatic_asset_criticality_changes(self):
        self.assertEqual(self.attach().status_code, 201)
        self.assertEqual(self.hardware.criticality, "UNDEFINED")
        self.assertEqual(Asset.objects.get(pk=self.hardware.pk).criticality, "UNDEFINED")
