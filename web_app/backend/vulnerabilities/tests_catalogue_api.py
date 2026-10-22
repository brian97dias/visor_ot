"""Retired manual catalogue HTTP explorer: cache persistence remains independent."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from assets.services import register_hardware_asset
from vulnerabilities.models import CpeQuerySnapshot, CpeSearchRun
from vulnerabilities.services.cpe_catalogue import enqueue_catalogue_query
from users.models import User


class RetiredCatalogueExplorerApiTests(TestCase):
    def setUp(self):
        analyst = get_user_model().objects.create_user(
            username="retired-catalogue-analyst", role=User.Role.ANALYST
        )
        self.client = APIClient()
        self.client.force_authenticate(analyst)
        self.asset = register_hardware_asset(
            data={"name": "Phoenix Contact", "asset_type": "HARDWARE",
                  "hardware": {"manufacturer": "Phoenix Contact",
                               "model": "FL IL 24 BK-PAC", "role": "PLC"}},
            user=analyst,
        )
        self.snapshot, _ = enqueue_catalogue_query(
            "cpeMatchString", "cpe:2.3:h:phoenixcontact"
        )

    def test_removed_browse_and_selection_routes_are_not_exposed(self):
        prefix = f"/api/vulnerabilities/assets/{self.asset.pk}/cpe-catalogue/snapshots/"
        self.assertEqual(self.client.get(prefix).status_code, 404)
        self.assertEqual(self.client.get(f"{prefix}{self.snapshot.pk}/").status_code, 404)
        self.assertEqual(self.client.post(
            f"{prefix}{self.snapshot.pk}/select/", {"evidence_id": 1},
            format="json",
        ).status_code, 404)
        self.assertFalse(CpeSearchRun.objects.exists())
        self.assertTrue(CpeQuerySnapshot.objects.filter(pk=self.snapshot.pk).exists())
