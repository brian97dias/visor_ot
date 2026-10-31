"""CPE searches begin only with an explicit authenticated analyst request.

Creation and editing of OT inventory assets never schedule NVD work.
Run: python manage.py test vulnerabilities.tests_on_demand --settings=config.settings_test_sqlite
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from vulnerabilities.models import CpeSearchRun, CpeQuerySnapshot
from assets.models import OTSystem


class AnalystInitiatedSearchTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="on-demand-operator", role=User.Role.OPERATOR
        )
        self.analyst = User.objects.create_user(
            username="on-demand-analyst", role=User.Role.ANALYST
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)
        self.system = OTSystem.objects.create(
            name="Laboratorio OT", criticality="MEDIUM",
            created_by=self.operator, updated_by=self.operator,
        )

    def test_register_and_update_assets_never_queue_cpe_or_call_nvd(self):
        with patch("vulnerabilities.services.nvd_client.fetch_page") as fetcher:
            hardware = self.client.post("/api/assets/", {
                "asset_type": "HARDWARE", "name": "PLC de prueba",
                "criticality": "MEDIUM", "system_ids": [self.system.pk],
                "hardware": {"manufacturer": "Siemens",
                             "model": "SIMATIC S7-1200", "role": "PLC"},
            }, format="json")
            self.assertEqual(hardware.status_code, 201, hardware.data)
            software = self.client.post("/api/assets/", {
                "asset_type": "SOFTWARE", "name": "IOS de prueba",
                "criticality": "MEDIUM",
                "software": {"software_type": "OS", "manufacturer": "Cisco",
                             "product": "IOS", "version": "12.1"},
            }, format="json")
            self.assertEqual(software.status_code, 201, software.data)
            edited = self.client.patch(
                f"/api/assets/{software.data['id']}/",
                {"description": "Inventariado manualmente"},
                format="json",
            )
            self.assertEqual(edited.status_code, 200, edited.data)
        fetcher.assert_not_called()
        self.assertFalse(CpeSearchRun.objects.exists())
        self.assertFalse(CpeQuerySnapshot.objects.exists())

    def test_explicit_search_queues_without_running_nvd(self):
        hardware = self.client.post("/api/assets/", {
            "asset_type": "HARDWARE", "name": "PLC bajo demanda",
                "criticality": "MEDIUM", "system_ids": [self.system.pk],
            "hardware": {"manufacturer": "Siemens",
                         "model": "SIMATIC S7-1200", "role": "PLC"},
        }, format="json")
        self.assertEqual(hardware.status_code, 201, hardware.data)
        self.assertFalse(CpeSearchRun.objects.exists())
        self.client.force_authenticate(self.analyst)
        endpoint = f"/api/vulnerabilities/assets/{hardware.data['id']}/cpe-searches/"
        with patch("vulnerabilities.services.nvd_client.fetch_page") as fetcher:
            response = self.client.post(endpoint, {"scope": "SPECIFIC"}, format="json")
        self.assertEqual(response.status_code, 202, response.data)
        run = CpeSearchRun.objects.get(pk=response.data["run_id"])
        self.assertEqual(run.trigger, "MANUAL")
        self.assertEqual(run.scope, CpeSearchRun.Scope.SPECIFIC)
        self.assertEqual(run.status, CpeSearchRun.Status.QUEUED)
        self.assertFalse(CpeQuerySnapshot.objects.exists())
        fetcher.assert_not_called()
        self.assertEqual(self.client.post(
            endpoint, {"scope": "BROAD"}, format="json"
        ).status_code, 400)
        self.assertEqual(CpeSearchRun.objects.count(), 1)
