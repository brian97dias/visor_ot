"""Bulk CPE queue: per-asset outcomes, concurrency-safe reuse and no NVD I/O."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from assets.models import Asset
from assets.services import register_hardware_asset
from assets.software_services import register_installed_software_asset
from vulnerabilities.models import CpeSearchRun
from vulnerabilities.services.identity import fingerprint, hardware_identity


class CpeBulkSearchTests(TestCase):
    URL = "/api/vulnerabilities/cpe-searches/bulk/"

    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(username="bulk-analyst", role=User.Role.ANALYST)
        self.admin = User.objects.create_user(username="bulk-admin", role=User.Role.ADMIN)
        self.operator = User.objects.create_user(username="bulk-operator", role=User.Role.OPERATOR)
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.plc = self.hardware("PLC Siemens")
        self.other = self.hardware("PLC respaldo")
        self.software = register_installed_software_asset(
            data={
                "asset_type": "SOFTWARE", "name": "Firmware Siemens",
                "software": {
                    "software_type": "FIRMWARE", "manufacturer": "Siemens",
                    "product": "SIMATIC Firmware", "version": "4.5.0",
                },
            }, user=self.operator,
        )

    def hardware(self, name):
        return register_hardware_asset(
            data={
                "name": name, "asset_type": "HARDWARE",
                "hardware": {
                    "manufacturer": "Siemens", "model": "SIMATIC S7-1200",
                    "cpu_model": "1215C", "role": "PLC",
                },
            }, user=self.operator,
        )

    def bulk(self, ids, **extra):
        return self.client.post(self.URL, {"asset_ids": ids, **extra}, format="json")

    def test_valid_hardware_queued_without_issuing_nvd_requests(self):
        with patch("vulnerabilities.services.nvd_client.fetch_page") as fetcher:
            response = self.bulk([self.plc.pk, self.other.pk])
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(response.data["scope"], "SPECIFIC")
        self.assertEqual(response.data["summary"], {
            "received": 2, "queued": 2, "reused": 0, "skipped": 0, "failed": 0
        })
        self.assertEqual([r["outcome"] for r in response.data["results"]], ["QUEUED", "QUEUED"])
        self.assertEqual(CpeSearchRun.objects.count(), 2)
        self.assertEqual(
            list(CpeSearchRun.objects.order_by("pk").values_list("status", flat=True)),
            ["QUEUED", "QUEUED"],
        )
        fetcher.assert_not_called()

    def test_duplicate_ids_are_deduplicated_and_second_request_reuses_run(self):
        first = self.bulk([self.plc.pk, self.plc.pk])
        self.assertEqual(first.status_code, 202, first.data)
        self.assertEqual(first.data["summary"]["received"], 1)
        second = self.bulk([self.plc.pk])
        self.assertEqual(second.status_code, 202, second.data)
        self.assertEqual(second.data["summary"]["reused"], 1)
        self.assertEqual(second.data["results"][0]["run_id"], first.data["results"][0]["run_id"])
        self.assertEqual(CpeSearchRun.objects.count(), 1)

    def test_software_is_selected_but_not_enqueued_and_hardware_continues(self):
        response = self.bulk([self.software.pk, self.plc.pk])
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(
            [r["outcome"] for r in response.data["results"]],
            ["UNSUPPORTED", "QUEUED"],
        )
        self.assertEqual(response.data["summary"]["skipped"], 1)
        self.assertEqual(response.data["summary"]["queued"], 1)
        self.assertFalse(CpeSearchRun.objects.filter(asset=self.software).exists())

    def test_software_only_returns_200_without_impossible_queue_jobs(self):
        response = self.bulk([self.software.pk])
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["summary"]["queued"], 0)
        self.assertEqual(response.data["summary"]["skipped"], 1)
        self.assertEqual(CpeSearchRun.objects.count(), 0)

    def test_missing_invalid_identity_and_archived_do_not_block_valid_neighbors(self):
        invalid = self.hardware("Sin fabricante")
        invalid.hardware.manufacturer = ""
        invalid.hardware.save(update_fields=["manufacturer"])
        archived = self.hardware("PLC archivado")
        archived.inventory_status = Asset.InventoryStatus.ARCHIVED
        archived.save(update_fields=["inventory_status"])
        response = self.bulk([999999, invalid.pk, archived.pk, self.plc.pk])
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(
            [r["outcome"] for r in response.data["results"]],
            ["NOT_FOUND", "INVALID_IDENTITY", "SKIPPED", "QUEUED"],
        )
        self.assertEqual(response.data["summary"], {
            "received": 4, "queued": 1, "reused": 0, "skipped": 1, "failed": 2,
        })
        self.assertEqual(CpeSearchRun.objects.count(), 1)

    def test_active_running_run_reused_but_different_identity_is_a_new_job(self):
        old = self.bulk([self.plc.pk]).data["results"][0]["run_id"]
        CpeSearchRun.objects.filter(pk=old).update(status=CpeSearchRun.Status.RUNNING)
        again = self.bulk([self.plc.pk])
        self.assertEqual(again.data["summary"]["reused"], 1)
        self.assertEqual(again.data["results"][0]["run_id"], old)
        self.plc.hardware.cpu_model = "1214C"
        self.plc.hardware.save(update_fields=["cpu_model"])
        fresh = self.bulk([self.plc.pk])
        self.assertEqual(fresh.data["summary"]["queued"], 1)
        self.assertNotEqual(fresh.data["results"][0]["run_id"], old)
        self.assertEqual(CpeSearchRun.objects.count(), 2)

    def test_completed_job_is_not_reused(self):
        old = self.bulk([self.plc.pk]).data["results"][0]["run_id"]
        CpeSearchRun.objects.filter(pk=old).update(status=CpeSearchRun.Status.COMPLETED)
        again = self.bulk([self.plc.pk])
        self.assertEqual(again.data["summary"]["queued"], 1)
        self.assertNotEqual(again.data["results"][0]["run_id"], old)

    def test_bulk_endpoint_requires_allowed_role(self):
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.bulk([self.plc.pk]).status_code, 403)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.bulk([self.plc.pk]).status_code, 401)
        self.client.force_authenticate(self.admin)
        self.assertEqual(self.bulk([self.plc.pk]).status_code, 202)

    def test_rejects_broad_scope_and_invalid_payloads(self):
        self.assertEqual(self.bulk([self.plc.pk], scope="BROAD").status_code, 400)
        for ids in ([], [0], ["not-id"], list(range(1, 102))):
            with self.subTest(ids_len=len(ids)):
                self.assertEqual(self.bulk(ids).status_code, 400)
        self.assertEqual(CpeSearchRun.objects.count(), 0)

    def test_search_uses_specific_scope_even_for_model_without_cpu(self):
        self.plc.hardware.cpu_model = ""
        self.plc.hardware.save(update_fields=["cpu_model"])
        response = self.bulk([self.plc.pk])
        self.assertEqual(response.status_code, 202, response.data)
        run = CpeSearchRun.objects.get(pk=response.data["results"][0]["run_id"])
        self.assertEqual(run.scope, "SPECIFIC")
        self.assertEqual(run.identity_snapshot["cpu_model"], "")
