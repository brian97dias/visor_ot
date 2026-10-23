"""CVE discovery HTTP contract: role access, no network and honest findings."""
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from assets.models import Asset
from vulnerabilities.models import (
    AssetCpe, AssetCveAssessment, AssetCveFinding, Cve, CveDiscoveryRun,
)
from vulnerabilities.services.cve_discovery_worker import execute_cve_discovery_run
from vulnerabilities.tests_cve_discovery_api import page, record
from vulnerabilities.tests_cve_discovery_plan import CveDiscoveryPlanTests, HW_CPE


class CveDiscoveryHttpTests(TestCase):
    URL = "/api/vulnerabilities/cve-discoveries/"

    def setUp(self):
        example = CveDiscoveryPlanTests(
            methodName="test_hardware_only_cpe_is_eligible_without_firmware_cpe"
        )
        example.setUp()
        self.user = example.user
        self.hardware = example.hardware
        example.confirm(self.hardware.asset, HW_CPE)
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="cve-api-operator", role=User.Role.OPERATOR,
        )
        self.admin = User.objects.create_user(
            username="cve-api-admin", role=User.Role.ADMIN,
        )

    def start(self, hardware_ids=None, **kwargs):
        return self.client.post(
            self.URL, {"hardware_ids": (
                [self.hardware.pk] if hardware_ids is None else hardware_ids
            ), **kwargs}, format="json",
        )

    def detail(self, run_id):
        return self.client.get(f"{self.URL}{run_id}/")

    def findings(self, run_id, params=None):
        return self.client.get(f"{self.URL}{run_id}/findings/", params or {})

    def test_start_enqueues_with_no_nvd_or_automatic_decisions(self):
        with patch(
            "vulnerabilities.services.nvd_cve_client.urlopen"
        ) as nvd:
            reply = self.start()
        self.assertEqual(reply.status_code, 202, reply.data)
        self.assertFalse(reply.data["reused"])
        run = CveDiscoveryRun.objects.get(pk=reply.data["run_id"])
        self.assertEqual(run.status, CveDiscoveryRun.Status.QUEUED)
        self.assertEqual(run.selected_hardware_ids, [self.hardware.pk])
        self.assertEqual(reply.data["run"]["query_count"], 1)
        self.assertEqual(reply.data["run"]["result_kind"], "CANDIDATE_DISCOVERY")
        nvd.assert_not_called()
        self.assertEqual(Cve.objects.count(), 0)
        self.assertEqual(AssetCpe.objects.count(), 1)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_repeat_request_reuses_active_job(self):
        first = self.start()
        second = self.start()
        self.assertEqual(second.status_code, 202)
        self.assertTrue(second.data["reused"])
        self.assertEqual(first.data["run_id"], second.data["run_id"])
        self.assertEqual(CveDiscoveryRun.objects.count(), 1)

    def test_new_request_after_completion_is_another_run(self):
        first = self.start().data["run_id"]
        CveDiscoveryRun.objects.filter(pk=first).update(
            status=CveDiscoveryRun.Status.COMPLETED
        )
        second = self.start().data
        self.assertFalse(second["reused"])
        self.assertNotEqual(first, second["run_id"])

    def test_operator_can_read_but_cannot_enqueue_and_anonymous_is_blocked(self):
        run_id = self.start().data["run_id"]
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.start().status_code, 403)
        self.assertEqual(self.detail(run_id).status_code, 200)
        self.assertEqual(self.client.get(self.URL).status_code, 200)
        self.assertEqual(self.findings(run_id).status_code, 200)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.start().status_code, 401)
        self.assertEqual(self.detail(run_id).status_code, 401)
        self.client.force_authenticate(self.admin)
        self.assertEqual(self.start().status_code, 202)

    def test_rejects_invalid_empty_excessive_or_unexpected_payloads(self):
        for identifiers in ([], [0], [999999] * 101, ["unknown"]):
            with self.subTest(identifiers=identifiers):
                response = self.start(identifiers)
                self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(self.start(page_size=1).status_code, 400)
        self.assertEqual(self.client.post(self.URL, {}, format="json").status_code, 400)
        self.assertEqual(CveDiscoveryRun.objects.count(), 0)

    def test_partial_valid_selection_is_visible_and_only_valid_cpes_queued(self):
        response = self.start([999999, self.hardware.pk, self.hardware.pk])
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(
            response.data["run"]["selected_hardware_ids"],
            [999999, self.hardware.pk],
        )
        self.assertEqual(response.data["run"]["eligible_hardware_ids"], [self.hardware.pk])
        self.assertEqual(response.data["run"]["query_count"], 1)

    def test_lists_runs_with_small_summary_and_limit(self):
        first = self.start().data["run_id"]
        CveDiscoveryRun.objects.filter(pk=first).update(
            status=CveDiscoveryRun.Status.COMPLETED
        )
        second = self.start().data["run_id"]
        response = self.client.get(self.URL, {"limit": 1})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data["runs"]), 1)
        self.assertEqual(response.data["runs"][0]["run_id"], second)
        self.assertNotIn("queries", response.data["runs"][0])
        self.assertEqual(self.client.get(self.URL, {"limit": 51}).status_code, 400)

    def test_detail_reports_checkpoints_without_exposing_large_id_lists(self):
        rid = self.start().data["run_id"]
        run = CveDiscoveryRun.objects.get(pk=rid)
        run.status = CveDiscoveryRun.Status.INCOMPLETE
        run.queries[0].update({
            "status": "RUNNING", "next_start_index": 25,
            "retrieved_count": 25, "pages_fetched": 2,
            "expected_total": 50, "seen_cve_ids": ["CVE-2024-12345"],
        })
        run.save(update_fields=["status", "queries"])
        answer = self.detail(rid)
        self.assertEqual(answer.status_code, 200, answer.data)
        self.assertEqual(answer.data["run"]["retrieved_occurrences"], 25)
        self.assertEqual(answer.data["run"]["pages_fetched"], 2)
        self.assertEqual(answer.data["run"]["queries"][0]["next_start_index"], 25)
        self.assertNotIn("seen_cve_ids", answer.data["run"]["queries"][0])
        self.assertNotIn("sources", answer.data["run"]["queries"][0])

    def test_missing_run_returns_404(self):
        self.assertEqual(self.detail(999999).status_code, 404)
        self.assertEqual(self.findings(999999).status_code, 404)

    def test_discovered_findings_are_paginated_and_only_candidates(self):
        rid = self.start().data["run_id"]
        run = CveDiscoveryRun.objects.get(pk=rid)
        reply = page([record("CVE-2024-65432"), record("CVE-2024-65433")],
                     total=2, size=500)
        result = execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(return_value=reply),
        )
        self.assertEqual(result.status, CveDiscoveryRun.Status.COMPLETED)
        first_page = self.findings(rid, {"page": 1, "page_size": 1})
        self.assertEqual(first_page.status_code, 200, first_page.data)
        self.assertEqual(first_page.data["count"], 2)
        self.assertEqual(len(first_page.data["results"]), 1)
        candidate = first_page.data["results"][0]
        self.assertEqual(candidate["candidate_status"], "CANDIDATE")
        self.assertEqual(candidate["evidence_status"], "CURRENT")
        self.assertEqual(candidate["hardware_id"], self.hardware.pk)
        self.assertEqual(candidate["sources"][0]["origin"], "HARDWARE")
        other_page = self.findings(rid, {"page": 2, "page_size": 1})
        self.assertEqual(other_page.data["count"], 2)
        self.assertNotEqual(
            candidate["cve_id"], other_page.data["results"][0]["cve_id"],
        )
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_archived_or_modified_inventory_marks_observation_stale(self):
        rid = self.start().data["run_id"]
        run = CveDiscoveryRun.objects.get(pk=rid)
        execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(
                return_value=page([record()], size=500),
            ),
        )
        before = self.findings(rid).data["results"][0]
        self.assertEqual(before["evidence_status"], "CURRENT")
        self.hardware.model = "Updated model"
        self.hardware.save(update_fields=["model"])
        after = self.findings(rid).data["results"][0]
        self.assertEqual(after["evidence_status"], "STALE")
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_findings_hardware_filter_is_bound_to_selected_run(self):
        rid = self.start().data["run_id"]
        self.assertEqual(self.findings(rid, {"hardware_id": 999999}).status_code, 400)
        self.assertEqual(self.findings(rid, {"page": 0}).status_code, 400)
        self.assertEqual(self.findings(rid, {"page_size": 101}).status_code, 400)
        self.assertEqual(self.findings(rid, {"page": 2}).status_code, 200)

    def test_finished_run_findings_are_a_latest_projection_not_history(self):
        first = self.start().data["run_id"]
        run = CveDiscoveryRun.objects.get(pk=first)
        execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(return_value=page([record()], size=500)),
        )
        second = self.start().data["run_id"]
        new_run = CveDiscoveryRun.objects.get(pk=second)
        execute_cve_discovery_run(
            new_run, Mock(), fetcher=Mock(return_value=page([record()], size=500)),
        )
        old = self.findings(first)
        current = self.findings(second)
        self.assertEqual(old.data["scope"], "LATEST_MATERIALIZED_FINDINGS_FOR_RUN")
        self.assertEqual(old.data["count"], 0)
        self.assertEqual(current.data["count"], 1)
        self.assertEqual(AssetCveFinding.objects.count(), 1)

    def test_no_nvd_calls_when_reading_existing_run(self):
        rid = self.start().data["run_id"]
        with patch(
            "vulnerabilities.services.nvd_cve_client.urlopen"
        ) as remote:
            self.detail(rid)
            self.findings(rid)
            self.client.get(self.URL)
        remote.assert_not_called()
