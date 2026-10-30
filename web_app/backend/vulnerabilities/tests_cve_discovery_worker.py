"""CVE discovery worker regressions. NVD replies are always mocked."""
from datetime import timedelta
from unittest.mock import Mock

from django.test import TestCase
from django.utils import timezone

from assets.models import Asset
from vulnerabilities.models import (
    AssetCpe, AssetCveAssessment, AssetCveFinding, CpeSearchRun,
    Cve, CveDiscoveryRun,
)
from vulnerabilities.management.commands.run_cpe_worker import oldest_work_kind
from vulnerabilities.services.cve_discovery_worker import (
    enqueue_cve_discovery, execute_cve_discovery_run,
    recover_interrupted_cve_discoveries,
)
from vulnerabilities.services.nvd_client import NvdError
from vulnerabilities.tests_cve_discovery_plan import (
    CveDiscoveryPlanTests, HW_CPE, SW_CPE,
)
from vulnerabilities.tests_cve_discovery_api import record, page


class CveDiscoveryWorkerTests(TestCase):
    def setUp(self):
        self.fixtures = CveDiscoveryPlanTests(
            methodName="test_hardware_only_cpe_is_eligible_without_firmware_cpe"
        )
        self.fixtures.setUp()
        self.user = self.fixtures.user
        self.hardware = self.fixtures.hardware
        self.firmware = self.fixtures.firmware
        self.fixtures.confirm(self.hardware.asset, HW_CPE)

    def enqueue(self, *, size=2):
        return enqueue_cve_discovery(
            [self.hardware.pk], self.user, page_size=size,
        )

    def test_enqueue_reuses_same_active_plan_and_does_not_assess(self):
        first, reused = self.enqueue()
        second, again = self.enqueue()
        self.assertFalse(reused)
        self.assertTrue(again)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(first.queries[0]["cpe_name"], HW_CPE)
        self.assertEqual(first.queries[0]["page_size"], 2)
        self.assertEqual(CveDiscoveryRun.objects.count(), 1)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_no_eligible_hardware_creates_no_run(self):
        association = AssetCpe.objects.get(asset_id=self.hardware.pk)
        association.validation_status = AssetCpe.Validation.REOPENED
        association.save(update_fields=["validation_status"])
        with self.assertRaises(ValueError):
            self.enqueue()
        self.assertEqual(CveDiscoveryRun.objects.count(), 0)

    def test_paginated_results_store_unique_cve_findings_and_checkpoints(self):
        run, _ = self.enqueue()
        first = page([record("CVE-2024-65432"), record("CVE-2024-65433")],
                     total=3, size=2)
        second = page([record("CVE-2024-65434")], total=3, start=2, size=2)
        fetched = Mock(side_effect=[first, second])
        checkpoints = []
        done = execute_cve_discovery_run(
            run, Mock(), fetcher=fetched,
            after_page=lambda r: checkpoints.append(
                (r.queries[0]["next_start_index"], r.queries[0]["status"])
            ),
        )
        self.assertEqual(done.status, CveDiscoveryRun.Status.COMPLETED)
        self.assertEqual(checkpoints, [(2, "RUNNING"), (3, "COMPLETED")])
        self.assertEqual([call.args[1] for call in fetched.call_args_list], [0, 2])
        self.assertEqual(Cve.objects.count(), 3)
        self.assertEqual(AssetCveFinding.objects.count(), 3)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_worker_logs_a_proven_firmware_match_once_on_repeated_discovery(self):
        from vulnerabilities.tests_cve_general_assessment import nvd_and
        self.fixtures.link()
        self.fixtures.confirm(self.firmware.asset, SW_CPE)
        job, _ = self.enqueue()
        row = record("CVE-2024-65432")
        row["configurations"] = [nvd_and(HW_CPE, SW_CPE)]
        fetched = Mock(return_value=page([row], size=2))
        done = execute_cve_discovery_run(job, Mock(), fetcher=fetched)
        self.assertEqual(done.status, CveDiscoveryRun.Status.COMPLETED)
        audits = AssetCveAssessment.objects.all()
        self.assertEqual(audits.count(), 1)
        self.assertEqual(audits[0].status, "APPLIES")
        self.assertEqual(audits[0].criteria_evidence["origin"], "SYSTEM")
        self.assertIsNone(audits[0].decided_by)
        # Re-evaluating the same stored CVE cannot duplicate a current audit.
        from vulnerabilities.services.cve_system_audit import ensure_system_cve_assessment
        _, created = ensure_system_cve_assessment(row["id"], self.hardware.pk)
        self.assertFalse(created)
        self.assertEqual(AssetCveAssessment.objects.count(), 1)

    def test_shared_cpe_queries_once_and_finds_two_hardware(self):
        other = self.fixtures.make_hardware("Controller 2")
        previous = AssetCpe.objects.get(asset_id=self.hardware.pk)
        source_identity = previous.source_run.identity_snapshot
        run = CpeSearchRun.objects.create(
            asset=other.asset, requested_by=self.user,
            status=CpeSearchRun.Status.COMPLETED,
            identity_snapshot=source_identity,
            identity_fingerprint=previous.validated_identity_fingerprint,
        )
        AssetCpe.objects.create(
            asset=other.asset, cpe=previous.cpe, source_run=run,
            validation_status=AssetCpe.Validation.CONFIRMED,
            validated_identity_fingerprint=previous.validated_identity_fingerprint,
            validated_at=timezone.now(), validated_by=self.user,
        )
        job, _ = enqueue_cve_discovery(
            [self.hardware.pk, other.pk], self.user, page_size=2,
        )
        self.assertEqual(len(job.queries), 1)
        fetched = Mock(return_value=page([record()], size=2))
        done = execute_cve_discovery_run(job, Mock(), fetcher=fetched)
        self.assertEqual(done.status, CveDiscoveryRun.Status.COMPLETED)
        fetched.assert_called_once()
        self.assertEqual(AssetCveFinding.objects.count(), 2)

    def test_firmware_cpe_is_not_a_worker_query_or_finding_source(self):
        self.fixtures.link()
        self.fixtures.confirm(self.firmware.asset, SW_CPE)
        run, _ = self.enqueue()
        self.assertEqual(len(run.queries), 1)
        self.assertEqual(run.queries[0]["cpe_name"], HW_CPE)
        self.assertTrue(all(
            source["origin"] == "HARDWARE"
            for source in run.queries[0]["sources"]
        ))
        fetcher = Mock(return_value=page([record()], size=2))
        done = execute_cve_discovery_run(run, Mock(), fetcher=fetcher)
        self.assertEqual(done.status, CveDiscoveryRun.Status.COMPLETED)
        self.assertEqual(fetcher.call_count, 1)
        finding = AssetCveFinding.objects.get()
        self.assertEqual(len(finding.sources), 1)
        self.assertEqual(finding.sources[0]["origin"], "HARDWARE")
        self.assertEqual(finding.first_discovery_run_id, run.pk)

    def test_legacy_queued_software_search_is_rejected_before_network(self):
        self.fixtures.link()
        self.fixtures.confirm(self.firmware.asset, SW_CPE)
        run, _ = self.enqueue()
        stale = list(run.queries)
        copy = dict(stale[0])
        copy["cpe_name"] = SW_CPE
        copy["sources"] = [{
            **stale[0]["sources"][0], "origin": "SOFTWARE",
            "cpe_name": SW_CPE,
        }]
        run.queries = stale + [copy]
        run.save(update_fields=["queries"])
        fetcher = Mock()
        failed = execute_cve_discovery_run(run, Mock(), fetcher=fetcher)
        fetcher.assert_not_called()
        self.assertEqual(failed.status, CveDiscoveryRun.Status.FAILED)
        self.assertEqual(failed.error_code, "STALE_EVIDENCE")
        self.assertEqual(AssetCveFinding.objects.count(), 0)

    def test_zero_results_is_complete_without_not_applicable_decision(self):
        run, _ = self.enqueue()
        done = execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(return_value=page([], size=2, total=0))
        )
        self.assertEqual(done.status, CveDiscoveryRun.Status.COMPLETED)
        self.assertEqual(done.queries[0]["retrieved_count"], 0)
        self.assertEqual(done.queries[0]["pages_fetched"], 1)
        self.assertEqual(AssetCveFinding.objects.count(), 0)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_crash_after_commit_recovers_and_resumes_from_saved_checkpoint(self):
        run, _ = self.enqueue()
        first = page([record()], total=2, size=2)
        second = page([record("CVE-2024-65433")], total=2, start=1, size=2)
        def crash(_):
            raise RuntimeError("Interrupted after page commit")
        with self.assertRaises(RuntimeError):
            execute_cve_discovery_run(
                run, Mock(), fetcher=Mock(return_value=first), after_page=crash,
            )
        run.refresh_from_db()
        self.assertEqual(run.status, CveDiscoveryRun.Status.RUNNING)
        self.assertEqual(run.queries[0]["next_start_index"], 1)
        self.assertEqual(AssetCveFinding.objects.count(), 1)
        self.assertEqual(recover_interrupted_cve_discoveries(), 1)
        run.refresh_from_db()
        self.assertEqual(run.status, CveDiscoveryRun.Status.INCOMPLETE)
        fetched = Mock(return_value=second)
        done = execute_cve_discovery_run(run, Mock(), fetcher=fetched)
        self.assertEqual(done.status, CveDiscoveryRun.Status.COMPLETED)
        self.assertEqual(fetched.call_args.args[1], 1)
        self.assertEqual(AssetCveFinding.objects.count(), 2)

    def test_fetch_error_is_failed_with_partial_checkpoint_not_empty(self):
        run, _ = self.enqueue()
        first = page([record()], total=2, size=2)
        failed = execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(side_effect=[first, NvdError("HTTP 503")])
        )
        self.assertEqual(failed.status, CveDiscoveryRun.Status.FAILED)
        self.assertEqual(failed.error_code, "FETCH_FAILED")
        self.assertEqual(failed.queries[0]["next_start_index"], 1)
        self.assertEqual(AssetCveFinding.objects.count(), 1)

    def test_dataset_drift_retains_prior_page_and_marks_failed(self):
        run, _ = self.enqueue()
        first = page([record()], total=2, size=2)
        changed = page([record("CVE-2024-65433")], total=3, start=1, size=2)
        failed = execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(side_effect=[first, changed])
        )
        self.assertEqual(failed.error_code, "NVD_TOTAL_CHANGED")
        self.assertEqual(failed.status, CveDiscoveryRun.Status.FAILED)
        self.assertEqual(failed.queries[0]["next_start_index"], 1)

    def test_invalid_cve_rolls_back_full_page(self):
        run, _ = self.enqueue()
        invalid = record("CVE-2024-65433")
        invalid.pop("published")
        failed = execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(return_value=page([record(), invalid], size=2))
        )
        self.assertEqual(failed.error_code, "INVALID_CVE")
        self.assertEqual(Cve.objects.count(), 0)
        self.assertEqual(AssetCveFinding.objects.count(), 0)
        self.assertEqual(failed.queries[0]["next_start_index"], 0)

    def test_duplicate_between_pages_fails_and_does_not_recount(self):
        run, _ = self.enqueue()
        first = page([record()], total=2, size=2)
        second = page([record()], total=2, size=2, start=1)
        failed = execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(side_effect=[first, second])
        )
        self.assertEqual(failed.status, CveDiscoveryRun.Status.FAILED)
        self.assertEqual(failed.error_code, "DUPLICATE_PAGE")
        self.assertEqual(AssetCveFinding.objects.count(), 1)

    def test_revoked_cpe_prevents_network_and_finding(self):
        run, _ = self.enqueue()
        assoc = AssetCpe.objects.get(asset_id=self.hardware.pk)
        assoc.validation_status = AssetCpe.Validation.REOPENED
        assoc.save(update_fields=["validation_status"])
        fetched = Mock()
        failed = execute_cve_discovery_run(run, Mock(), fetcher=fetched)
        fetched.assert_not_called()
        self.assertEqual(failed.error_code, "STALE_EVIDENCE")
        self.assertEqual(failed.status, CveDiscoveryRun.Status.FAILED)
        self.assertEqual(AssetCveFinding.objects.count(), 0)

    def test_inventory_changed_between_pages_stops_without_another_fetch(self):
        run, _ = self.enqueue()
        fetched = Mock(return_value=page([record()], total=2, size=2))
        def archive(_):
            self.hardware.asset.inventory_status = Asset.InventoryStatus.ARCHIVED
            self.hardware.asset.save(update_fields=["inventory_status"])
        failed = execute_cve_discovery_run(
            run, Mock(), fetcher=fetched, after_page=archive
        )
        self.assertEqual(failed.error_code, "STALE_EVIDENCE")
        self.assertEqual(fetched.call_count, 1)
        self.assertEqual(failed.queries[0]["next_start_index"], 1)

    def test_new_completed_run_keeps_original_first_discovery_id(self):
        first, _ = self.enqueue()
        done = execute_cve_discovery_run(
            first, Mock(), fetcher=Mock(return_value=page([record()], size=2))
        )
        second, reused = self.enqueue()
        self.assertFalse(reused)
        self.assertNotEqual(done.pk, second.pk)
        again = execute_cve_discovery_run(
            second, Mock(), fetcher=Mock(return_value=page([record()], size=2))
        )
        self.assertEqual(again.status, CveDiscoveryRun.Status.COMPLETED)
        finding = AssetCveFinding.objects.get()
        self.assertEqual(finding.first_discovery_run_id, first.pk)
        self.assertEqual(finding.last_discovery_run_id, second.pk)
        self.assertEqual(AssetCveFinding.objects.count(), 1)

    def test_scheduler_integrates_discovery_and_keeps_legacy_signature(self):
        now = timezone.now()
        asset = Mock(created_at=now, queries=[])
        discovery = Mock(created_at=now - timedelta(seconds=1))
        self.assertEqual(oldest_work_kind(asset, None, None, discovery), "CVE_DISCOVERY")
        self.assertEqual(oldest_work_kind(asset, None, None), "ASSET")
