"""End-to-end CPE recovery regressions, with all network responses mocked."""
from datetime import timedelta
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from assets.models import Asset, Software
from users.models import User
from vulnerabilities.models import (
    CpeQueryCache, CpeQuerySnapshot, CpeSearchRun,
)
from vulnerabilities.services.cpe_catalogue import (
    MAX_AUTOMATIC_RETRIES, enqueue_catalogue_query,
    execute_catalogue_snapshot, retry_failed_snapshot,
    snapshot_retry_scheduled,
)
from vulnerabilities.services.cpe_search import (
    execute_run, retry_failed_cpe_search, serialize_run,
)
from vulnerabilities.services.identity import fingerprint, software_identity
from vulnerabilities.management.commands.run_cpe_worker import (
    next_ready_catalogue_snapshot, next_runnable_cpe_run,
)


class CpeTransientRecoveryTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="cpe-recovery-analyst", role=User.Role.ANALYST
        )
        self.asset = Asset.objects.create(
            name="FW-PHX-ILPN-1.13", asset_type=Asset.AssetType.SOFTWARE,
            created_by=self.user, updated_by=self.user,
        )
        self.software = Software.objects.create(
            asset=self.asset, software_type=Software.SoftwareType.FIRMWARE,
            manufacturer="Phoenix Contact", product="IL PN BK-PAC Firmware",
            version="1.13",
        )
        identity = software_identity(self.asset)
        self.run = CpeSearchRun.objects.create(
            asset=self.asset, requested_by=self.user,
            identity_snapshot=identity, identity_fingerprint=fingerprint(identity),
        )

    @staticmethod
    def no_products(*args, **kwargs):
        return {"products": [], "totalResults": 0, "startIndex": args[2]}

    @staticmethod
    def timeout(*args, **kwargs):
        raise TimeoutError("NVD temporalmente no respondió")

    def _waiting_snapshot(self):
        result = execute_run(self.run, object(), fetcher=self.no_products)
        self.assertEqual(result.status, CpeSearchRun.Status.QUEUED)
        last = result.queries[-1]
        self.assertEqual(last["status"], "WAITING_CATALOGUE")
        self.assertEqual(last["version_scope"], "BRANCH_PREFIX")
        return CpeQuerySnapshot.objects.get(pk=last["snapshot_id"])

    def test_phoenix_timeout_waits_and_resumes_from_checkpoint_without_repeating_queries(self):
        snapshot = self._waiting_snapshot()
        original_count = len(self.run.queries)
        self.assertGreater(original_count, 1)
        failed = execute_catalogue_snapshot(
            snapshot, object(), fetcher=self.timeout
        )
        self.assertEqual(failed.status, CpeQuerySnapshot.Status.FAILED)
        self.assertEqual(failed.error_code, "FETCH_FAILED")
        self.assertEqual(failed.next_start_index, 0)
        self.assertEqual(failed.automatic_retry_count, 1)
        self.assertTrue(snapshot_retry_scheduled(failed))
        self.assertGreater(failed.retry_after, timezone.now())

        # Old incomplete run must not get falsely finalized while backoff
        # is pending; later independent tasks remain schedulable.
        self.assertIsNone(next_runnable_cpe_run())
        self.assertIsNone(next_ready_catalogue_snapshot())
        self.assertEqual(
            execute_run(self.run, object(), fetcher=lambda *args, **kwargs:
                        self.fail("Repeated a completed specific CPE query")).status,
            CpeSearchRun.Status.QUEUED,
        )
        response = serialize_run(self.run)
        self.assertEqual(response["catalogue_retry"]["attempt"], 1)
        self.assertEqual(response["catalogue_retry"]["maximum"],
                         MAX_AUTOMATIC_RETRIES)
        self.assertEqual(len(self.run.queries), original_count)

        failed.retry_after = timezone.now() - timedelta(seconds=1)
        failed.save(update_fields=["retry_after"])
        due = next_ready_catalogue_snapshot()
        self.assertEqual(due.pk, snapshot.pk)
        retried = retry_failed_snapshot(due.pk)
        self.assertEqual(retried.status, CpeQuerySnapshot.Status.INCOMPLETE)
        self.assertEqual(retried.automatic_retry_count, 1)
        self.assertIsNone(retried.retry_after)
        completed = execute_catalogue_snapshot(
            retried, object(), fetcher=self.no_products
        )
        self.assertEqual(completed.status, CpeQuerySnapshot.Status.COMPLETED)
        self.assertEqual(completed.unique_products_count, 0)
        self.assertEqual(next_runnable_cpe_run().pk, self.run.pk)
        resumed = execute_run(
            self.run, object(),
            fetcher=lambda *args, **kwargs:
            self.fail("Previous completed query was requested again"),
        )
        self.assertEqual(resumed.queries[original_count - 1]["status"], "COMPLETED")
        self.assertEqual(resumed.queries[original_count - 1]["snapshot_id"],
                         snapshot.pk)
        self.assertTrue(all(
            q["status"] == "COMPLETED"
            for q in resumed.queries[:original_count]
        ))
        self.assertGreaterEqual(len(resumed.queries), original_count)
        self.assertEqual(self.run.candidates, [])

    def test_backoff_is_bounded_across_retries_and_final_failure_is_terminal(self):
        snapshot = self._waiting_snapshot()
        intervals = []
        for attempt in range(1, MAX_AUTOMATIC_RETRIES + 2):
            failed = execute_catalogue_snapshot(
                snapshot, object(), fetcher=self.timeout
            )
            self.assertEqual(failed.status, CpeQuerySnapshot.Status.FAILED)
            if attempt <= MAX_AUTOMATIC_RETRIES:
                self.assertTrue(snapshot_retry_scheduled(failed))
                self.assertEqual(failed.automatic_retry_count, attempt)
                intervals.append(
                    (failed.retry_after - failed.finished_at).total_seconds()
                )
                snapshot = retry_failed_snapshot(failed.pk)
            else:
                self.assertFalse(snapshot_retry_scheduled(failed))
                self.assertEqual(failed.automatic_retry_count,
                                 MAX_AUTOMATIC_RETRIES)
                self.assertIsNone(failed.retry_after)
        for observed, target in zip(intervals, (30, 60, 120)):
            self.assertAlmostEqual(observed, target, delta=2)
        failed_run = execute_run(
            self.run, object(),
            fetcher=lambda *args, **kwargs:
            self.fail("Must not repeat network calls on terminal failure"),
        )
        self.assertEqual(failed_run.status, CpeSearchRun.Status.FAILED)
        self.assertIn("No se completó", failed_run.error_message)

    def test_invalid_catalogue_response_does_not_schedule_retry(self):
        snapshot = self._waiting_snapshot()
        failed = execute_catalogue_snapshot(
            snapshot, object(), fetcher=lambda *args, **kwargs: {
                "products": [], "totalResults": 4, "startIndex": 0
            },
        )
        self.assertEqual(failed.status, CpeQuerySnapshot.Status.FAILED)
        self.assertEqual(failed.error_code, "EMPTY_PAGE")
        self.assertIsNone(failed.retry_after)
        self.assertEqual(failed.automatic_retry_count, 0)

    def test_automatic_retry_preserves_partially_downloaded_catalogue_pages(self):
        from vulnerabilities.tests_catalogue import product, feed
        records = [product(i, kind="o") for i in range(550)]
        snapshot, reused = enqueue_catalogue_query(
            "cpeMatchString", "cpe:2.3:o:phoenixcontact:il_pn*",
            page_size=500,
        )
        self.assertFalse(reused)

        def first_fetch(*args, **kwargs):
            if args[2] == 500:
                raise TimeoutError("Falla transitoria al descargar página dos")
            return feed(records)(*args, **kwargs)

        failed = execute_catalogue_snapshot(
            snapshot, object(), fetcher=first_fetch
        )
        self.assertEqual(failed.next_start_index, 500)
        self.assertEqual(failed.products.count(), 500)
        self.assertTrue(snapshot_retry_scheduled(failed))
        recovered = retry_failed_snapshot(snapshot.pk)
        requested = []

        def remaining_only(*args, **kwargs):
            requested.append(args[2])
            return feed(records)(*args, **kwargs)

        done = execute_catalogue_snapshot(
            recovered, object(), fetcher=remaining_only
        )
        self.assertEqual(requested, [500])
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(done.products.count(), 550)
        self.assertEqual(done.automatic_retry_count, 1)

    def test_http_400_and_invalid_page_are_never_automatically_retried(self):
        from vulnerabilities.services.nvd_client import NvdError
        first = self._waiting_snapshot()

        def bad_request(*args, **kwargs):
            raise NvdError("NVD devolvió HTTP 400.")

        failed = execute_catalogue_snapshot(
            first, object(), fetcher=bad_request
        )
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.error_code, "FETCH_FAILED")
        self.assertIsNone(failed.retry_after)
        self.assertEqual(failed.automatic_retry_count, 0)

    def test_another_asset_run_is_not_starved_by_delayed_snapshot(self):
        snapshot = self._waiting_snapshot()
        execute_catalogue_snapshot(snapshot, object(), fetcher=self.timeout)
        other = CpeSearchRun.objects.create(
            asset=self.asset, requested_by=self.user,
            identity_snapshot=self.run.identity_snapshot,
            identity_fingerprint=self.run.identity_fingerprint,
        )
        self.assertEqual(next_runnable_cpe_run().pk, other.pk)

    def test_explicit_legacy_recovery_requeues_same_work_without_erasing_history(self):
        snapshot = self._waiting_snapshot()
        execute_catalogue_snapshot(snapshot, object(), fetcher=self.timeout)
        # Simulate the pre-recovery code: it marked the entire asset search
        # FAILED after encountering a failed snapshot.
        previous_queries = list(self.run.queries)
        last = dict(previous_queries[-1])
        last["status"] = "FAILED"
        last["stop_reason"] = "FETCH_FAILED"
        previous_queries[-1] = last
        self.run.status = CpeSearchRun.Status.FAILED
        self.run.error_message = "No se completó la recuperación: TimeoutError."
        self.run.queries = previous_queries
        self.run.result_truncated = True
        self.run.save(update_fields=[
            "status", "error_message", "queries", "result_truncated"
        ])
        snapshot.retry_after = None  # old worker had no auto-retry schedule
        snapshot.save(update_fields=["retry_after"])

        out = StringIO()
        call_command("retry_failed_cpe_search", str(self.run.pk), stdout=out)
        self.assertIn("VISTA PREVIA", out.getvalue())
        self.run.refresh_from_db()
        self.assertEqual(self.run.status, "FAILED")
        call_command(
            "retry_failed_cpe_search", str(self.run.pk), "--execute",
            stdout=StringIO(),
        )
        self.run.refresh_from_db()
        snapshot.refresh_from_db()
        self.assertEqual(self.run.status, "QUEUED")
        self.assertEqual(self.run.queries[-1]["status"], "WAITING_CATALOGUE")
        self.assertEqual(self.run.queries[:-1], previous_queries[:-1])
        self.assertEqual(snapshot.status, "INCOMPLETE")
        self.assertEqual(snapshot.automatic_retry_count, 0)
        self.assertIsNone(snapshot.retry_after)
        self.assertFalse(self.run.result_truncated)

    def test_old_run_recovery_is_refused_if_asset_identity_changed(self):
        snapshot = self._waiting_snapshot()
        execute_catalogue_snapshot(snapshot, object(), fetcher=self.timeout)
        self.run.status = CpeSearchRun.Status.FAILED
        self.run.queries[-1]["status"] = "FAILED"
        self.run.save(update_fields=["status", "queries"])
        self.software.version = "2.0"
        self.software.save(update_fields=["version"])
        with self.assertRaises(ValidationError):
            retry_failed_cpe_search(self.run.pk)
        self.run.refresh_from_db()
        snapshot.refresh_from_db()
        self.assertEqual(self.run.status, "FAILED")
        self.assertEqual(snapshot.status, "FAILED")
