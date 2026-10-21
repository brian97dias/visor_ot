"""Phase 1 of shared NVD catalogue: page recovery without live NVD access."""
from datetime import timedelta
import io
import json
from unittest.mock import Mock, patch
from io import StringIO
from uuid import uuid5, NAMESPACE_DNS

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from vulnerabilities.models import (
    Cpe, CpeQueryCache, CpeQueryProduct, CpeQuerySnapshot,
    CpeSearchRun, AssetCpe, AssetCpeDecision,
)
from vulnerabilities.services.cpe_catalogue import (
    CACHE_TTL, canonical_key, canonical_query, enqueue_catalogue_query,
    execute_catalogue_snapshot, recover_interrupted_catalogue_snapshots,
    retry_failed_snapshot,
)
from assets.services import register_hardware_asset
from django.contrib.auth import get_user_model


def product(index, *, kind="h", vendor="phoenix_contact", cpe_id=None):
    return {"cpe": {
        "cpeNameId": str(cpe_id or uuid5(NAMESPACE_DNS, f"visorot-{kind}-{index}")),
        "cpeName": f"cpe:2.3:{kind}:{vendor}:product_{index}:-:*:*:*:*:*:*:*",
        "deprecated": False,
        "titles": [{"title": f"Product {index}", "lang": "en"}],
        "created": "2020-01-01T00:00:00.000",
        "lastModified": "2025-01-01T00:00:00.000",
        "refs": [
            {"ref": "https://www.phoenixcontact.com/product", "type": "Product"},
        ],
    }}


def feed(rows, *, total_override=None, after=0):
    """Simulate the full NVD CPE endpoint including pagination."""
    def fetch(strategy, parameter, start_index, pacer, *, results_per_page):
        assert strategy in ("keywordSearch", "cpeMatchString")
        assert results_per_page > 0
        return {
            "products": rows[start_index:start_index + results_per_page],
            "totalResults": len(rows) if total_override is None else total_override,
            "startIndex": start_index,
            "timestamp": "2026-10-20T10:10:10.000",
        }
    return fetch


class CatalogueQueryValidationTests(SimpleTestCase):
    def test_equivalent_parameter_names_share_cache_key(self):
        s1, p1 = canonical_query("keywordSearch", "  Phoenix   Contact  ")
        s2, p2 = canonical_query("keywordSearch", "Phoenix Contact")
        self.assertEqual(canonical_key(s1, p1), canonical_key(s2, p2))
        self.assertNotEqual(
            canonical_key("keywordSearch", "Phoenix Contact"),
            canonical_key("cpeMatchString", "cpe:2.3:h:phoenix_contact"),
        )

    def test_query_does_not_allow_nvd_urls_or_unbounded_parameters(self):
        invalid = [
            ("keywordSearch", "http://nvd.nist.gov"),
            ("keywordSearch", "x"),
            ("keywordSearch", "Rockwell\nOther"),
            ("keywordSearch", "X" * 121),
            ("cpeMatchString", "cpe:2.3:x:rockwell:factorytalk"),
            ("cpeMatchString", "cpe:2.3:h:"),
            ("cpeMatchString", "cpe:2.3:h:rockwell:*:*:*:*:*:*:*"),
        ]
        for strategy, parameter in invalid:
            with self.subTest(parameter=parameter), self.assertRaises(ValueError):
                canonical_query(strategy, parameter)



class NvdClientCataloguePagingTests(SimpleTestCase):
    def test_fetch_page_accepts_larger_page_size_without_changing_legacy_default(self):
        from vulnerabilities.services.nvd_client import fetch_page
        data = {"products": [], "totalResults": 0, "startIndex": 500}
        with patch("vulnerabilities.services.nvd_client.urlopen",
                   return_value=io.BytesIO(json.dumps(data).encode("utf-8"))) as opener:
            response = fetch_page(
                "keywordSearch", "Phoenix Contact", 500, Mock(),
                results_per_page=500,
            )
        self.assertEqual(response["products"], [])
        url = opener.call_args.args[0].full_url
        self.assertIn("resultsPerPage=500", url)
        self.assertIn("startIndex=500", url)


class CatalogueCacheTests(TestCase):
    def test_page_size_bounds_are_explicit(self):
        for size in (0, -1, 1001, "500", True):
            with self.subTest(size=size), self.assertRaises(ValueError):
                enqueue_catalogue_query("keywordSearch", "Siemens", page_size=size)
        self.assertFalse(CpeQuerySnapshot.objects.exists())
    def test_reuses_completed_cache_and_force_produces_new_snapshot(self):
        now = timezone.now()
        first, reused = enqueue_catalogue_query(
            "keywordSearch", "Phoenix Contact", page_size=500, now=now,
        )
        self.assertFalse(reused)
        same, reused = enqueue_catalogue_query(
            "keywordSearch", "Phoenix   Contact", now=now,
        )
        self.assertTrue(reused)
        self.assertEqual(same.pk, first.pk)
        first.status = "COMPLETED"
        first.finished_at = now
        first.save(update_fields=["status", "finished_at"])
        fresh, reused = enqueue_catalogue_query("keywordSearch", "Phoenix Contact", now=now)
        self.assertTrue(reused)
        self.assertEqual(fresh.pk, first.pk)
        forced, reused = enqueue_catalogue_query(
            "keywordSearch", "Phoenix Contact", force=True, now=now,
        )
        self.assertFalse(reused)
        self.assertNotEqual(forced.pk, first.pk)
        self.assertEqual(CpeQueryCache.objects.count(), 1)

    def test_expired_cache_gets_new_snapshot_without_deleting_history(self):
        old_time = timezone.now() - CACHE_TTL - timedelta(seconds=1)
        old, _ = enqueue_catalogue_query("keywordSearch", "Siemens")
        old.status = "COMPLETED"
        old.finished_at = old_time
        old.save(update_fields=["status", "finished_at"])
        new, reused = enqueue_catalogue_query("keywordSearch", "Siemens")
        self.assertFalse(reused)
        self.assertNotEqual(new.pk, old.pk)
        self.assertEqual(old.status, "COMPLETED")
        self.assertEqual(CpeQuerySnapshot.objects.count(), 2)

    def test_cli_enqueues_without_running_nvd_requests(self):
        out = StringIO()
        call_command(
            "enqueue_cpe_catalogue", strategy="keywordSearch",
            parameter="Rockwell", stdout=out,
        )
        self.assertEqual(CpeQuerySnapshot.objects.count(), 1)
        self.assertIn("Snapshot #", out.getvalue())
        self.assertEqual(CpeQuerySnapshot.objects.get().status, "QUEUED")


class CatalogueRecoveryTests(TestCase):
    def make(self, *, name="cpe:2.3:h:phoenix_contact", size=500):
        snapshot, _ = enqueue_catalogue_query(
            "cpeMatchString", name, page_size=size,
        )
        return snapshot

    def test_1902_products_all_pages_stored_without_candidate_filtering(self):
        records = [
            product(i, kind=("o" if i % 5 == 0 else "h")) for i in range(1902)
        ]
        snapshot = execute_catalogue_snapshot(
            self.make(), object(), fetcher=feed(records),
        )
        self.assertEqual(snapshot.status, "COMPLETED")
        self.assertEqual(snapshot.expected_total, 1902)
        self.assertEqual(snapshot.retrieved_count, 1902)
        self.assertEqual(snapshot.next_start_index, 1902)
        self.assertEqual(snapshot.pages_fetched, 4)
        self.assertEqual(snapshot.unique_products_count, 1902)
        self.assertEqual(CpeQueryProduct.objects.filter(snapshot=snapshot).count(), 1902)
        self.assertEqual(Cpe.objects.count(), 1902)
        self.assertTrue(Cpe.objects.filter(cpe_name__startswith="cpe:2.3:o:").exists())
        evidence = snapshot.products.select_related("cpe").first()
        self.assertEqual(evidence.nvd_record["cpe"]["cpeNameId"], str(evidence.cpe.cpe_name_id))

    def test_keyboard_interrupt_resumes_at_committed_checkpoint(self):
        records = [product(i) for i in range(1202)]
        snapshot = self.make()
        pages = []
        def fetch(*args, **kwargs):
            pages.append(args[2])
            return feed(records)(*args, **kwargs)
        def halt(progress):
            if progress.pages_fetched == 2:
                raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            execute_catalogue_snapshot(
                snapshot, object(), fetcher=fetch, after_page=halt,
            )
        snapshot.refresh_from_db()
        self.assertEqual(snapshot.status, "RUNNING")
        self.assertEqual(snapshot.next_start_index, 1000)
        self.assertEqual(snapshot.unique_products_count, 1000)
        self.assertEqual(recover_interrupted_catalogue_snapshots(), 1)
        snapshot.refresh_from_db()
        self.assertEqual(snapshot.status, "INCOMPLETE")
        completed = execute_catalogue_snapshot(snapshot, object(), fetcher=fetch)
        self.assertEqual(completed.status, "COMPLETED")
        self.assertEqual(completed.unique_products_count, 1202)
        self.assertEqual(pages, [0, 500, 1000])
        self.assertEqual(CpeQueryProduct.objects.filter(snapshot=snapshot).count(), 1202)

    def test_fetch_failure_preserves_checkpoint_and_supports_explicit_retry(self):
        records = [product(i) for i in range(900)]
        snapshot = self.make()
        def network_failure(*args, **kwargs):
            if args[2] >= 500:
                raise TimeoutError("simulated NVD timeout")
            return feed(records)(*args, **kwargs)
        failed = execute_catalogue_snapshot(snapshot, object(), fetcher=network_failure)
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.error_code, "FETCH_FAILED")
        self.assertEqual(failed.next_start_index, 500)
        self.assertEqual(failed.products.count(), 500)
        retry_failed_snapshot(failed.pk)
        failed.refresh_from_db()
        self.assertEqual(failed.status, "INCOMPLETE")
        seen = []
        def resume(*args, **kwargs):
            seen.append(args[2])
            return feed(records)(*args, **kwargs)
        done = execute_catalogue_snapshot(failed, object(), fetcher=resume)
        self.assertEqual(seen, [500])
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(done.products.count(), 900)

    def test_total_changed_never_declares_exhaustive_and_cannot_resume(self):
        records = [product(i) for i in range(900)]
        snapshot = self.make()
        def inconsistent(*args, **kwargs):
            data = feed(records)(*args, **kwargs)
            if args[2] >= 500:
                data["totalResults"] = 901
            return data
        failed = execute_catalogue_snapshot(snapshot, object(), fetcher=inconsistent)
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.error_code, "NVD_TOTAL_CHANGED")
        self.assertEqual(failed.next_start_index, 500)
        self.assertEqual(failed.products.count(), 500)
        with self.assertRaises(ValueError):
            retry_failed_snapshot(failed.pk)
        self.assertEqual(CpeQueryProduct.objects.count(), 500)

    def test_duplicate_uuid_across_pages_never_claims_completeness(self):
        records = [product(i) for i in range(500)] * 2
        failed = execute_catalogue_snapshot(
            self.make(), object(), fetcher=feed(records),
        )
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.error_code, "INCOMPLETE_SET")
        self.assertEqual(failed.retrieved_count, 1000)
        self.assertEqual(failed.unique_products_count, 500)
        self.assertEqual(Cpe.objects.count(), 500)

    def test_valid_empty_result_can_complete_without_products(self):
        snapshot = self.make()
        done = execute_catalogue_snapshot(
            snapshot, object(), fetcher=feed([]),
        )
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(done.expected_total, 0)
        self.assertEqual(done.unique_products_count, 0)
        self.assertEqual(done.pages_fetched, 1)
        self.assertFalse(CpeQueryProduct.objects.exists())

    def test_empty_page_before_total_does_not_mark_complete(self):
        snapshot = self.make()
        def invalid(*args, **kwargs):
            return {"products": [], "startIndex": 0, "totalResults": 900}
        result = execute_catalogue_snapshot(snapshot, object(), fetcher=invalid)
        self.assertEqual(result.status, "FAILED")
        self.assertEqual(result.error_code, "EMPTY_PAGE")
        self.assertEqual(result.next_start_index, 0)
        self.assertFalse(CpeQueryProduct.objects.exists())

    def test_invalid_record_rolls_back_entire_page_and_checkpoint(self):
        snapshot = self.make()
        bad = product(2)
        bad["cpe"]["cpeNameId"] = "not-a-uuid"
        result = execute_catalogue_snapshot(
            snapshot, object(), fetcher=feed([product(1), bad]),
        )
        self.assertEqual(result.status, "FAILED")
        self.assertEqual(result.error_code, "INVALID_PRODUCT")
        self.assertEqual(result.next_start_index, 0)
        self.assertFalse(Cpe.objects.exists())

    def test_same_uuid_in_two_queries_creates_one_cpe_two_evidences(self):
        record = product(20)
        one = self.make()
        two, _ = enqueue_catalogue_query("keywordSearch", "Phoenix Contact")
        done1 = execute_catalogue_snapshot(one, object(), fetcher=feed([record]))
        done2 = execute_catalogue_snapshot(two, object(), fetcher=feed([record]))
        self.assertEqual(done1.status, "COMPLETED")
        self.assertEqual(done2.status, "COMPLETED")
        self.assertEqual(Cpe.objects.count(), 1)
        self.assertEqual(CpeQueryProduct.objects.count(), 2)
        self.assertNotEqual(done1.pk, done2.pk)

    def test_new_snapshot_preserves_previous_source_and_human_decisions(self):
        User = get_user_model()
        analyst = User.objects.create_user(username="catalogue-analyst", role=User.Role.ANALYST)
        operator = User.objects.create_user(username="catalogue-operator", role=User.Role.OPERATOR)
        asset = register_hardware_asset(
            data={
                "name": "PLC Siemens", "asset_type": "HARDWARE",
                "hardware": {
                    "manufacturer": "Siemens", "model": "SIMATIC S7-1200",
                    "cpu_model": "1215C", "role": "PLC",
                },
            }, user=operator,
        )
        run = CpeSearchRun.objects.create(
            asset=asset, requested_by=analyst, identity_fingerprint="legacy",
        )
        record = product(5, vendor="siemens")
        cpe = Cpe.objects.create(
            cpe_name_id=record["cpe"]["cpeNameId"],
            cpe_name=record["cpe"]["cpeName"], title="Siemens older title",
            nvd_references=[{"url": "https://www.siemens.com/product", "type": "Product", "source": "NVD"}],
            references_source_run=run,
        )
        associated = AssetCpe.objects.create(
            asset=asset, cpe=cpe, source_run=run,
            validation_status=AssetCpe.Validation.CONFIRMED,
            validated_by=analyst, validated_at=timezone.now(),
            validated_identity_fingerprint="legacy",
        )
        AssetCpeDecision.objects.create(
            association=associated, new_status=AssetCpe.Validation.CONFIRMED,
            source_run=run, identity_fingerprint="legacy", actor=analyst,
        )
        snapshot, _ = enqueue_catalogue_query("keywordSearch", "Siemens")
        execute_catalogue_snapshot(snapshot, object(), fetcher=feed([record]))
        cpe.refresh_from_db()
        self.assertEqual(cpe.references_source_run_id, run.pk)
        self.assertEqual(cpe.nvd_references[0]["url"], "https://www.siemens.com/product")
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        self.assertEqual(AssetCpe.objects.get().validation_status, "CONFIRMED")
        self.assertEqual(CpeQueryProduct.objects.count(), 1)
