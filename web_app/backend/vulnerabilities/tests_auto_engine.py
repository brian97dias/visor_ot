"""Increment 2: structured-only automatic NVD discovery and shared catalogue.

NVD always uses injected synthetic responses, never a live HTTP request.
"""
from uuid import NAMESPACE_DNS, uuid5
from types import SimpleNamespace
from datetime import timedelta
from django.utils import timezone
from vulnerabilities.management.commands.run_cpe_worker import asset_run_precedes_snapshot

from django.contrib.auth import get_user_model
from django.test import TestCase

from assets.services import register_hardware_asset
from vulnerabilities.models import (
    AssetCpe, AssetCpeDecision, CpeQuerySnapshot, CpeSearchRun,
)
from vulnerabilities.services.cpe_catalogue import execute_catalogue_snapshot
from vulnerabilities.services.cpe_search import execute_run
from vulnerabilities.services.identity import fingerprint, hardware_identity


def product(vendor, model, *, suffix="", deprecated=False):
    value = vendor + ":" + model + ":" + suffix
    return {"cpe": {
        "cpeNameId": str(uuid5(NAMESPACE_DNS, "new-cpe-auto-" + value)),
        "cpeName": f"cpe:2.3:h:{vendor}:{model}:-:*:*:*:*:*:*:*",
        "deprecated": deprecated,
        "titles": [{"lang": "en", "title": vendor + " " + model}],
        "refs": [{"ref": "https://www.example.com/product", "type": "Product"}],
    }}


def reply(records, *, start=0, total=None):
    return {
        "products": records,
        "totalResults": len(records) if total is None else total,
        "startIndex": start,
    }


class StructuredAutomaticDiscoveryTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.actor = User.objects.create_user(
            username="auto-query-analyst", role=User.Role.ANALYST
        )

    def hardware(self, vendor, model, cpu=""):
        return register_hardware_asset(
            data={
                "name": vendor + " " + model,
                "asset_type": "HARDWARE",
                "hardware": {
                    "manufacturer": vendor, "model": model,
                    "cpu_model": cpu, "role": "PLC",
                },
            },
            user=self.actor,
        )

    def make_run(self, asset):
        identity = hardware_identity(asset)
        return CpeSearchRun.objects.create(
            asset=asset, requested_by=self.actor, scope="SPECIFIC",
            identity_snapshot=identity, identity_fingerprint=fingerprint(identity),
        )

    def test_siemens_specific_match_stops_before_general_and_uses_only_cpe(self):
        run = self.make_run(self.hardware("Siemens", "SIMATIC S7-1200", "1215C"))
        official = product("siemens", "simatic_s7-1200_cpu_1215c")
        seen = []
        def fetch(strategy, parameter, start, pacer):
            seen.append((strategy, parameter, start))
            return reply([official] if parameter.endswith("simatic_s7-1200_cpu_1215c*") else [])
        out = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(out.status, "COMPLETED")
        self.assertFalse(out.result_truncated)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], "cpeMatchString")
        self.assertEqual(out.candidates[0]["match_level"], "SPECIFIC")
        self.assertEqual(out.candidates[0]["methods"], ["cpeMatchString"])
        self.assertEqual(len(out.queries), 1)
        self.assertEqual(out.queries[0]["level_result"], "SUFFICIENT_PERTINENT_CANDIDATES")
        self.assertFalse(CpeQuerySnapshot.objects.exists())
        self.assertFalse(AssetCpe.objects.exists())

    def test_advantech_expands_to_adam_then_queues_complete_catalogue(self):
        run = self.make_run(self.hardware("Advantech", "ADAM-5000 Series"))
        related = [
            product("advantech", "adam-3600"),
            product("advantech", "adam-5630"),
            product("advantech", "adam-5550"),
        ]
        calls = []
        def fetch(strategy, parameter, start, pacer):
            calls.append((strategy, parameter, start))
            return reply(related if parameter.endswith("advantech:adam*") else [])
        initial = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(initial.status, "QUEUED")
        self.assertEqual(initial.queries[-1]["status"], "WAITING_CATALOGUE")
        self.assertEqual(initial.queries[-1]["level"], "MANUFACTURER")
        snapshot = CpeQuerySnapshot.objects.get()
        self.assertEqual(snapshot.status, "QUEUED")
        self.assertEqual(snapshot.cache.parameter, "cpe:2.3:h:advantech:*")
        self.assertEqual({x["match_level"] for x in initial.candidates}, {"RELATED"})
        self.assertEqual(len(initial.candidates), 3)
        self.assertFalse(AssetCpeDecision.objects.exists())
        before = list(calls)

        def catalog_fetch(strategy, parameter, start, pacer, *, results_per_page):
            return reply(related, start=start)
        snapshot = execute_catalogue_snapshot(snapshot, object(), fetcher=catalog_fetch)
        self.assertEqual(snapshot.status, "COMPLETED")
        finished = execute_run(initial, object(), fetcher=fetch)
        self.assertEqual(finished.status, "COMPLETED")
        self.assertFalse(finished.result_truncated)
        self.assertEqual(calls, before, "No deben repetirse las consultas específicas.")
        self.assertEqual(len(finished.candidates), 3)
        self.assertEqual(finished.queries[-1]["snapshot_id"], snapshot.pk)
        self.assertTrue(finished.queries[-1]["catalogue_complete"])
        self.assertEqual(snapshot.unique_products_count, 3)
        self.assertFalse(AssetCpe.objects.exists())
        self.assertFalse(AssetCpeDecision.objects.exists())

    def test_reuses_manufacturer_snapshot_between_different_assets(self):
        first = self.make_run(self.hardware("Advantech", "ADAM-5000 Series"))
        second = self.make_run(self.hardware("Advantech", "ADAM-5000 Series"))
        fetch = lambda strategy, parameter, start, pacer: reply([])
        first = execute_run(first, object(), fetcher=fetch)
        self.assertEqual(first.status, "QUEUED")
        snapshot = CpeQuerySnapshot.objects.get()
        snap_result = execute_catalogue_snapshot(
            snapshot, object(),
            fetcher=lambda strategy, parameter, start, pacer, *, results_per_page:
            reply([product("advantech", "adam-5550")], start=start)
        )
        self.assertEqual(snap_result.status, "COMPLETED")
        first = execute_run(first, object(), fetcher=fetch)
        second = execute_run(second, object(), fetcher=fetch)
        self.assertEqual(first.status, "COMPLETED")
        self.assertEqual(second.status, "COMPLETED")
        self.assertEqual(CpeQuerySnapshot.objects.count(), 1)
        self.assertEqual(second.queries[-1]["snapshot_id"], snapshot.pk)
        self.assertTrue(second.queries[-1]["cache_reused"])

    def test_partial_specific_page_never_proves_absence_or_falls_back(self):
        run = self.make_run(self.hardware("Siemens", "SIMATIC S7-1200", "1215C"))
        calls = []
        def fetch(strategy, parameter, start, pacer):
            calls.append((strategy, parameter, start))
            rows = [product("siemens", f"other_{start + i}") for i in range(100)]
            return reply(rows, total=400, start=start)
        out = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(out.status, "COMPLETED")
        self.assertTrue(out.result_truncated)
        self.assertEqual(out.queries[0]["status"], "PARTIAL")
        self.assertEqual(out.queries[0]["level_result"], "PARTIAL_RESULTS")
        self.assertEqual(out.queries[0]["stop_reason"], "PREVIEW_PAGE_LIMIT")
        self.assertEqual(len(calls), 3)
        self.assertFalse(CpeQuerySnapshot.objects.exists())

    def test_rockwell_variants_progress_without_keyword_or_false_confirmation(self):
        run = self.make_run(self.hardware("Rockwell Automation", "1783-EMS08T/B"))
        related = product("rockwellautomation", "1783-natr")
        seen = []
        def fetch(strategy, parameter, start, pacer):
            seen.append((strategy, parameter))
            return reply([related] if parameter == "cpe:2.3:h:rockwellautomation:1783*" else [])
        out = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(out.status, "QUEUED")
        self.assertTrue(all(strategy == "cpeMatchString" for strategy, param in seen))
        self.assertEqual(len(seen), len(set(seen)))
        self.assertTrue(any("rockwell_automation" in param for _, param in seen))
        self.assertEqual(out.candidates[0]["match_level"], "RELATED")
        self.assertEqual(out.queries[-1]["status"], "WAITING_CATALOGUE")
        self.assertEqual(CpeQuerySnapshot.objects.count(), 1)
        self.assertFalse(AssetCpe.objects.exists())

    def test_failed_catalogue_marks_run_failed_and_preserves_candidate_evidence(self):
        run = self.make_run(self.hardware("Advantech", "ADAM-5000 Series"))
        related = product("advantech", "adam-5550")
        out = execute_run(run, object(), fetcher=lambda s, p, i, pacer:
                          reply([related] if p.endswith(":adam*") else []))
        self.assertEqual(out.status, "QUEUED")
        snapshot = CpeQuerySnapshot.objects.get()
        snapshot.status = "FAILED"
        snapshot.error_code = "NVD_TOTAL_CHANGED"
        snapshot.error_message = "Los resultados cambiaron durante la recuperación."
        snapshot.save(update_fields=["status", "error_code", "error_message"])
        out = execute_run(out, object(), fetcher=lambda *args:
                          self.fail("No debe repetirse ninguna búsqueda previa"))
        self.assertEqual(out.status, "FAILED")
        self.assertTrue(out.result_truncated)
        self.assertEqual(out.queries[-1]["status"], "FAILED")
        self.assertEqual(out.queries[-1]["stop_reason"], "NVD_TOTAL_CHANGED")
        self.assertEqual(len(out.candidates), 1)

    def test_fetch_failure_retains_partial_evidence_without_general_fallback(self):
        run = self.make_run(self.hardware("Siemens", "SIMATIC S7-1200", "1215C"))
        calls = []
        def failed(strategy, parameter, start, pacer):
            calls.append(start)
            if start:
                raise TimeoutError("NVD temporalmente no disponible")
            return reply([product("siemens", "simatic_s7-1200_cpu_1214c")], total=101)
        done = execute_run(run, object(), fetcher=failed)
        self.assertEqual(done.status, "FAILED")
        self.assertTrue(done.result_truncated)
        self.assertEqual(calls, [0, 1])
        self.assertEqual(done.queries[-1]["status"], "FAILED")
        self.assertEqual(done.queries[-1]["stop_reason"], "REQUEST_FAILED")
        self.assertFalse(CpeQuerySnapshot.objects.exists())

    def test_axis_weak_suggestions_from_existing_catalogue_are_bounded(self):
        run = self.make_run(self.hardware("Axis", "206"))
        waiting = execute_run(run, object(), fetcher=lambda *args: reply([]))
        self.assertEqual(waiting.status, "QUEUED")
        snapshot = CpeQuerySnapshot.objects.get()
        rows = [
            product("axis", value)
            for value in ("207", "207w", "205", "205w", "204", "208", "209", "other")
        ]
        snapshot = execute_catalogue_snapshot(
            snapshot, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply(rows, start=i)
        )
        self.assertEqual(snapshot.status, "COMPLETED")
        finished = execute_run(waiting, object(), fetcher=lambda *args:
                               self.fail("No debe repetir la consulta a NVD"))
        self.assertEqual(finished.status, "COMPLETED")
        self.assertEqual(len(finished.candidates), 5)
        self.assertTrue(all(c["match_level"] == "EXPLORATORY"
                            for c in finished.candidates))
        self.assertFalse(finished.result_truncated)
        self.assertFalse(AssetCpe.objects.exists())

    def test_unrelated_manufacturer_catalogue_keeps_zero_candidates(self):
        run = self.make_run(self.hardware("Axis", "206"))
        waiting = execute_run(run, object(), fetcher=lambda *args: reply([]))
        snapshot = CpeQuerySnapshot.objects.get()
        snapshot = execute_catalogue_snapshot(
            snapshot, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([product("axis", "large_unrelated_device")], start=i)
        )
        finished = execute_run(waiting, object(), fetcher=lambda *args:
                               self.fail("No debe repetir la consulta a NVD"))
        self.assertEqual(finished.status, "COMPLETED")
        self.assertEqual(finished.candidates, [])

    def test_worker_prioritizes_catalogue_needed_by_waiting_asset(self):
        now = timezone.now()
        run = SimpleNamespace(
            queries=[], created_at=now - timedelta(minutes=1),
        )
        snapshot = SimpleNamespace(created_at=now)
        self.assertTrue(asset_run_precedes_snapshot(run, snapshot))
        run.queries = [{"status": "WAITING_CATALOGUE", "snapshot_id": 42}]
        self.assertFalse(asset_run_precedes_snapshot(run, snapshot))
        self.assertTrue(asset_run_precedes_snapshot(run, None))
        self.assertFalse(asset_run_precedes_snapshot(None, snapshot))
