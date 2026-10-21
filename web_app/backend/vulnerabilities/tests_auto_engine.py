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

    def test_phoenix_short_prefix_preview_finds_weak_candidates_and_continues(self):
        asset = self.hardware("Phoenix Contact", "FL IL 24 BK PAC")
        run = self.make_run(asset)
        rows = [product("phoenixcontact", "fl_comserver_basic_232"),
                product("phoenixcontact", "fl_comserver_uni_422")]
        calls = []

        def fetch(strategy, parameter, start, pacer):
            calls.append(parameter)
            return reply(rows if parameter == "cpe:2.3:h:phoenixcontact:fl*" else [])

        waiting = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(waiting.status, "QUEUED")
        self.assertIn("cpe:2.3:h:phoenixcontact:fl_il_24*", calls)
        self.assertIn("cpe:2.3:h:phoenixcontact:fl_il*", calls)
        self.assertIn("cpe:2.3:h:phoenixcontact:fl*", calls)
        self.assertEqual(len(waiting.candidates), 2)
        self.assertEqual({c["match_level"] for c in waiting.candidates},
                         {"EXPLORATORY"})
        self.assertFalse(waiting.result_truncated)
        snapshot = CpeQuerySnapshot.objects.get()
        self.assertEqual(snapshot.cache.parameter, "cpe:2.3:h:phoenixcontact:*")
        self.assertFalse(AssetCpe.objects.exists())

    def test_phoenix_complete_manufacturer_catalogue_ranks_only_five_fl(self):
        asset = self.hardware("Phoenix Contact", "FL IL 24 BK PAC")
        run = self.make_run(asset)
        empty = lambda *args: reply([])
        waiting = execute_run(run, object(), fetcher=empty)
        self.assertEqual(waiting.status, "QUEUED")
        snapshot = CpeQuerySnapshot.objects.get()
        names = ("fl_comserver_basic_232", "fl_comserver_uni_422",
                 "fl_il_24_switch", "fl_il_controller", "fl_server_1",
                 "fl_router_1", "fl_monitor_1")
        rows = [product("phoenixcontact", f"quint_power_{i}") for i in range(320)]
        rows += [product("phoenixcontact", name) for name in names]

        def catalogue(strategy, parameter, start, pacer, *, results_per_page):
            return reply(rows[start:start + results_per_page],
                         start=start, total=len(rows))

        completed = execute_catalogue_snapshot(snapshot, object(), fetcher=catalogue)
        self.assertEqual(completed.status, "COMPLETED")
        self.assertEqual(completed.retrieved_count, 327)
        no_repeated_previews = lambda *args: self.fail(
            "Las consultas específicas/de familia completadas no deben repetirse"
        )
        finished = execute_run(waiting, object(), fetcher=no_repeated_previews)
        # Recover the two remaining vendor aliases. A completed catalogue
        # under phoenixcontact does not prove that phoenix_contact or
        # phoenix-contact contain no additional products.
        for vendor in ("phoenix_contact", "phoenix-contact"):
            self.assertEqual(finished.status, "QUEUED")
            queued = CpeQuerySnapshot.objects.get(
                cache__parameter=f"cpe:2.3:h:{vendor}:*"
            )
            self.assertEqual(queued.status, CpeQuerySnapshot.Status.QUEUED)
            execute_catalogue_snapshot(
                queued, object(),
                fetcher=lambda s, p, i, pacer, *, results_per_page:
                reply([], start=i),
            )
            finished = execute_run(finished, object(),
                                   fetcher=no_repeated_previews)
        self.assertEqual(finished.status, "COMPLETED")
        self.assertEqual(len(finished.candidates), 5)
        self.assertTrue(all(c["match_level"] == "EXPLORATORY"
                            for c in finished.candidates))
        self.assertEqual(finished.candidates[0]["cpe_name"].split(":")[4],
                         "fl_il_24_switch")
        self.assertEqual(finished.candidates[1]["cpe_name"].split(":")[4],
                         "fl_il_controller")
        self.assertFalse(finished.result_truncated)
        self.assertFalse(AssetCpe.objects.exists())
        self.assertFalse(AssetCpeDecision.objects.exists())

    def test_moxa_family_prefix_finds_510a_but_does_not_stop_manufacturer(self):
        asset = self.hardware("Moxa", "EDS-508A")
        run = self.make_run(asset)
        sibling = product("moxa", "eds-510a")
        seen = []

        def fetch(strategy, parameter, start, pacer):
            seen.append(parameter)
            return reply([sibling] if parameter == "cpe:2.3:h:moxa:eds-5*" else [])

        waiting = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(waiting.status, "QUEUED")
        self.assertIn("cpe:2.3:h:moxa:eds-508*", seen)
        self.assertIn("cpe:2.3:h:moxa:eds-50*", seen)
        self.assertIn("cpe:2.3:h:moxa:eds-5*", seen)
        self.assertEqual(len(waiting.candidates), 1)
        self.assertEqual(waiting.candidates[0]["match_level"], "EXPLORATORY")
        self.assertFalse(waiting.result_truncated)
        snapshot = CpeQuerySnapshot.objects.get()
        self.assertEqual(snapshot.cache.parameter, "cpe:2.3:h:moxa:*")
        execute_catalogue_snapshot(
            snapshot, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([sibling], start=i),
        )
        finished = execute_run(waiting, object(), fetcher=lambda *args:
                               self.fail("No debe repetir consultas por prefijo"))
        self.assertEqual(finished.status, "COMPLETED")
        self.assertEqual(len(finished.candidates), 1)
        self.assertEqual(finished.candidates[0]["match_level"], "EXPLORATORY")
        self.assertEqual(finished.candidates[0]["discovery_levels"],
                         ["FAMILY", "MANUFACTURER"])
        self.assertFalse(AssetCpe.objects.exists())

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

    def test_real_axis_206_finds_weak_207w_from_reused_full_catalogue(self):
        run = self.make_run(self.hardware("Axis Communications", "AXIS 206"))
        fetch = lambda *args: reply([])
        run = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "QUEUED")
        first = CpeQuerySnapshot.objects.get()
        self.assertEqual(first.cache.parameter, "cpe:2.3:h:axis:*")
        rows = [product("axis", model) for model in
                ("207w", "207", "205w", "205", "204", "m1125")]
        completed = execute_catalogue_snapshot(
            first, object(),
            fetcher=lambda s, p, i, pacer, *, results_per_page: reply(rows, start=i),
        )
        self.assertEqual(completed.status, "COMPLETED")
        # Continue through other known NVD vendor aliases without refetching
        # the first snapshot; no network request is repeated for any prefix.
        for _ in range(5):
            run = execute_run(run, object(), fetcher=fetch)
            if run.status == "COMPLETED":
                break
            waiting = CpeQuerySnapshot.objects.filter(
                status=CpeQuerySnapshot.Status.QUEUED).order_by("pk").first()
            self.assertIsNotNone(waiting)
            self.assertNotEqual(waiting.pk, first.pk)
            execute_catalogue_snapshot(
                waiting, object(),
                fetcher=lambda s, p, i, pacer, *, results_per_page: reply([], start=i),
            )
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(run.candidates), 5)
        self.assertTrue(all(c["match_level"] == "EXPLORATORY"
                            for c in run.candidates))
        self.assertIn("207w", [c["cpe_name"].split(":")[4] for c in run.candidates])
        self.assertFalse(AssetCpe.objects.exists())
        self.assertFalse(run.result_truncated)

    def test_beckhoff_cx1010_revision_reuses_catalogue_for_cx9020(self):
        run = self.make_run(self.hardware("Beckhoff", "CX 1010-0012"))
        fetched = []
        def fetch(strategy, parameter, start, pacer):
            fetched.append(parameter)
            return reply([])
        waiting = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(waiting.status, "QUEUED")
        snapshot = CpeQuerySnapshot.objects.get()
        self.assertEqual(snapshot.cache.parameter, "cpe:2.3:h:beckhoff:*")
        from_nvd = product("beckhoff", "cx9020")
        snapshot = execute_catalogue_snapshot(
            snapshot, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([from_nvd], start=i)
        )
        self.assertEqual(snapshot.status, "COMPLETED")
        finished = execute_run(waiting, object(), fetcher=lambda *args:
                               self.fail("El catálogo guardado no exige nuevas consultas a NVD"))
        self.assertEqual(finished.status, "COMPLETED")
        self.assertEqual(len(finished.candidates), 1)
        item = finished.candidates[0]
        self.assertEqual(item["match_level"], "EXPLORATORY")
        self.assertIn("serie CX", item["match_reason"])
        self.assertFalse(AssetCpe.objects.exists())

    def test_unrelated_manufacturer_catalogue_keeps_zero_candidates(self):
        run = self.make_run(self.hardware("Axis", "206"))
        empty = lambda *args: reply([])
        waiting = execute_run(run, object(), fetcher=empty)
        manufacturer = CpeQuerySnapshot.objects.get()
        execute_catalogue_snapshot(
            manufacturer, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([product("axis", "large_unrelated_device")], start=i),
        )
        # No technical match: two cached keyword fallbacks must also finish
        # before the run can truthfully say it has no candidate.
        for expected in ("Axis 206", "Axis"):
            waiting = execute_run(waiting, object(), fetcher=empty)
            self.assertEqual(waiting.status, "QUEUED")
            snapshot = CpeQuerySnapshot.objects.get(
                cache__strategy="keywordSearch", cache__parameter=expected
            )
            execute_catalogue_snapshot(
                snapshot, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
                reply([], start=i),
            )
        finished = execute_run(waiting, object(), fetcher=lambda *args:
                               self.fail("No debe repetir ninguna consulta estructurada"))
        self.assertEqual(finished.status, "COMPLETED")
        self.assertEqual(finished.candidates, [])
        self.assertFalse(finished.result_truncated)

    def test_hirschmann_eagle20_discovers_belden_through_keyword_fallback(self):
        run = self.make_run(self.hardware("Hirschmann", "EAGLE20"))
        no_structured = lambda *args: reply([])
        waiting = execute_run(run, object(), fetcher=no_structured)
        self.assertEqual(waiting.status, "QUEUED")
        manufacturer = CpeQuerySnapshot.objects.get()
        self.assertEqual(manufacturer.cache.parameter, "cpe:2.3:h:hirschmann:*")
        execute_catalogue_snapshot(
            manufacturer, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([], start=i),
        )
        waiting = execute_run(waiting, object(), fetcher=no_structured)
        self.assertEqual(waiting.status, "QUEUED")
        snapshot = CpeQuerySnapshot.objects.get(cache__strategy="keywordSearch")
        self.assertEqual(snapshot.cache.parameter, "Hirschmann EAGLE20")
        official = product("belden", "hirschmann_eagle20")
        execute_catalogue_snapshot(
            snapshot, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([official], start=i),
        )
        completed = execute_run(waiting, object(), fetcher=lambda *args:
                                self.fail("El snapshot completo evita nuevas consultas"))
        self.assertEqual(completed.status, "COMPLETED")
        self.assertEqual(len(completed.candidates), 1)
        match = completed.candidates[0]
        self.assertEqual(match["match_level"], "EXPLORATORY")
        self.assertEqual(match["methods"], ["keywordSearch"])
        self.assertEqual(match["discovery_levels"], ["ALTERNATIVE"])
        self.assertIn("belden", match["match_reason"])
        self.assertIn("Hirschmann", match["match_reason"])
        self.assertEqual(completed.queries[-1]["status"], "COMPLETED")
        self.assertTrue(completed.queries[-1]["catalogue_complete"])
        self.assertFalse(AssetCpe.objects.exists())
        self.assertFalse(AssetCpeDecision.objects.exists())

    def test_hirschmann_keyword_broadening_uses_reusable_snapshot(self):
        run = self.make_run(self.hardware("Hirschmann", "EAGLE20"))
        empty = lambda *args: reply([])
        run = execute_run(run, object(), fetcher=empty)
        manufacturer = CpeQuerySnapshot.objects.get()
        execute_catalogue_snapshot(
            manufacturer, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([], start=i),
        )
        run = execute_run(run, object(), fetcher=empty)
        narrow = CpeQuerySnapshot.objects.get(cache__strategy="keywordSearch")
        execute_catalogue_snapshot(
            narrow, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([], start=i),
        )
        run = execute_run(run, object(), fetcher=empty)
        self.assertEqual(run.status, "QUEUED")
        broad = CpeQuerySnapshot.objects.get(
            cache__strategy="keywordSearch", cache__parameter="Hirschmann"
        )
        execute_catalogue_snapshot(
            broad, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([product("belden", "hirschmann_eagle20"),
                   product("belden", "hirschmann_eagle200"),
                   product("belden", "hirschmann_dragon")], start=i),
        )
        run = execute_run(run, object(), fetcher=lambda *args:
                          self.fail("No se deben repetir consultas anteriores"))
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(run.candidates[0]["match_level"], "EXPLORATORY")
        self.assertEqual(run.queries[-1]["cache_reused"], False)
        self.assertFalse(run.result_truncated)

    def test_failed_alternative_snapshot_does_not_broaden_or_fake_no_results(self):
        run = self.make_run(self.hardware("Hirschmann", "EAGLE20"))
        empty = lambda *args: reply([])
        waiting = execute_run(run, object(), fetcher=empty)
        manufacturer = CpeQuerySnapshot.objects.get()
        execute_catalogue_snapshot(
            manufacturer, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            reply([], start=i),
        )
        waiting = execute_run(waiting, object(), fetcher=empty)
        self.assertEqual(waiting.status, "QUEUED")
        narrow = CpeQuerySnapshot.objects.get(cache__strategy="keywordSearch")
        narrow.status = CpeQuerySnapshot.Status.FAILED
        narrow.error_code = "FETCH_FAILED"
        narrow.error_message = "NVD indisponible"
        narrow.save(update_fields=["status", "error_code", "error_message"])
        failed = execute_run(waiting, object(), fetcher=lambda *args:
                             self.fail("No debe reintentar el plan completo"))
        self.assertEqual(failed.status, "FAILED")
        self.assertTrue(failed.result_truncated)
        self.assertEqual(CpeQuerySnapshot.objects.filter(
            cache__strategy="keywordSearch").count(), 1)
        self.assertFalse(AssetCpe.objects.exists())

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
