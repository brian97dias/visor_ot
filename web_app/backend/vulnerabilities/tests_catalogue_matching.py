"""Phase 2: non-destructive, asset-contextual classification of NVD evidence.

All NVD responses are fixtures. Snapshot products are never mutated/deleted.
"""
from copy import deepcopy
from io import StringIO
from uuid import NAMESPACE_DNS, uuid5

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from assets.services import register_hardware_asset
from vulnerabilities.models import (
    AssetCpe, AssetCpeDecision, Cpe, CpeQueryProduct, CpeQuerySnapshot,
    CpeSearchRun,
)
from vulnerabilities.services.cpe_catalogue import (
    enqueue_catalogue_query, execute_catalogue_snapshot,
)
from vulnerabilities.services.cpe_catalogue_matching import (
    CANDIDATE, EXCLUDED_NON_HARDWARE, EXCLUDED_OTHER_VENDOR,
    EXCLUDED_OTHER_PRODUCT, browse_catalogue, classify_catalogue_record,
    summarize_catalogue,
)
from vulnerabilities.services.identity import fingerprint, hardware_identity


ROCKWELL = {
    "asset_type": "HARDWARE", "manufacturer": "Rockwell Automation",
    "model": "1783-EMS08T/B", "cpu_model": "", "role": "SWITCH",
}
SIEMENS = {
    "asset_type": "HARDWARE", "manufacturer": "Siemens",
    "model": "SIMATIC S7-1200", "cpu_model": "1215C", "role": "PLC",
}
AXIS = {
    "asset_type": "HARDWARE", "manufacturer": "Axis Communications",
    "model": "AXIS 206", "cpu_model": "", "role": "CAMERA",
}


def record(product_name, *, vendor="rockwellautomation", part="h", title=None,
           deprecated=False, cpe_id=None):
    identity = f"{part}-{vendor}-{product_name}"
    return {"cpe": {
        "cpeNameId": str(cpe_id or uuid5(NAMESPACE_DNS, identity)),
        "cpeName": f"cpe:2.3:{part}:{vendor}:{product_name}:-:*:*:*:*:*:*:*",
        "deprecated": deprecated,
        "titles": [{"lang": "en", "title": title or identity}],
        "created": "2020-01-01T00:00:00.000",
        "lastModified": "2025-01-01T00:00:00.000",
        "refs": [{"ref": "https://www.rockwellautomation.com/product", "type": "Product"}],
    }}


def catalogue_snapshot(records, *, strategy="keywordSearch", keyword="Rockwell Automation",
                       page_size=2):
    snapshot, reused = enqueue_catalogue_query(strategy, keyword, page_size=page_size)
    assert not reused
    def fetch(method, parameter, start, pacer, *, results_per_page):
        return {
            "products": deepcopy(records[start:start + results_per_page]),
            "totalResults": len(records),
            "startIndex": start,
        }
    result = execute_catalogue_snapshot(snapshot, object(), fetcher=fetch)
    assert result.status == "COMPLETED", result.error_message
    return result


class CatalogueClassificationTests(TestCase):
    def setUp(self):
        self.records = [
            record("1783-natr", title="Rockwell 1783 NATR related"),
            record("1784-ems08t", title="Unrelated Rockwell series"),
            record("1783_ems08t_b", title="Rockwell 1783 EMS08T B"),
            record("1783_ems08t_b", part="o", title="Software, not hardware"),
            record("1783_ems08t_b", vendor="unrelated_vendor",
                   title="Different vendor"),
            record("1783_ems08t_b_old", title="Deprecated Rockwell version",
                   deprecated=True),
        ]
        self.snapshot = catalogue_snapshot(self.records)

    def test_all_products_remain_available_even_when_not_candidates(self):
        summary = summarize_catalogue(self.snapshot, ROCKWELL)
        self.assertTrue(summary["coverage_complete"])
        self.assertEqual(summary["examined"], 6)
        self.assertEqual(summary["candidate_count"], 3)
        self.assertEqual(summary["excluded_count"], 3)
        self.assertEqual(summary["classification_counts"][EXCLUDED_NON_HARDWARE], 1)
        self.assertEqual(summary["classification_counts"][EXCLUDED_OTHER_VENDOR], 1)
        self.assertEqual(summary["classification_counts"][EXCLUDED_OTHER_PRODUCT], 1)
        self.assertEqual(summary["pertinent_count"], 1)
        self.assertEqual(self.snapshot.products.count(), 6)
        self.assertEqual(Cpe.objects.count(), 6)

    def test_related_catalogue_prefix_never_becomes_a_specific_confirmation(self):
        rows = browse_catalogue(self.snapshot, ROCKWELL, view="CANDIDATES", limit=50)["items"]
        related = next(row for row in rows if "1783-natr" in row["cpe_name"])
        self.assertEqual(related["classification"], CANDIDATE)
        self.assertEqual(related["match_level"], "RELATED")
        self.assertFalse(related["is_pertinent"])
        self.assertIn("prefijo de catálogo", related["match_reason"])
        self.assertEqual(AssetCpe.objects.count(), 0)
        self.assertEqual(AssetCpeDecision.objects.count(), 0)

    def test_deprecated_product_not_used_as_strong_match(self):
        rows = browse_catalogue(self.snapshot, ROCKWELL, limit=50)["items"]
        deprecated = next(row for row in rows if row["deprecated"])
        self.assertTrue(deprecated["is_candidate"])
        self.assertFalse(deprecated["is_pertinent"])
        self.assertEqual(deprecated["classification"], CANDIDATE)

    def test_filtered_cursor_never_skips_records_between_candidates(self):
        first = browse_catalogue(self.snapshot, ROCKWELL, view="CANDIDATES", limit=1)
        self.assertEqual(len(first["items"]), 1)
        self.assertIsNotNone(first["next_after"])
        second = browse_catalogue(
            self.snapshot, ROCKWELL, view="CANDIDATES", limit=1,
            after_id=first["next_after"],
        )
        self.assertEqual(len(second["items"]), 1)
        self.assertNotEqual(first["items"][0]["evidence_id"], second["items"][0]["evidence_id"])
        third = browse_catalogue(
            self.snapshot, ROCKWELL, view="CANDIDATES", limit=1,
            after_id=second["next_after"],
        )
        self.assertEqual(len(third["items"]), 1)
        self.assertIsNone(third["next_after"])
        self.assertEqual(
            [p["evidence_id"] for p in (first["items"] + second["items"] + third["items"])],
            [p["evidence_id"] for p in browse_catalogue(
                self.snapshot, ROCKWELL, view="CANDIDATES", limit=20
            )["items"]],
        )

    def test_excluded_view_is_still_navigable_after_filtering(self):
        preview = browse_catalogue(self.snapshot, ROCKWELL, view="EXCLUDED", limit=20)
        self.assertEqual(len(preview["items"]), 3)
        self.assertTrue(all(not item["is_candidate"] for item in preview["items"]))
        self.assertIn(EXCLUDED_NON_HARDWARE, {p["classification"] for p in preview["items"]})

    def test_same_snapshot_different_inventory_has_independent_classification(self):
        different = summarize_catalogue(self.snapshot, SIEMENS)
        self.assertEqual(different["candidate_count"], 0)
        self.assertEqual(different["excluded_count"], 6)
        same = summarize_catalogue(self.snapshot, ROCKWELL)
        self.assertEqual(same["candidate_count"], 3)
        self.assertEqual(self.snapshot.products.count(), 6)
        self.assertEqual(CpeSearchRun.objects.count(), 0)
        self.assertEqual(AssetCpe.objects.count(), 0)

    def test_snapshot_original_json_is_never_changed_by_preview_or_summary(self):
        evidence = CpeQueryProduct.objects.filter(snapshot=self.snapshot).order_by("pk").first()
        original = deepcopy(evidence.nvd_record)
        title = original["cpe"]["titles"][0]["title"]
        browse_catalogue(self.snapshot, ROCKWELL, view="CANDIDATES")
        summarize_catalogue(self.snapshot, ROCKWELL)
        evidence.refresh_from_db()
        self.assertEqual(evidence.nvd_record, original)
        self.assertEqual(evidence.nvd_record["cpe"]["titles"][0]["title"], title)

    def test_partial_snapshot_never_claims_complete_coverage(self):
        self.snapshot.status = CpeQuerySnapshot.Status.FAILED
        self.snapshot.error_code = "NVD_TOTAL_CHANGED"
        self.snapshot.save(update_fields=["status", "error_code"])
        summary = summarize_catalogue(self.snapshot, ROCKWELL)
        preview = browse_catalogue(self.snapshot, ROCKWELL)
        self.assertFalse(summary["coverage_complete"])
        self.assertFalse(preview["coverage_complete"])
        self.assertEqual(summary["error_code"], "NVD_TOTAL_CHANGED")
        self.assertEqual(summary["examined"], 6)

    def test_invalid_page_filters_and_identity_are_rejected(self):
        for args in [
            {"view": "RANDOM"}, {"limit": 0}, {"limit": 101},
            {"limit": True}, {"after_id": -1}, {"after_id": True},
        ]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                browse_catalogue(self.snapshot, ROCKWELL, **args)
        with self.assertRaises(ValueError):
            summarize_catalogue(self.snapshot, {**ROCKWELL, "manufacturer": ""})
        with self.assertRaises(ValueError):
            browse_catalogue(self.snapshot, {**ROCKWELL, "asset_type": "SOFTWARE"})

    def test_read_only_inspection_command_displays_counts_without_creating_search_runs(self):
        User = get_user_model()
        operator = User.objects.create_user(username="catalogue-phase2", role=User.Role.OPERATOR)
        asset = register_hardware_asset(
            data={"name": "Rockwell Stratix", "asset_type": "HARDWARE",
                  "hardware": {"manufacturer": ROCKWELL["manufacturer"],
                               "model": ROCKWELL["model"], "role": "SWITCH"}},
            user=operator,
        )
        before = self.snapshot.products.count()
        output = StringIO()
        call_command(
            "inspect_cpe_catalogue", snapshot=self.snapshot.pk,
            asset=asset.pk, view="EXCLUDED", limit=2, stdout=output,
        )
        self.assertIn("candidatos sugeridos=3", output.getvalue())
        self.assertIn("Vista=EXCLUDED", output.getvalue())
        self.assertIn("Más registros:", output.getvalue())
        self.assertEqual(self.snapshot.products.count(), before)
        self.assertFalse(CpeSearchRun.objects.exists())

    def test_read_only_command_warns_when_snapshot_incomplete(self):
        User = get_user_model()
        operator = User.objects.create_user(username="catalogue-incomplete", role=User.Role.OPERATOR)
        asset = register_hardware_asset(
            data={"name": "Rockwell 2", "asset_type": "HARDWARE",
                  "hardware": {"manufacturer": "Rockwell Automation",
                               "model": "1783-EMS08T/B", "role": "SWITCH"}},
            user=operator,
        )
        self.snapshot.status = CpeQuerySnapshot.Status.INCOMPLETE
        self.snapshot.save(update_fields=["status"])
        output = StringIO()
        call_command("inspect_cpe_catalogue", snapshot=self.snapshot.pk,
                     asset=asset.pk, stdout=output)
        self.assertIn("Catálogo parcial/no finalizado", output.getvalue())
        self.assertFalse(CpeSearchRun.objects.exists())


class CatalogueSnapshotEvidenceTests(TestCase):
    def test_same_uuid_in_versions_classifies_using_original_snapshot(self):
        historical_id = uuid5(NAMESPACE_DNS, "same-uuid-versioning")
        original = record("simatic_s7-1200_cpu_1215c", vendor="siemens",
                          cpe_id=historical_id, title="Original CPE title")
        old = catalogue_snapshot([original], strategy="keywordSearch", keyword="Siemens")
        updated = deepcopy(original)
        updated["cpe"]["titles"][0]["title"] = "New CPE title"
        updated["cpe"]["lastModified"] = "2026-10-20T10:00:00.000"
        new, _ = enqueue_catalogue_query("keywordSearch", "Siemens", force=True)
        def fetch(method, parameter, start, pacer, *, results_per_page):
            return {"products": [updated], "startIndex": start, "totalResults": 1}
        new = execute_catalogue_snapshot(new, object(), fetcher=fetch)
        self.assertEqual(new.status, "COMPLETED")
        original_row = browse_catalogue(old, SIEMENS)["items"][0]
        new_row = browse_catalogue(new, SIEMENS)["items"][0]
        self.assertEqual(original_row["title"], "Original CPE title")
        self.assertEqual(new_row["title"], "New CPE title")
        self.assertTrue(original_row["is_pertinent"])
        self.assertEqual(Cpe.objects.count(), 1)
        self.assertEqual(CpeQueryProduct.objects.count(), 2)

    def test_axis_207_is_exploratory_not_a_technical_axis_206_match(self):
        snapshot = catalogue_snapshot([
            record("axis_207_network_camera", vendor="axis"),
            record("axis_206_network_camera", vendor="axis"),
        ], keyword="AXIS")
        all_rows = browse_catalogue(snapshot, AXIS, view="ALL")["items"]
        self.assertEqual(len(all_rows), 2)
        neighbour = next(row for row in all_rows if "207" in row["cpe_name"])
        self.assertEqual(neighbour["classification"], CANDIDATE)
        self.assertEqual(neighbour["match_level"], "EXPLORATORY")
        self.assertFalse(neighbour["is_pertinent"])
        candidates = browse_catalogue(snapshot, AXIS, view="CANDIDATES")["items"]
        self.assertEqual(len(candidates), 2)
        self.assertEqual(snapshot.products.count(), 2)

    def test_malformed_nvd_title_list_does_not_destroy_catalogue_evidence(self):
        malformed = record("1783-natr")
        malformed["cpe"]["titles"] = ["unrecognized", None, {"lang": "en", "title": "Rockwell NATR"}]
        snapshot = catalogue_snapshot([malformed], keyword="Rockwell")
        candidate = browse_catalogue(snapshot, ROCKWELL, view="CANDIDATES")["items"][0]
        self.assertEqual(candidate["title"], "Rockwell NATR")
        self.assertEqual(candidate["classification"], CANDIDATE)
        evidence = snapshot.products.first()
        self.assertEqual(evidence.nvd_record["cpe"]["titles"][0], "unrecognized")
