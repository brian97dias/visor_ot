"""Phase 3: catalogue REST explorer, roles and evidence-bound human decisions.

No requests to NVD are made in these tests.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from assets.models import Asset
from assets.services import register_hardware_asset
from vulnerabilities.models import (
    AssetCpe, AssetCpeDecision, Cpe, CpeQueryProduct, CpeQuerySnapshot,
    CpeSearchRun,
)
from vulnerabilities.services.cpe_catalogue import (
    enqueue_catalogue_query, execute_catalogue_snapshot,
)
from vulnerabilities.tests_catalogue_matching import record


class CatalogueExplorerAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="catalogue-ui-analyst", role=User.Role.ANALYST
        )
        self.operator = User.objects.create_user(
            username="catalogue-ui-operator", role=User.Role.OPERATOR
        )
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.asset = register_hardware_asset(
            data={"name": "Phoenix Contact", "asset_type": "HARDWARE",
                  "hardware": {"manufacturer": "Phoenix Contact",
                               "model": "FL IL 24 BK-PAC", "role": "PLC"}},
            user=self.operator,
        )
        self.records = [
            record("fl_il_24_bk-pac", vendor="phoenixcontact",
                   title="Phoenix Contact FL IL 24 BK-PAC"),
            record("other_model", vendor="phoenixcontact", title="Otro producto"),
            record("fl_il_24_bk-pac", vendor="unrelated_vendor", title="Otro fabricante"),
            record("fl_il_24_bk-pac", vendor="phoenixcontact", part="o",
                   title="Sistema operativo"),
            record("legacy_device", vendor="phoenixcontact", deprecated=True,
                   title="Hardware antiguo"),
        ]
        self.snapshot, _ = enqueue_catalogue_query(
            "cpeMatchString", "cpe:2.3:h:phoenixcontact", page_size=2,
        )
        def fake_nvd(strategy, parameter, start, pacer, *, results_per_page):
            return {
                "products": self.records[start:start + results_per_page],
                "totalResults": len(self.records), "startIndex": start,
            }
        self.snapshot = execute_catalogue_snapshot(
            self.snapshot, object(), fetcher=fake_nvd
        )
        self.assertEqual(self.snapshot.status, "COMPLETED")
        self.prefix = f"/api/vulnerabilities/assets/{self.asset.pk}/cpe-catalogue/snapshots/"
        self.browse_url = self.prefix + f"{self.snapshot.pk}/"
        self.select_url = self.browse_url + "select/"

    def test_snapshot_list_and_complete_summary(self):
        listing = self.client.get(self.prefix)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.data["snapshots"][0]["stored_products"], 5)
        browse = self.client.get(self.browse_url)
        self.assertEqual(browse.status_code, 200, browse.data)
        self.assertEqual(browse.data["summary"]["examined"], 5)
        self.assertEqual(browse.data["summary"]["candidate_count"], 1)
        self.assertEqual(browse.data["summary"]["excluded_count"], 4)
        self.assertTrue(browse.data["page"]["coverage_complete"])
        self.assertEqual(CpeQueryProduct.objects.count(), 5)
        self.assertFalse(AssetCpe.objects.exists())

    def test_filters_are_applied_before_server_cursor_pagination(self):
        query = {"view": "EXCLUDED", "limit": 1, "cpe_type": "h",
                 "deprecated": "ALL"}
        all_rows = []
        cursor = 0
        for _ in range(10):
            result = self.client.get(self.browse_url, {**query, "after": cursor})
            self.assertEqual(result.status_code, 200, result.data)
            current = result.data["page"]
            all_rows.extend(current["items"])
            if current["next_after"] is None:
                break
            cursor = current["next_after"]
        self.assertEqual(len(all_rows), 3)
        self.assertEqual(len({row["evidence_id"] for row in all_rows}), 3)
        self.assertTrue(all(row["cpe_type"] == "h" for row in all_rows))
        response = self.client.get(self.browse_url, {"q": "BK-PAC", "cpe_type": "h"})
        self.assertEqual(len(response.data["page"]["items"]), 2)

    def test_nvd_type_and_deprecation_filters(self):
        os_response = self.client.get(self.browse_url, {"cpe_type": "o"})
        self.assertEqual(len(os_response.data["page"]["items"]), 1)
        self.assertEqual(os_response.data["page"]["items"][0]["classification"], "NON_HARDWARE")
        deprecated = self.client.get(self.browse_url, {"deprecated": "YES"})
        self.assertEqual(len(deprecated.data["page"]["items"]), 1)
        self.assertTrue(deprecated.data["page"]["items"][0]["deprecated"])

    def test_validation_rejects_invalid_filters(self):
        for params in (
            {"view": "EVIL"}, {"limit": 101}, {"limit": -1},
            {"after": -1}, {"q": "x" * 121}, {"cpe_type": "x"},
        ):
            with self.subTest(params=params):
                response = self.client.get(self.browse_url, params)
                self.assertEqual(response.status_code, 400, response.data)

    def test_operator_can_browse_but_cannot_select(self):
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.get(self.prefix).status_code, 200)
        self.assertEqual(self.client.get(self.browse_url).status_code, 200)
        eid = CpeQueryProduct.objects.get(snapshot=self.snapshot,
                  cpe__cpe_name=self.records[0]["cpe"]["cpeName"]).pk
        response = self.client.post(self.select_url, {"evidence_id": eid}, format="json")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(CpeSearchRun.objects.exists())

    def test_select_prepares_evidence_without_creating_human_decision(self):
        row = CpeQueryProduct.objects.get(
            snapshot=self.snapshot, cpe__cpe_name=self.records[0]["cpe"]["cpeName"]
        )
        response = self.client.post(self.select_url, {"evidence_id": row.pk}, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        run = response.data["run"]
        self.assertEqual(run["trigger"], "CATALOGUE")
        self.assertEqual(run["status"], "COMPLETED")
        self.assertTrue(run["identity_is_current"])
        self.assertEqual(run["queries"][0]["snapshot_id"], self.snapshot.pk)
        self.assertEqual(run["queries"][0]["evidence_id"], row.pk)
        self.assertEqual(run["candidates"][0]["source_evidence_id"], row.pk)
        self.assertEqual(run["candidates"][0]["cpe_name_id"].lower(),
                         str(row.cpe.cpe_name_id).lower())
        self.assertEqual(AssetCpeDecision.objects.count(), 0)
        self.assertEqual(AssetCpe.objects.count(), 0)
        again = self.client.post(self.select_url, {"evidence_id": row.pk}, format="json")
        self.assertEqual(again.status_code, 200, again.data)
        self.assertTrue(again.data["reused"])
        self.assertEqual(CpeSearchRun.objects.count(), 1)

    def test_explicit_confirmation_uses_existing_audited_decision_service(self):
        row = CpeQueryProduct.objects.get(
            snapshot=self.snapshot, cpe__cpe_name=self.records[0]["cpe"]["cpeName"]
        )
        prepared = self.client.post(
            self.select_url, {"evidence_id": row.pk}, format="json"
        ).data["run"]
        outcome = self.client.post(
            f"/api/vulnerabilities/assets/{self.asset.pk}/cpes/",
            {"run_id": prepared["id"], "cpe_name_id": row.cpe.cpe_name_id,
             "status": "CONFIRMED", "justification": "Etiqueta del fabricante"},
            format="json",
        )
        self.assertEqual(outcome.status_code, 201, outcome.data)
        self.assertEqual(AssetCpe.objects.get().validation_status, "CONFIRMED")
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        self.assertEqual(AssetCpeDecision.objects.get().source_run_id, prepared["id"])
        # The original product evidence has never been edited or erased.
        self.assertEqual(row.nvd_record["cpe"]["cpeNameId"].lower(),
                         str(row.cpe.cpe_name_id).lower())
        self.assertEqual(self.snapshot.products.count(), 5)

    def test_software_records_cannot_be_prepared_for_hardware_review(self):
        row = CpeQueryProduct.objects.get(snapshot=self.snapshot,
                  cpe__cpe_name__startswith="cpe:2.3:o:")
        result = self.client.post(
            self.select_url, {"evidence_id": row.pk}, format="json"
        )
        self.assertEqual(result.status_code, 400)
        self.assertFalse(CpeSearchRun.objects.exists())

    def test_cross_snapshot_id_and_random_uuids_cannot_be_selected(self):
        first = CpeQueryProduct.objects.filter(snapshot=self.snapshot).first()
        other_snapshot, _ = enqueue_catalogue_query("keywordSearch", "Siemens")
        self.assertEqual(self.client.post(
            self.prefix + f"{other_snapshot.pk}/select/",
            {"evidence_id": first.pk}, format="json",
        ).status_code, 400 if other_snapshot.status != "COMPLETED" else 404)
        self.assertEqual(self.client.post(
            self.select_url, {"evidence_id": 99999999}, format="json"
        ).status_code, 404)
        self.assertFalse(CpeSearchRun.objects.exists())

    def test_archived_asset_and_incomplete_snapshot_are_not_selectable(self):
        first = self.snapshot.products.first()
        self.snapshot.status = CpeQuerySnapshot.Status.INCOMPLETE
        self.snapshot.save(update_fields=["status"])
        response = self.client.post(
            self.select_url, {"evidence_id": first.pk}, format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.snapshot.status = CpeQuerySnapshot.Status.COMPLETED
        self.snapshot.save(update_fields=["status"])
        self.asset.inventory_status = Asset.InventoryStatus.ARCHIVED
        self.asset.save(update_fields=["inventory_status"])
        response = self.client.post(
            self.select_url, {"evidence_id": first.pk}, format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(CpeSearchRun.objects.exists())

    def test_selection_identity_is_checked_again_at_decision_time(self):
        first = self.snapshot.products.first()
        selected = self.client.post(
            self.select_url, {"evidence_id": first.pk}, format="json",
        ).data["run"]
        from assets.models import Hardware
        hardware = Hardware.objects.get(asset=self.asset)
        hardware.model = "Changed inventory model"
        hardware.save(update_fields=["model"])
        decision = self.client.post(
            f"/api/vulnerabilities/assets/{self.asset.pk}/cpes/",
            {"run_id": selected["id"], "cpe_name_id": selected["candidates"][0]["cpe_name_id"],
             "status": "CONFIRMED"}, format="json",
        )
        self.assertEqual(decision.status_code, 400)
        self.assertFalse(AssetCpeDecision.objects.exists())
