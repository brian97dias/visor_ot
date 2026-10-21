"""Phase 5: NVD product references, provenance and legacy compatibility.

All NVD responses are synthetic. No outbound HTTP requests are performed.
"""
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient

from assets.services import register_hardware_asset
from vulnerabilities.models import AssetCpe, AssetCpeDecision, Cpe, CpeSearchRun
from vulnerabilities.services.candidate_matching import (
    merge_candidates, normalize_candidate,
)
from vulnerabilities.services.cpe_search import execute_legacy_run as execute_run, serialize_run
from vulnerabilities.services.identity import fingerprint, hardware_identity
from vulnerabilities.services.nvd_references import (
    combine_references, safe_reference_url, safe_references,
)

CPE_UUID = "09f448d2-f606-44ab-8891-c27a3ff64002"
CPE_NAME = "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c:-:*:*:*:*:*:*:*"
PRODUCT_URL = "https://www.siemens.com/global/en/products/automation/systems/industrial/plc.html"
ADVISORY_URL = "https://cert-portal.siemens.com/productcert/pdf/ssa-232418.pdf"
SIEMENS = {
    "asset_type": "HARDWARE", "manufacturer": "Siemens", "model": "SIMATIC S7-1200",
    "cpu_model": "1215C", "role": "PLC",
}


def nvd_record(refs=None):
    return {"cpe": {
        "cpeNameId": CPE_UUID,
        "cpeName": CPE_NAME,
        "deprecated": False,
        "titles": [{"lang": "en", "title": "Siemens SIMATIC S7-1200 CPU 1215C"}],
        "refs": refs if refs is not None else [
            {"ref": PRODUCT_URL, "type": "Product"},
            {"ref": ADVISORY_URL, "type": "Advisory"},
        ],
    }}


class NvdReferenceValidationTests(SimpleTestCase):
    def test_preserves_product_and_advisory_as_nvd_metadata(self):
        item = normalize_candidate(nvd_record(), SIEMENS, "keywordSearch")
        self.assertEqual(item["nvd_references"], [
            {"url": PRODUCT_URL, "type": "Product", "source": "NVD"},
            {"url": ADVISORY_URL, "type": "Advisory", "source": "NVD"},
        ])
        self.assertEqual(item["match_level"], "SPECIFIC")

    def test_unsafe_or_irrelevant_urls_never_enter_catalogue(self):
        raw = [
            {"ref": "javascript:alert(1)", "type": "Product"},
            {"ref": "http://siemens.com/something", "type": "Advisory"},
            {"ref": "https://127.0.0.1/admin", "type": "Product"},
            {"ref": "https://127.1/admin", "type": "Product"},
            {"ref": "https://siemens.com/bad path", "type": "Product"},
            {"ref": "https://localhost/page", "type": "Product"},
            {"ref": "https://private.internal/config", "type": "Product"},
            {"ref": "https://user:pass@siemens.com", "type": "Product"},
            {"ref": "https://siemens.com\nnew", "type": "Product"},
            {"ref": ADVISORY_URL, "type": "Advisory"},
            {"ref": ADVISORY_URL, "type": "Product"},
        ]
        self.assertEqual(safe_references(raw), [
            {"url": ADVISORY_URL, "type": "Advisory", "source": "NVD"},
        ])
        for item in raw:
            if item["ref"] != ADVISORY_URL:
                self.assertIsNone(safe_reference_url(item["ref"]))

    def test_malformed_and_legacy_entries_are_safe(self):
        self.assertEqual(safe_references(None), [])
        self.assertEqual(safe_references({"ref": ADVISORY_URL}), [])
        self.assertEqual(safe_references(["invalid", {}, None]), [])
        self.assertEqual(safe_references([{"ref": PRODUCT_URL, "tags": ["Product"]}])[0]["type"], "Product")

    def test_reference_union_is_stable_and_bounded(self):
        first = safe_references([{"ref": PRODUCT_URL, "type": "Product"}])
        next_refs = safe_references([{"ref": PRODUCT_URL, "type": "Product"},
                                    {"ref": ADVISORY_URL, "type": "Advisory"}])
        self.assertEqual(len(combine_references(first, next_refs)), 2)
        links = [{"ref": f"https://docs.siemens.com/references/{i}", "type": "Product"}
                 for i in range(40)]
        self.assertEqual(len(safe_references(links)), 20)

    def test_merge_preserves_refs_across_duplicate_uuid(self):
        first = normalize_candidate(nvd_record([{"ref": PRODUCT_URL, "type": "Product"}]),
                                    SIEMENS, "keywordSearch")
        second = normalize_candidate(nvd_record([{"ref": ADVISORY_URL, "type": "Advisory"}]),
                                     SIEMENS, "cpeMatchString")
        combined = merge_candidates([first, second])
        self.assertEqual(len(combined), 1)
        self.assertEqual(len(combined[0]["nvd_references"]), 2)
        self.assertEqual(combined[0]["methods"], ["cpeMatchString", "keywordSearch"])

    def test_empty_historical_refs_do_not_raise(self):
        item = normalize_candidate(nvd_record(refs=[]), SIEMENS, "keywordSearch")
        self.assertEqual(item["nvd_references"], [])
        self.assertEqual(combine_references(item.get("nvd_references"), None), [])


class NvdReferencesWorkerTests(SimpleTestCase):
    def test_progressive_worker_persists_two_strategy_references_once(self):
        run = SimpleNamespace(
            identity_snapshot=SIEMENS, scope="SPECIFIC", trigger="MANUAL",
            status="QUEUED", queries=[], candidates=[], result_truncated=False,
            error_message="", save=lambda update_fields: None,
        )
        def fetch(strategy, parameter, start_index, pacer):
            refs = ([{"ref": PRODUCT_URL, "type": "Product"}]
                    if strategy == "keywordSearch" else
                    [{"ref": ADVISORY_URL, "type": "Advisory"}])
            return {"products": [nvd_record(refs)], "totalResults": 1}
        execute_run(run, object(), fetcher=fetch)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(len(run.candidates[0]["nvd_references"]), 2)
        self.assertEqual(run.candidates[0]["discovery_levels"], ["SPECIFIC"])
        self.assertEqual(len(run.queries), 2)
        self.assertEqual(run.candidates[0]["methods"], ["cpeMatchString", "keywordSearch"])

    def test_advanced_search_keeps_references_and_original_plan(self):
        run = SimpleNamespace(
            identity_snapshot=SIEMENS, scope="SPECIFIC", trigger="ADVANCED",
            status="QUEUED", queries=[{"strategy": "keywordSearch",
                                     "parameter": "Siemens", "start_index": 0,
                                     "max_pages": 1, "level": "ADVANCED"}],
            candidates=[], result_truncated=False,
            error_message="", save=lambda update_fields: None,
        )
        execute_run(run, object(), fetcher=lambda *args: {
            "products": [nvd_record()], "totalResults": 1,
        })
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(run.queries[0]["level"], "ADVANCED")
        self.assertEqual(len(run.candidates[0]["nvd_references"]), 2)


class NvdReferencesDecisionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(username="references-analyst",
                                                 role=User.Role.ANALYST)
        self.operator = User.objects.create_user(username="references-operator",
                                                  role=User.Role.OPERATOR)
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.asset = register_hardware_asset(
            data={"name": "PLC de prueba", "asset_type": "HARDWARE",
                  "hardware": {"manufacturer": "Siemens", "model": "SIMATIC S7-1200",
                               "cpu_model": "1215C", "role": "PLC"}},
            user=self.operator,
        )
        self.api = f"/api/vulnerabilities/assets/{self.asset.pk}/cpes/"

    def run_with_candidate(self, refs=None):
        identity = hardware_identity(self.asset)
        item = normalize_candidate(nvd_record(refs), identity, "keywordSearch")
        return CpeSearchRun.objects.create(
            asset=self.asset, requested_by=self.analyst,
            status=CpeSearchRun.Status.COMPLETED,
            identity_snapshot=identity,
            identity_fingerprint=fingerprint(identity),
            candidates=[item],
        )

    def decide(self, run, status="CONFIRMED", association_id=None):
        body = {"run_id": run.pk, "cpe_name_id": CPE_UUID,
                "status": status, "justification": "Comparación con etiqueta"}
        if association_id:
            return self.client.patch(self.api + f"{association_id}/", body, format="json")
        return self.client.post(self.api, body, format="json")

    def test_confirmed_catalogue_preserves_links_source_run_and_audit(self):
        run = self.run_with_candidate()
        result = self.decide(run)
        self.assertEqual(result.status_code, 201, result.data)
        catalogue = Cpe.objects.get(cpe_name_id=CPE_UUID)
        self.assertEqual(len(catalogue.nvd_references), 2)
        self.assertEqual(catalogue.references_source_run_id, run.pk)
        self.assertEqual(result.data["association"]["references_source_run_id"], run.pk)
        self.assertEqual(len(result.data["association"]["nvd_references"]), 2)
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        again = self.client.get(self.api)
        self.assertEqual(len(again.data["associations"][0]["nvd_references"]), 2)

    def test_rejected_catalogue_also_retains_references_without_confirmation(self):
        run = self.run_with_candidate()
        result = self.decide(run, "REJECTED")
        self.assertEqual(result.status_code, 201)
        self.assertEqual(result.data["association"]["validation_status"], "REJECTED")
        self.assertEqual(len(Cpe.objects.get().nvd_references), 2)
        self.assertEqual(AssetCpeDecision.objects.get().new_status, "REJECTED")

    def test_new_evidence_updates_catalogue_but_preserves_decision_history(self):
        first = self.run_with_candidate([{"ref": PRODUCT_URL, "type": "Product"}])
        created = self.decide(first)
        self.assertEqual(created.status_code, 201)
        association = created.data["association"]["id"]
        second = self.run_with_candidate([{"ref": ADVISORY_URL, "type": "Advisory"}])
        changed = self.decide(second, "CONFIRMED", association_id=association)
        self.assertEqual(changed.status_code, 200, changed.data)
        self.assertEqual(changed.data["association"]["references_source_run_id"], second.pk)
        self.assertEqual(changed.data["association"]["nvd_references"][0]["url"], ADVISORY_URL)
        # A read after PATCH must not replace the newer Advisory-only
        # provenance with a Product reference from the older search.
        persisted = Cpe.objects.get(cpe_name_id=CPE_UUID)
        self.assertEqual(persisted.references_source_run_id, second.pk)
        self.assertEqual(persisted.nvd_references[0]["url"], ADVISORY_URL)
        fetched = self.client.get(self.api)
        self.assertEqual(fetched.status_code, 200, fetched.data)
        self.assertEqual(fetched.data["associations"][0]["references_source_run_id"], second.pk)
        self.assertEqual(fetched.data["associations"][0]["nvd_references"][0]["url"], ADVISORY_URL)
        self.assertEqual(AssetCpeDecision.objects.count(), 2)
        self.assertEqual([x.source_run_id for x in AssetCpeDecision.objects.order_by("pk")],
                         [first.pk, second.pk])

    def test_later_missing_references_cannot_erase_known_source(self):
        first = self.run_with_candidate()
        created = self.decide(first)
        empty = self.run_with_candidate([])
        response = self.decide(empty, "REJECTED",
                               association_id=created.data["association"]["id"])
        self.assertEqual(response.status_code, 200, response.data)
        catalogue = Cpe.objects.get()
        self.assertEqual(catalogue.references_source_run_id, first.pk)
        self.assertEqual(len(catalogue.nvd_references), 2)
        self.assertEqual(AssetCpeDecision.objects.count(), 2)

    def test_legacy_candidates_can_be_reviewed_without_references(self):
        run = self.run_with_candidate([])
        created = self.decide(run)
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(created.data["association"]["nvd_references"], [])
        self.assertIsNone(created.data["association"]["references_source_run_id"])
        self.assertEqual(Cpe.objects.get().nvd_references, [])


    def test_reviewed_legacy_cpe_uses_new_search_product_without_new_decision(self):
        historical = self.run_with_candidate([])
        created = self.decide(historical)
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(Cpe.objects.get().nvd_references, [])
        later = self.run_with_candidate([
            {"ref": PRODUCT_URL, "type": "Product"},
            {"ref": ADVISORY_URL, "type": "Advisory"},
        ])
        response = self.client.get(self.api)
        self.assertEqual(response.status_code, 200, response.data)
        item = response.data["associations"][0]
        self.assertEqual(item["references_source_run_id"], later.pk)
        self.assertEqual(len(item["nvd_references"]), 2)
        self.assertEqual(item["nvd_references"][0]["url"], PRODUCT_URL)
        # A read-only API must not rewrite catalogue entries or decisions.
        self.assertEqual(Cpe.objects.get().nvd_references, [])
        self.assertEqual(AssetCpeDecision.objects.count(), 1)

    def test_recent_cpe_without_product_does_not_replace_catalogue_product(self):
        original = self.run_with_candidate([{"ref": PRODUCT_URL, "type": "Product"}])
        created = self.decide(original)
        self.assertEqual(created.status_code, 201)
        later = self.run_with_candidate([{"ref": ADVISORY_URL, "type": "Advisory"}])
        response = self.client.get(self.api)
        item = response.data["associations"][0]
        self.assertEqual(item["references_source_run_id"], original.pk)
        self.assertEqual(item["nvd_references"][0]["url"], PRODUCT_URL)
        self.assertEqual(AssetCpeDecision.objects.count(), 1)

    def test_recent_search_other_uuid_never_supplies_incorrect_product(self):
        old = self.run_with_candidate([])
        created = self.decide(old)
        self.assertEqual(created.status_code, 201)
        run = self.run_with_candidate([])
        row = run.candidates[0]
        row["cpe_name_id"] = "72c1d71f-72a7-4520-8773-0d1cfc32e0b9"
        row["nvd_references"] = [{"url": PRODUCT_URL, "type": "Product", "source": "NVD"}]
        run.candidates = [row]
        run.save(update_fields=["candidates"])
        response = self.client.get(self.api)
        item = response.data["associations"][0]
        self.assertEqual(item["nvd_references"], [])
        self.assertIsNone(item["references_source_run_id"])

    def test_reopened_decision_does_not_change_nvd_reference_source(self):
        run = self.run_with_candidate()
        created = self.decide(run)
        association = created.data["association"]["id"]
        changed = self.client.patch(self.api + f"{association}/", {
            "status": "REOPENED", "justification": ""
        }, format="json")
        self.assertEqual(changed.status_code, 200, changed.data)
        self.assertEqual(changed.data["association"]["references_source_run_id"], run.pk)
        self.assertEqual(AssetCpe.objects.get().validation_status, "REOPENED")
        self.assertEqual(AssetCpeDecision.objects.count(), 2)
