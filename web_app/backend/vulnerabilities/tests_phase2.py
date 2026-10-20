"""Phase 2: audited human CPE review; never calls external NVD."""
import uuid

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from rest_framework.test import APIClient

from assets.services import register_hardware_asset
from vulnerabilities.models import Cpe, CpeSearchRun, AssetCpe, AssetCpeDecision
from vulnerabilities.services.identity import fingerprint, hardware_identity


OFFICIAL_ID = "09f448d2-f606-44ab-8891-c27a3ff64002"
OFFICIAL_NAME = "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c:-:*:*:*:*:*:*:*"


def candidate(name_id=OFFICIAL_ID, cpe_name=OFFICIAL_NAME):
    return {
        "cpe_name_id": name_id,
        "cpe_name": cpe_name,
        "title": "Siemens SIMATIC S7-1200 CPU 1215C",
        "deprecated": False,
        "nvd_created_at": "2019-08-22T11:55:42.377",
        "nvd_modified_at": "2021-05-03T14:48:45.150",
        "methods": ["keywordSearch", "cpeMatchString"],
    }


class CpeDecisionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(username="review-analyst", role=User.Role.ANALYST)
        self.admin = User.objects.create_user(username="review-admin", role=User.Role.ADMIN)
        self.operator = User.objects.create_user(username="review-operator", role=User.Role.OPERATOR)
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.asset = self.hardware("PLC Siemens")
        self.run = self.completed_search(self.asset)
        self.api = f"/api/vulnerabilities/assets/{self.asset.pk}/cpes/"

    def hardware(self, name):
        return register_hardware_asset(data={
            "name": name,
            "asset_type": "HARDWARE",
            "hardware": {
                "manufacturer": "Siemens", "model": "SIMATIC S7-1200",
                "cpu_model": "1215C", "role": "PLC",
            },
        }, user=self.operator)

    def completed_search(self, asset, product=None):
        identity = hardware_identity(asset)
        return CpeSearchRun.objects.create(
            asset=asset, requested_by=self.analyst,
            status=CpeSearchRun.Status.COMPLETED,
            identity_snapshot=identity,
            identity_fingerprint=fingerprint(identity),
            candidates=[product or candidate()],
        )

    def decision(self, status="CONFIRMED", justification="Inscripción CPU 1215C cotejada", **more):
        return {
            "run_id": self.run.pk,
            "cpe_name_id": OFFICIAL_ID,
            "status": status,
            "justification": justification,
            **more,
        }

    def create(self, **kwargs):
        return self.client.post(self.api, self.decision(**kwargs), format="json")

    def test_confirmation_creates_catalogue_association_and_immutable_audit(self):
        response = self.create()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(Cpe.objects.count(), 1)
        record = Cpe.objects.get()
        self.assertEqual(str(record.cpe_name_id), OFFICIAL_ID)
        self.assertEqual(record.cpe_name, OFFICIAL_NAME)
        self.assertIsNotNone(record.nvd_created_at)
        self.assertIsNotNone(record.nvd_modified_at)

        association = AssetCpe.objects.get(asset=self.asset)
        self.assertEqual(association.validation_status, "CONFIRMED")
        self.assertEqual(association.validated_by, self.analyst)
        self.assertEqual(association.source_run_id, self.run.pk)
        self.assertFalse(response.data["association"]["needs_review"])
        audit = list(AssetCpeDecision.objects.filter(association=association))
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0].previous_status, "")
        self.assertEqual(audit[0].new_status, "CONFIRMED")
        self.assertEqual(audit[0].actor, self.analyst)
        self.assertEqual(response.data["association"]["history"][0]["new_status"], "CONFIRMED")

    def test_duplicate_create_conflicts_and_revising_keeps_history(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.data)
        second = self.create()
        self.assertEqual(second.status_code, 409, second.data)
        self.assertEqual(AssetCpeDecision.objects.count(), 1)

        pk = first.data["association"]["id"]
        changed = self.client.patch(self.api + f"{pk}/", self.decision(
            status="REJECTED", justification="Documento del fabricante no corresponde",
        ), format="json")
        self.assertEqual(changed.status_code, 200, changed.data)
        self.assertEqual(changed.data["association"]["validation_status"], "REJECTED")
        self.assertEqual([h["new_status"] for h in changed.data["association"]["history"]],
                         ["CONFIRMED", "REJECTED"])
        original = AssetCpeDecision.objects.order_by("pk").first()
        self.assertEqual(original.new_status, "CONFIRMED")
        self.assertEqual(AssetCpe.objects.count(), 1)

    def test_same_nvd_cpe_can_be_confirmed_for_two_assets(self):
        self.assertEqual(self.create().status_code, 201)
        other = self.hardware("PLC de respaldo")
        run = self.completed_search(other)
        second = self.client.post(f"/api/vulnerabilities/assets/{other.pk}/cpes/", {
            **self.decision(),
            "run_id": run.pk,
        }, format="json")
        self.assertEqual(second.status_code, 201, second.data)
        self.assertEqual(Cpe.objects.count(), 1)
        self.assertEqual(AssetCpe.objects.count(), 2)
        self.assertEqual(AssetCpeDecision.objects.count(), 2)

    def test_pending_is_rejected_for_new_decisions_and_remains_readable_as_legacy(self):
        denied = self.create(status="PENDING", justification="")
        self.assertEqual(denied.status_code, 400, denied.data)
        self.assertEqual(AssetCpe.objects.count(), 0)
        created = self.create(status="CONFIRMED")
        self.assertEqual(created.status_code, 201, created.data)
        association = AssetCpe.objects.get()
        association.validation_status = "PENDING"  # Legacy state from older release
        association.save(update_fields=["validation_status"])
        listing = self.client.get(self.api).data["associations"]
        self.assertEqual(listing[0]["validation_status"], "PENDING")
        denied_patch = self.client.patch(
            self.api + f"{association.pk}/", self.decision(status="PENDING"),
            format="json"
        )
        self.assertEqual(denied_patch.status_code, 400, denied_patch.data)
        updated = self.client.patch(
            self.api + f"{association.pk}/",
            self.decision(status="REJECTED", justification="No aplica"), format="json"
        )
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertEqual(updated.data["association"]["validation_status"], "REJECTED")
        self.assertEqual(AssetCpeDecision.objects.count(), 2)

    def test_reason_optional_for_all_decisions_and_audited(self):
        for status in ("CONFIRMED", "REJECTED", "CONFIRMED"):
            with self.subTest(status=status):
                # Each subtest operates on a distinct review of the same CPE.
                association = AssetCpe.objects.first()
                if association:
                    if association.validation_status == status:
                        # A new valid search permits meaningful revalidation.
                        fresh = self.completed_search(self.asset)
                        payload = self.decision(
                            run_id=fresh.pk, status=status, justification=" ",
                        )
                    else:
                        payload = self.decision(status=status, justification=" ")
                    response = self.client.patch(
                        self.api + f"{association.pk}/",
                        payload,
                        format="json",
                    )
                    self.assertEqual(response.status_code, 200, response.data)
                else:
                    response = self.create(status=status, justification=" ")
                    self.assertEqual(response.status_code, 201, response.data)
                self.assertEqual(response.data["association"]["justification"], "")
                self.assertEqual(AssetCpeDecision.objects.latest("pk").justification, "")
        self.assertEqual(AssetCpe.objects.count(), 1)
        self.assertEqual(AssetCpeDecision.objects.count(), 3)

    def test_justification_may_be_omitted_and_is_limited_in_length(self):
        payload = self.decision()
        payload.pop("justification")
        response = self.client.post(self.api, payload, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["association"]["justification"], "")
        item_id = response.data["association"]["id"]
        too_long = self.client.patch(
            self.api + f"{item_id}/",
            self.decision(status="REJECTED", justification="x" * 1001), format="json",
        )
        self.assertEqual(too_long.status_code, 400, too_long.data)
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        self.assertEqual(AssetCpe.objects.get(pk=item_id).validation_status, "CONFIRMED")

    def test_foreign_run_unfinished_run_and_forged_candidate_are_blocked(self):
        other = self.hardware("PLC ajeno")
        foreign = self.completed_search(other)
        response = self.create(run_id=foreign.pk)
        self.assertEqual(response.status_code, 404, response.data)
        self.run.status = "QUEUED"
        self.run.save(update_fields=["status"])
        self.assertEqual(self.create().status_code, 400)
        self.run.status = "COMPLETED"
        self.run.save(update_fields=["status"])
        self.assertEqual(self.create(cpe_name_id=str(uuid.uuid4())).status_code, 400)
        self.assertEqual(AssetCpe.objects.count(), 0)
        self.assertEqual(AssetCpeDecision.objects.count(), 0)

    def test_change_of_cpu_invalidates_review_without_deletion(self):
        created = self.create()
        self.assertEqual(created.status_code, 201)
        self.asset.hardware.cpu_model = "1214C"
        self.asset.hardware.save(update_fields=["cpu_model"])
        association = self.client.get(self.api).data["associations"][0]
        self.assertTrue(association["needs_review"])
        overview = self.client.get("/api/vulnerabilities/cpe-overview/")
        item = next(x for x in overview.data["results"] if x["asset_id"] == self.asset.pk)
        self.assertEqual(item["identification_status"], "STALE")
        self.assertEqual(item["confirmed_count"], 0)
        self.assertEqual(self.create().status_code, 400)
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        self.assertEqual(AssetCpe.objects.count(), 1)

    def test_role_based_permissions_for_create_edit_and_read(self):
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.post(self.api, self.decision(), format="json").status_code, 403)
        self.assertEqual(self.client.get(self.api).status_code, 200)
        self.client.force_authenticate(self.analyst)
        response = self.create()
        association_id = response.data["association"]["id"]
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.patch(self.api + f"{association_id}/",
            self.decision(status="REJECTED", justification="No aplica"),
            format="json").status_code, 403)
        self.client.force_authenticate(self.admin)
        self.assertEqual(self.client.patch(self.api + f"{association_id}/",
            self.decision(status="REJECTED", justification="Producto distinto"),
            format="json").status_code, 200)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.client.get(self.api).status_code, 401)

    def test_overview_counts_validated_matches(self):
        created = self.create()
        self.assertEqual(created.status_code, 201)
        response = self.client.get("/api/vulnerabilities/cpe-overview/")
        item = next(x for x in response.data["results"] if x["asset_id"] == self.asset.pk)
        self.assertEqual(item["identification_status"], "CONFIRMED")
        self.assertEqual(item["confirmed_count"], 1)
        self.assertEqual(item["reviewed_count"], 1)

    def test_reject_cpe_from_other_asset_and_other_association(self):
        other = self.hardware("PLC alterno")
        run = self.completed_search(other)
        self.assertEqual(self.create().status_code, 201)
        pk = AssetCpe.objects.get(asset=self.asset).pk
        response = self.client.patch(f"/api/vulnerabilities/assets/{other.pk}/cpes/{pk}/", {
            **self.decision(status="REJECTED", justification="Revisado"),
            "run_id": run.pk,
        }, format="json")
        self.assertEqual(response.status_code, 404, response.data)


    def test_reopen_moves_decision_back_to_candidates_and_preserves_history(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.data)
        association_id = first.data["association"]["id"]
        endpoint = self.api + f"{association_id}/"

        reopened = self.client.patch(endpoint, {
            "status": "REOPENED", "justification": "Deseo revisar otro CPE",
        }, format="json")
        self.assertEqual(reopened.status_code, 200, reopened.data)
        self.assertEqual(reopened.data["association"]["validation_status"], "REOPENED")
        self.assertEqual(reopened.data["association"]["source_run_id"], self.run.pk)
        self.assertEqual(
            [x["new_status"] for x in reopened.data["association"]["history"]],
            ["CONFIRMED", "REOPENED"],
        )
        global_response = self.client.get("/api/vulnerabilities/cpe-overview/")
        global_row = next(x for x in global_response.data["results"]
                          if x["asset_id"] == self.asset.pk)
        self.assertEqual(global_row["identification_status"], "REOPENED")
        self.assertEqual(global_row["reviewed_count"], 0)
        self.assertEqual(global_row["reopened_count"], 1)
        self.assertEqual(global_row["confirmed_count"], 0)

        # A second decision must PATCH the same association, never create again.
        second = self.client.patch(endpoint, self.decision(
            status="CONFIRMED", justification="CPU verificada contra la placa"
        ), format="json")
        self.assertEqual(second.status_code, 200, second.data)
        self.assertEqual(AssetCpe.objects.count(), 1)
        self.assertEqual(Cpe.objects.count(), 1)
        self.assertEqual(
            [x["new_status"] for x in second.data["association"]["history"]],
            ["CONFIRMED", "REOPENED", "CONFIRMED"],
        )

    def test_reopen_without_current_run_after_identity_change(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.data)
        self.asset.hardware.cpu_model = "1214C"
        self.asset.hardware.save(update_fields=["cpu_model"])
        endpoint = self.api + f"{first.data['association']['id']}/"
        response = self.client.patch(endpoint, {"status": "REOPENED"}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(response.data["association"]["needs_review"])
        self.assertEqual(AssetCpeDecision.objects.count(), 2)
        # The old search is no longer valid for another confirmation.
        impossible = self.client.patch(endpoint, self.decision(), format="json")
        self.assertEqual(impossible.status_code, 400, impossible.data)
        self.assertEqual(AssetCpeDecision.objects.count(), 2)

    def test_reopen_requires_existing_association_and_cannot_repeat(self):
        no_record = self.client.post(self.api, {
            "run_id": self.run.pk, "cpe_name_id": OFFICIAL_ID,
            "status": "REOPENED",
        }, format="json")
        self.assertEqual(no_record.status_code, 400, no_record.data)
        first = self.create()
        endpoint = self.api + f"{first.data['association']['id']}/"
        bad_run = self.client.patch(endpoint, {
            "run_id": self.run.pk, "status": "REOPENED",
        }, format="json")
        self.assertEqual(bad_run.status_code, 400, bad_run.data)
        self.assertEqual(self.client.patch(
            endpoint, {"status": "REOPENED"}, format="json"
        ).status_code, 200)
        repeated = self.client.patch(endpoint, {"status": "REOPENED"}, format="json")
        self.assertEqual(repeated.status_code, 409, repeated.data)
        self.assertEqual(AssetCpeDecision.objects.count(), 2)

    def test_identical_decision_is_conflict_but_new_run_supports_revalidation(self):
        first = self.create()
        endpoint = self.api + f"{first.data['association']['id']}/"
        repeated = self.client.patch(endpoint, self.decision(), format="json")
        self.assertEqual(repeated.status_code, 409, repeated.data)
        self.assertEqual(AssetCpeDecision.objects.count(), 1)

        fresh = self.completed_search(self.asset)
        again = self.client.patch(endpoint, {
            **self.decision(), "run_id": fresh.pk,
        }, format="json")
        self.assertEqual(again.status_code, 200, again.data)
        self.assertEqual(again.data["association"]["source_run_id"], fresh.pk)
        self.assertEqual(AssetCpeDecision.objects.count(), 2)

    def test_only_analyst_can_reopen_and_history_is_preserved(self):
        first = self.create()
        endpoint = self.api + f"{first.data['association']['id']}/"
        self.client.force_authenticate(self.operator)
        forbidden = self.client.patch(endpoint, {"status": "REOPENED"}, format="json")
        self.assertEqual(forbidden.status_code, 403, forbidden.data)
        self.client.force_authenticate(self.admin)
        permitted = self.client.patch(endpoint, {"status": "REOPENED"}, format="json")
        self.assertEqual(permitted.status_code, 200, permitted.data)
        history = list(AssetCpeDecision.objects.order_by("pk"))
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].new_status, "CONFIRMED")
        self.assertEqual(history[1].previous_status, "CONFIRMED")
        self.assertEqual(history[1].actor, self.admin)
