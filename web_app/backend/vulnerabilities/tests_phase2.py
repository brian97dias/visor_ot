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
        self.assertEqual(item["identification_status"], "EVALUATED")
        self.assertEqual(item["confirmed_count"], 1)
        self.assertEqual(item["reviewed_count"], 1)

    def test_rejected_candidate_absent_from_latest_search_does_not_make_siemens_stale(self):
        # Two original candidates, both explicitly reviewed by the analyst.
        missing_id = "144590a4-1c2f-41b6-a05b-cc9a98d58104"
        missing_name = "cpe:2.3:h:siemens:unrelated_plc:-:*:*:*:*:*:*:*"
        self.run.candidates.append(candidate(missing_id, missing_name))
        self.run.save(update_fields=["candidates"])
        self.assertEqual(self.create(status="CONFIRMED").status_code, 201)
        rejected = self.client.post(self.api, {
            "run_id": self.run.pk, "cpe_name_id": missing_id,
            "status": "REJECTED", "justification": "Modelo distinto",
        }, format="json")
        self.assertEqual(rejected.status_code, 201, rejected.data)

        # The latest complete search only found the confirmed Siemens CPU.
        self.completed_search(self.asset)
        response = self.client.get("/api/vulnerabilities/cpe-overview/")
        item = next(x for x in response.data["results"] if x["asset_id"] == self.asset.pk)
        self.assertEqual(item["identification_status"], "EVALUATED")
        self.assertEqual(item["confirmed_count"], 1)
        self.assertEqual(item["unreviewed_count"], 0)
        self.assertEqual(item["out_of_scope_count"], 0)

    def test_confirmed_candidate_absent_from_latest_search_remains_stale(self):
        self.assertEqual(self.create(status="CONFIRMED").status_code, 201)
        other_name = "cpe:2.3:h:siemens:another_model:-:*:*:*:*:*:*:*"
        self.completed_search(self.asset, candidate(
            "b91ca843-f7ca-4531-828d-7279a2d2d3cb", other_name
        ))
        response = self.client.get("/api/vulnerabilities/cpe-overview/")
        item = next(x for x in response.data["results"] if x["asset_id"] == self.asset.pk)
        self.assertEqual(item["identification_status"], "STALE")
        self.assertEqual(item["out_of_scope_count"], 1)

    def test_exploratory_candidates_do_not_inflate_pending_review(self):
        exploratory = {**candidate(), "match_level": "EXPLORATORY",
                       "match_reason": "Fabricante coincidente, referencia próxima."}
        self.run.candidates = [exploratory]
        self.run.save(update_fields=["candidates"])
        response = self.client.get("/api/vulnerabilities/cpe-overview/")
        row = next(r for r in response.data["results"] if r["asset_id"] == self.asset.pk)
        self.assertEqual(row["candidate_count"], 1)
        self.assertEqual(row["exploratory_count"], 1)
        self.assertEqual(row["unreviewed_count"], 0)
        self.assertEqual(row["identification_status"], "TO_REVIEW")

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
        self.assertEqual(global_row["identification_status"], "TO_REVIEW")
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

    def test_overview_evaluated_with_one_confirmed_and_one_rejected(self):
        second_uuid = "72c1d71f-72a7-4520-8773-0d1cfc32e0b9"
        second = candidate(
            name_id=second_uuid,
            cpe_name="cpe:2.3:h:siemens:simatic_s7-1200_cpu_12_1215c:-:*:*:*:*:*:*:*",
        )
        self.run.candidates.append(second)
        self.run.save(update_fields=["candidates"])
        confirmed = self.create()
        self.assertEqual(confirmed.status_code, 201, confirmed.data)
        rejected = self.client.post(self.api, {
            "run_id": self.run.pk, "cpe_name_id": second_uuid,
            "status": "REJECTED", "justification": "",
        }, format="json")
        self.assertEqual(rejected.status_code, 201, rejected.data)

        def overview():
            response = self.client.get("/api/vulnerabilities/cpe-overview/")
            self.assertEqual(response.status_code, 200, response.data)
            return next(x for x in response.data["results"] if x["asset_id"] == self.asset.pk)

        evaluated = overview()
        self.assertEqual(evaluated["identification_status"], "EVALUATED")
        self.assertEqual(
            (evaluated["candidate_count"], evaluated["confirmed_count"],
             evaluated["rejected_count"], evaluated["unreviewed_count"]), (2, 1, 1, 0)
        )

        endpoint = self.api + f'{rejected.data["association"]["id"]}/'
        undone = self.client.patch(endpoint, {"status": "REOPENED"}, format="json")
        self.assertEqual(undone.status_code, 200, undone.data)
        reviewing = overview()
        self.assertEqual(reviewing["identification_status"], "IN_REVIEW")
        self.assertEqual(
            (reviewing["candidate_count"], reviewing["confirmed_count"],
             reviewing["rejected_count"], reviewing["unreviewed_count"]), (2, 1, 0, 1)
        )
        again = self.client.patch(endpoint, {
            "run_id": self.run.pk, "status": "REJECTED",
        }, format="json")
        self.assertEqual(again.status_code, 200, again.data)
        self.assertEqual(overview()["identification_status"], "EVALUATED")
        self.assertEqual(AssetCpe.objects.count(), 2)
        self.assertEqual(
            [h.new_status for h in AssetCpeDecision.objects.filter(
                association_id=rejected.data["association"]["id"]).order_by("pk")
            ], ["REJECTED", "REOPENED", "REJECTED"]
        )

    def test_overview_rejected_only_is_evaluated_without_a_confirmation(self):
        result = self.create(status="REJECTED", justification="")
        self.assertEqual(result.status_code, 201, result.data)
        data = self.client.get("/api/vulnerabilities/cpe-overview/").data
        row = next(x for x in data["results"] if x["asset_id"] == self.asset.pk)
        self.assertEqual(row["identification_status"], "EVALUATED")
        self.assertEqual(row["confirmed_count"], 0)
        self.assertEqual(row["rejected_count"], 1)
        self.assertEqual(row["unreviewed_count"], 0)

    def test_overview_uses_last_completed_run_while_new_one_is_queued(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.data)
        waiting = CpeSearchRun.objects.create(
            asset=self.asset, requested_by=self.analyst,
            status=CpeSearchRun.Status.QUEUED,
            identity_snapshot=hardware_identity(self.asset),
            identity_fingerprint=fingerprint(hardware_identity(self.asset)),
            candidates=[],
        )
        response = self.client.get("/api/vulnerabilities/cpe-overview/")
        row = next(x for x in response.data["results"] if x["asset_id"] == self.asset.pk)
        self.assertEqual(row["identification_status"], "QUEUED")
        self.assertEqual(row["run_id"], waiting.pk)
        self.assertEqual(row["candidate_count"], 1)
        self.assertEqual(row["confirmed_count"], 1)
        self.assertEqual(row["unreviewed_count"], 0)

    def test_historical_pending_remains_readable_and_counted_as_unreviewed(self):
        # Existing PENDING rows from previous releases must not be deleted.
        self.run.candidates.append(candidate(
            name_id="72c1d71f-72a7-4520-8773-0d1cfc32e0b9",
            cpe_name="cpe:2.3:h:siemens:simatic_s7-1200_cpu_12_1215c:-:*:*:*:*:*:*:*",
        ))
        self.run.save(update_fields=["candidates"])
        response = self.create()
        self.assertEqual(response.status_code, 201, response.data)
        catalogue = Cpe.objects.create(
            cpe_name_id="72c1d71f-72a7-4520-8773-0d1cfc32e0b9",
            cpe_name="cpe:2.3:h:siemens:simatic_s7-1200_cpu_12_1215c:-:*:*:*:*:*:*:*",
            title="Siemens CPU 12 1215C",
        )
        from django.utils import timezone
        AssetCpe.objects.create(
            asset=self.asset, cpe=catalogue, source_run=self.run,
            validation_status="PENDING", validated_by=self.analyst,
            validated_at=timezone.now(),
            validated_identity_fingerprint=fingerprint(hardware_identity(self.asset)),
        )
        response = self.client.get("/api/vulnerabilities/cpe-overview/")
        row = next(x for x in response.data["results"] if x["asset_id"] == self.asset.pk)
        self.assertEqual(row["identification_status"], "IN_REVIEW")
        self.assertEqual(row["candidate_count"], 2)
        self.assertEqual(row["confirmed_count"], 1)
        self.assertEqual(row["rejected_count"], 0)
        self.assertEqual(row["legacy_pending_count"], 1)
        self.assertEqual(row["unreviewed_count"], 1)

    def test_outside_new_search_is_not_counted_as_confirmed(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.data)
        newer = CpeSearchRun.objects.create(
            asset=self.asset, requested_by=self.analyst,
            status=CpeSearchRun.Status.COMPLETED,
            identity_snapshot=hardware_identity(self.asset),
            identity_fingerprint=fingerprint(hardware_identity(self.asset)),
            candidates=[candidate(
                name_id="72c1d71f-72a7-4520-8773-0d1cfc32e0b9",
                cpe_name="cpe:2.3:h:siemens:simatic_s7-1200_cpu_12_1215c:-:*:*:*:*:*:*:*"
            )],
        )
        row = next(x for x in self.client.get(
            "/api/vulnerabilities/cpe-overview/").data["results"] if x["asset_id"] == self.asset.pk)
        self.assertEqual(row["identification_status"], "STALE")
        self.assertEqual(row["run_id"], newer.pk)
        self.assertEqual(row["candidate_count"], 1)
        self.assertEqual(row["confirmed_count"], 0)
        self.assertEqual(row["out_of_scope_count"], 1)
