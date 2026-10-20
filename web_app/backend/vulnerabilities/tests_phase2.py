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

    def test_pending_and_reject_are_explicit_actions(self):
        pending = self.create(status="PENDING", justification="")
        self.assertEqual(pending.status_code, 201, pending.data)
        self.assertEqual(pending.data["association"]["validation_status"], "PENDING")
        association = AssetCpe.objects.get()
        rejected = self.client.patch(self.api + f"{association.pk}/",
            self.decision(status="REJECTED", justification="CPU no coincide"),
            format="json")
        self.assertEqual(rejected.status_code, 200, rejected.data)
        self.assertEqual(rejected.data["association"]["validation_status"], "REJECTED")

    def test_reason_required_for_confirmed_and_rejected(self):
        for status in ("CONFIRMED", "REJECTED"):
            with self.subTest(status=status):
                response = self.create(status=status, justification=" ")
                self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(AssetCpe.objects.exists())
        self.assertFalse(Cpe.objects.exists())

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
