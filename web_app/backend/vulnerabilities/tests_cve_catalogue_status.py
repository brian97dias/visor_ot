"""Global CVE state and server-side filtering from current analyst decisions.

These are not NVD-fetched states. A CVE can include many independent
configurations and assets; a negative applies globally only when all are
covered by latest, current audited decisions.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from vulnerabilities.models import AssetCveAssessment, Cve
from vulnerabilities.tests_cve_discovery_plan import (
    CveDiscoveryPlanTests, HW_CPE,
)
from vulnerabilities.tests_cve_general_assessment import nvd_and


class CveCatalogueEvaluationStatusTests(TestCase):
    BASE = "/api/vulnerabilities/cves/"

    def setUp(self):
        self.fixtures = CveDiscoveryPlanTests(
            methodName="test_hardware_only_cpe_is_eligible_without_firmware_cpe"
        )
        self.fixtures.setUp()
        self.user = self.fixtures.user
        self.hardware = self.fixtures.hardware
        self.software = self.fixtures.firmware
        self.fixtures.confirm(self.hardware.asset, HW_CPE)
        self.installation = self.fixtures.link()
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def make_cve(self, identifier="CVE-2026-12345", configurations=None):
        return Cve.objects.create(
            cve_id=identifier,
            fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(),
            description="Example CVE with hardware and firmware",
            configurations=[nvd_and()] if configurations is None else configurations,
        )

    def current_state(self, identifier):
        response = self.client.get(self.BASE, {"q": identifier})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["count"], 1)
        return response.data["results"][0]["evaluation_status"]

    def assess(self, cve, verdict, *, index=0, complete=False):
        path = (self.BASE + cve.cve_id + "/hardware/"
                + str(self.hardware.pk) + "/assessment/")
        context = self.client.get(path)
        self.assertEqual(context.status_code, 200, context.data)
        data = context.data
        result = self.client.post(path, {
            "configuration_index": index, "verdict": verdict,
            "software_installation_id": (
                self.installation.pk if verdict != "UNKNOWN" else None
            ),
            "inventory_declared_complete": complete,
            "justification": "Revisión de la correspondencia NVD.",
            "inventory_fingerprint": data["inventory_fingerprint"],
            "configuration_fingerprint": data["configurations"][index]["fingerprint"],
        }, format="json")
        self.assertEqual(result.status_code, 201, result.data)
        return result.data["assessment"]

    def test_no_decision_is_pending_even_when_cve_has_been_fetched(self):
        self.make_cve()
        self.assertEqual(self.current_state("CVE-2026-12345"), "PENDING_REVIEW")
        self.assertEqual(self.client.get(self.BASE, {"status": "PENDING_REVIEW"}).data["count"], 1)
        self.assertEqual(self.client.get(self.BASE, {"status": "APPLIES"}).data["count"], 0)

    def test_validated_positive_reports_applies_without_automatic_verdict(self):
        cve = self.make_cve()
        self.assertEqual(self.assess(cve, "CONFIRMED")["status"], "APPLIES")
        self.assertEqual(self.current_state(cve.cve_id), "APPLIES")
        self.assertEqual(self.client.get(self.BASE, {"status": "APPLIES"}).data["count"], 1)
        self.assertEqual(AssetCveAssessment.objects.count(), 1)

    def test_latest_undo_reopens_without_reusing_old_positive(self):
        cve = self.make_cve()
        self.assess(cve, "CONFIRMED")
        self.assess(cve, "UNKNOWN")
        self.assertEqual(self.current_state(cve.cve_id), "IN_REVIEW")
        self.assertEqual(self.client.get(self.BASE, {"status": "APPLIES"}).data["count"], 0)
        self.assertEqual(self.client.get(self.BASE, {"status": "PENDING_REVIEW"}).data["count"], 1)
        self.assertEqual(AssetCveAssessment.objects.count(), 2)

    def test_all_configurations_negative_may_be_not_applicable(self):
        cve = self.make_cve()
        result = self.assess(cve, "NOT_MATCH", complete=True)
        self.assertEqual(result["status"], "NOT_APPLICABLE")
        self.assertEqual(self.current_state(cve.cve_id), "NOT_APPLICABLE")
        self.assertEqual(self.client.get(self.BASE, {"status": "NOT_APPLICABLE"}).data["count"], 1)

    def test_hardware_wide_negative_applies_to_all_nvd_alternatives(self):
        cve = self.make_cve(
            configurations=[nvd_and(), nvd_and()]
        )
        self.assess(cve, "NOT_MATCH", index=0, complete=True)
        self.assertEqual(self.current_state(cve.cve_id), "NOT_APPLICABLE")
        self.assertEqual(self.client.get(self.BASE, {"status": "NOT_APPLICABLE"}).data["count"], 1)

    def test_changed_hardware_identity_marks_old_decision_stale(self):
        cve = self.make_cve()
        self.assess(cve, "CONFIRMED")
        self.hardware.model = "Changed Hardware Model"
        self.hardware.save(update_fields=["model"])
        self.assertEqual(self.current_state(cve.cve_id), "STALE")
        self.assertEqual(self.client.get(self.BASE, {"status": "PENDING_REVIEW"}).data["count"], 1)
        self.assertEqual(self.client.get(self.BASE, {"status": "APPLIES"}).data["count"], 0)

    def test_changed_nvd_configuration_marks_old_decision_stale(self):
        cve = self.make_cve()
        self.assess(cve, "NOT_MATCH", complete=True)
        cve.configurations[0]["nodes"][0]["cpeMatch"][0][
            "versionEndIncluding"
        ] = "3.0"
        cve.save(update_fields=["configurations"])
        self.assertEqual(self.current_state(cve.cve_id), "STALE")
        self.assertEqual(self.client.get(self.BASE, {"status": "NOT_APPLICABLE"}).data["count"], 0)

    def test_filter_is_applied_before_pagination_and_counts_only_matches(self):
        first = self.make_cve("CVE-2026-10001")
        second = self.make_cve("CVE-2026-10002")
        third = self.make_cve("CVE-2026-10003")
        self.assess(second, "CONFIRMED")
        pending = self.client.get(self.BASE, {
            "status": "PENDING_REVIEW", "page": 2, "page_size": 1
        })
        self.assertEqual(pending.status_code, 200, pending.data)
        self.assertEqual(pending.data["count"], 2)
        self.assertEqual(len(pending.data["results"]), 1)
        self.assertEqual(pending.data["results"][0]["cve_id"], third.cve_id)
        positive = self.client.get(self.BASE, {
            "status": "APPLIES", "page_size": 1,
        })
        self.assertEqual(positive.data["count"], 1)
        self.assertEqual(positive.data["results"][0]["cve_id"], second.cve_id)
        self.assertEqual(self.client.get(self.BASE, {"status": "invalid"}).status_code, 400)
        self.assertEqual(self.client.get(self.BASE, {"status": "ALL"}).data["count"], 3)
        self.assertEqual(first.cve_id, "CVE-2026-10001")

    def test_summary_counts_all_cves_unaffected_by_status_severity_and_pagination(self):
        good = self.make_cve("CVE-2026-10001")
        excluded = self.make_cve("CVE-2026-10002")
        self.make_cve("CVE-2026-10003")
        self.make_cve("CVE-2026-10004", configurations=[nvd_and(), nvd_and()])
        self.assess(good, "CONFIRMED")
        self.assess(excluded, "NOT_MATCH", complete=True)
        self.assess(Cve.objects.get(cve_id="CVE-2026-10004"), "UNKNOWN")
        expected = {"total": 4, "applies": 1, "not_applicable": 1,
                    "pending_review": 2, "validated": 2, "applies_conditional": 0}
        all_rows = self.client.get(self.BASE, {"page": 1, "page_size": 1})
        self.assertEqual(all_rows.status_code, 200, all_rows.data)
        self.assertEqual(all_rows.data["summary"], expected)
        self.assertEqual(all_rows.data["count"], 4)
        filtered = self.client.get(self.BASE, {
            "status": "PENDING_REVIEW", "page_size": 1, "q": "CVE-2026",
        })
        self.assertEqual(filtered.data["summary"], expected)
        self.assertEqual(filtered.data["count"], 2)
        self.assertEqual(len(filtered.data["results"]), 1)
        applied = self.client.get(self.BASE, {"status": "APPLIES"})
        self.assertEqual(applied.data["summary"], expected)
        self.assertEqual(applied.data["count"], 1)
        self.assertEqual(self.client.get(self.BASE, {
            "q": "does-not-exist", "severity": "HIGH",
        }).data["summary"], expected)

    def test_stale_audits_are_in_three_state_pending_filter(self):
        cve = self.make_cve()
        self.assess(cve, "CONFIRMED")
        self.hardware.model = "Changed Hardware Model"
        self.hardware.save(update_fields=["model"])
        reply = self.client.get(self.BASE, {"status": "PENDING_REVIEW"})
        self.assertEqual(reply.status_code, 200, reply.data)
        self.assertEqual(reply.data["count"], 1)
        self.assertEqual(reply.data["summary"]["pending_review"], 1)
        self.assertEqual(reply.data["summary"]["applies"], 0)
        self.assertEqual(reply.data["results"][0]["applicability_status"], "PENDING_REVIEW")

    def test_operator_can_filter_but_cannot_create_assessments(self):
        self.make_cve()
        operator = get_user_model().objects.create_user(
            username="cve-status-operator", role="OPERATOR"
        )
        self.client.force_authenticate(operator)
        self.assertEqual(
            self.client.get(self.BASE, {"status": "PENDING_REVIEW"}).status_code, 200
        )
        self.assertEqual(self.client.get(self.BASE, {"status": "STALE"}).status_code, 200)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.client.get(self.BASE).status_code, 401)


class LegacyCveCatalogueStatusTests(TestCase):
    def setUp(self):
        from vulnerabilities.tests_cve_assessment import ExperimentalCveAssessmentTests
        self.fixture = ExperimentalCveAssessmentTests(
            methodName="test_without_hardware_confirmation_or_installation_stays_pending"
        )
        self.fixture.setUp()

    def test_legacy_phoenix_positive_and_undo_use_correct_fingerprint(self):
        self.fixture.confirm_hardware_cpe()
        linked = self.fixture.link()
        positive = self.fixture.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(positive.status_code, 201, positive.data)
        url = "/api/vulnerabilities/cves/?q=CVE-2021-33540"
        response = self.fixture.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["results"][0]["evaluation_status"], "APPLIES")
        undo = self.fixture.post_decision(
            verdict="UNKNOWN", installation=linked,
            justification="Retirar correspondencia anterior."
        )
        self.assertEqual(undo.status_code, 201, undo.data)
        state = self.fixture.client.get(url)
        self.assertEqual(state.data["results"][0]["evaluation_status"], "IN_REVIEW")

    def test_legacy_inventory_changes_invalidate_previous_positive(self):
        self.fixture.confirm_hardware_cpe()
        linked = self.fixture.link()
        self.fixture.post_decision(verdict="CONFIRMED", installation=linked)
        self.fixture.hw.model = "Updated model"
        self.fixture.hw.save(update_fields=["model"])
        response = self.fixture.client.get(
            "/api/vulnerabilities/cves/?status=PENDING_REVIEW"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["cve_id"], "CVE-2021-33540")
