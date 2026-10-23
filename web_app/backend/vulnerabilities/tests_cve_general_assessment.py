"""Generic CVE evaluation contracts; no NVD or inventory mutation."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from vulnerabilities.models import AssetCpe, AssetCveAssessment, Cpe, Cve
from vulnerabilities.services.cve_general_assessment import (
    general_assessment_context, record_general_assessment,
)
from vulnerabilities.tests_cve_discovery_plan import (
    CveDiscoveryPlanTests, HW_CPE, SW_CPE,
)


def nvd_and(hardware_criterion=HW_CPE, firmware_criterion=SW_CPE):
    return {"operator": "AND", "negate": False, "nodes": [
        {"operator": "OR", "cpeMatch": [
            {"criteria": firmware_criterion, "vulnerable": True},
        ]},
        {"operator": "OR", "cpeMatch": [
            {"criteria": hardware_criterion, "vulnerable": False},
        ]},
    ]}


class GenericCveAssessmentTests(TestCase):
    def setUp(self):
        sample = CveDiscoveryPlanTests(
            methodName="test_hardware_only_cpe_is_eligible_without_firmware_cpe",
        )
        sample.setUp()
        self.user = sample.user
        self.hw = sample.hardware
        self.sw = sample.firmware
        self.sample = sample
        self.sample.confirm(self.hw.asset, HW_CPE)
        self.installation = sample.link()
        self.cve = Cve.objects.create(
            cve_id="CVE-2026-12345", fetch_status=Cve.FetchStatus.COMPLETED,
            configurations=[nvd_and(), {
                "operator": "OR", "nodes": [
                    {"operator": "OR", "cpeMatch": [
                        {"criteria": SW_CPE, "vulnerable": True},
                    ]},
                ],
            }],
            retrieved_at=timezone.now(),
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.url = (
            "/api/vulnerabilities/cves/"
            + self.cve.cve_id + "/hardware/" + str(self.hw.pk) + "/assessment/"
        )

    def context(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        return response.data

    def decision(self, config, *, verdict="CONFIRMED", **kwargs):
        info = self.context()
        current = info["configurations"][config]
        payload = {
            "configuration_index": config,
            "verdict": verdict,
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": False,
            "justification": "Verificación manual de firmware instalado.",
            "inventory_fingerprint": info["inventory_fingerprint"],
            "configuration_fingerprint": current["fingerprint"],
        }
        payload.update(kwargs)
        return self.client.post(self.url, payload, format="json")

    def test_context_includes_all_configuration_trees_and_installed_software(self):
        info = self.context()
        self.assertEqual(len(info["configurations"]), 2)
        first = info["configurations"][0]
        self.assertTrue(first["review_supported"])
        self.assertEqual(first["tree"]["operator"], "AND")
        self.assertEqual(len(first["tree"]["children"]), 2)
        self.assertEqual(info["installed_software"][0]["software_asset_id"], self.sw.pk)
        self.assertIsInstance(info["confirmed_hardware_cpes"][0], dict)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_explicit_confirm_then_undo_append_only_for_one_configuration(self):
        posted = self.decision(0)
        self.assertEqual(posted.status_code, 201, posted.data)
        self.assertEqual(posted.data["assessment"]["status"], "APPLIES")
        state = self.context()
        self.assertEqual(state["configurations"][0]["latest_assessment"]["status"], "APPLIES")
        self.assertIsNone(state["configurations"][1]["latest_assessment"])
        undone = self.decision(0, verdict="UNKNOWN", software_installation_id=None,
                               justification="Reabrir correspondencia para investigar.")
        self.assertEqual(undone.status_code, 201, undone.data)
        self.assertEqual(undone.data["assessment"]["status"], "PENDING_REVIEW")
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
        self.assertEqual(Cpe.objects.count(), 1)
        self.assertEqual(AssetCpe.objects.count(), 1)

    def test_unverified_or_complex_or_restricted_configuration_cannot_confirm(self):
        self.assertFalse(self.context()["configurations"][1]["review_supported"])
        resp = self.decision(1)
        self.assertEqual(resp.status_code, 400, resp.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
        self.cve.configurations[0]["nodes"][0]["cpeMatch"][0][
            "versionEndExcluding"
        ] = "3.0"
        self.cve.save(update_fields=["configurations"])
        self.assertFalse(self.context()["configurations"][0]["review_supported"])
        self.assertEqual(self.decision(0).status_code, 400)

    def test_cannot_confirm_without_active_installation_or_current_hardware_cpe(self):
        linked = self.installation
        linked.unlinked_at = timezone.now()
        linked.unlinked_by = self.user
        linked.save(update_fields=["unlinked_at", "unlinked_by"])
        self.assertEqual(self.decision(0).status_code, 400)
        linked.unlinked_at = None
        linked.unlinked_by = None
        linked.save(update_fields=["unlinked_at", "unlinked_by"])
        association = AssetCpe.objects.get(asset_id=self.hw.pk)
        association.validation_status = AssetCpe.Validation.REOPENED
        association.save(update_fields=["validation_status"])
        self.assertEqual(self.decision(0).status_code, 400)

    def test_stale_configuration_revision_marks_historical_record_pending(self):
        self.assertEqual(self.decision(0).status_code, 201)
        self.cve.configurations[0]["nodes"][0]["cpeMatch"][0][
            "matchCriteriaId"
        ] = "revised"
        self.cve.save(update_fields=["configurations"])
        state = self.context()
        self.assertTrue(state["configurations"][0]["latest_assessment"]["stale"])
        self.assertEqual(
            state["configurations"][0]["latest_assessment"]["effective_status"],
            "PENDING_REVIEW",
        )

    def test_stale_submission_is_rejected_without_writes(self):
        info = self.context()
        response = self.client.post(self.url, {
            "configuration_index": 0,
            "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "justification": "Revisión",
            "inventory_fingerprint": "a" * 64,
            "configuration_fingerprint": info["configurations"][0]["fingerprint"],
        }, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_operator_cannot_record_but_can_read(self):
        operator = get_user_model().objects.create_user(
            username="generic-cve-op", role="OPERATOR",
        )
        self.client.force_authenticate(operator)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        self.assertEqual(self.client.post(self.url, {}).status_code, 403)

    def test_negative_requires_single_installed_software_and_complete_inventory(self):
        partial = self.decision(0, verdict="NOT_MATCH")
        self.assertEqual(partial.status_code, 201)
        self.assertEqual(partial.data["assessment"]["status"], "PENDING_REVIEW")
        full = self.decision(0, verdict="NOT_MATCH",
                             inventory_declared_complete=True)
        self.assertEqual(full.status_code, 201)
        self.assertEqual(full.data["assessment"]["status"], "NOT_APPLICABLE")
