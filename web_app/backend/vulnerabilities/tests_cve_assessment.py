"""Phase 2: assistive CVE evaluation; no NVD network access nor CPE mutation."""
from decimal import Decimal
from uuid import UUID

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from assets.models import Asset, Hardware, Software, SoftwareInstallation
from vulnerabilities.models import (
    Cve, Cpe, CpeSearchRun, AssetCpe, AssetCpeDecision, AssetCveAssessment,
)
from vulnerabilities.services.cve_ingestion import (
    EXPERIMENTAL_CVE_ID, FIRMWARE_CRITERION, HARDWARE_CRITERION,
)
from vulnerabilities.services.identity import fingerprint, hardware_identity
from vulnerabilities.tests_cve_ingestion import nvd_fixture


class ExperimentalCveAssessmentTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(username="cve-analyst", role=User.Role.ANALYST)
        self.operator = User.objects.create_user(username="cve-operator", role=User.Role.OPERATOR)
        self.client = APIClient()
        self.client.force_authenticate(self.analyst)
        self.hardware_asset = Asset.objects.create(
            id=2, name="Phoenix Contact IL PN BK-PAC", asset_type="HARDWARE",
            created_by=self.analyst, updated_by=self.analyst,
        )
        self.hw = Hardware.objects.create(
            asset=self.hardware_asset, manufacturer="Phoenix Contact",
            model="IL PN BK-PAC", role="OTHER",
        )
        self.software_asset = Asset.objects.create(
            id=4, name="Phoenix Contact IL PN BK-PAC Firmware",
            asset_type="SOFTWARE", created_by=self.analyst, updated_by=self.analyst,
        )
        self.firmware = Software.objects.create(
            asset=self.software_asset, manufacturer="Phoenix Contact",
            product="IL PN BK-PAC Firmware", version="2.0",
            software_type=Software.SoftwareType.FIRMWARE,
        )
        self.cve = Cve.objects.create(
            cve_id=EXPERIMENTAL_CVE_ID,
            fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(),
            description="Undocumented FTP access",
            severity="HIGH", base_score=Decimal("7.3"),
            configurations=nvd_fixture()["vulnerabilities"][0]["cve"]["configurations"],
        )
        self.url = f"/api/vulnerabilities/assets/2/cve-assessments/{EXPERIMENTAL_CVE_ID}/"

    def context(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        return response.data

    def link(self, software=None, hardware=None):
        return SoftwareInstallation.objects.create(
            software=software or self.firmware, hardware=hardware or self.hw,
            registered_by=self.analyst, identity_snapshot={},
        )

    def confirm_hardware_cpe(self):
        name_id = UUID("f9fc7f57-0f76-4dcb-aca0-3b767bc3dafd")
        run = CpeSearchRun.objects.create(
            asset=self.hardware_asset, requested_by=self.analyst,
            status=CpeSearchRun.Status.COMPLETED,
            identity_snapshot=hardware_identity(self.hardware_asset),
            identity_fingerprint=fingerprint(hardware_identity(self.hardware_asset)),
        )
        cpe = Cpe.objects.create(
            cpe_name_id=name_id, cpe_name=HARDWARE_CRITERION,
            title="Phoenix IL PN BK-PAC",
        )
        return AssetCpe.objects.create(
            asset=self.hardware_asset, cpe=cpe, source_run=run,
            validation_status=AssetCpe.Validation.CONFIRMED,
            validated_by=self.analyst, validated_at=timezone.now(),
            validated_identity_fingerprint=fingerprint(hardware_identity(self.hardware_asset)),
        )

    def post_decision(self, *, verdict="UNKNOWN", installation=None,
                      complete=False,
                      justification="Decisión justificada por el analista", **overrides):
        info = self.context()
        payload = {
            "firmware_verdict": verdict,
            "software_installation_id": installation.pk if installation else None,
            "inventory_declared_complete": complete,
            "justification": justification,
            "inventory_fingerprint": info["inventory_fingerprint"],
            "configuration_fingerprint": info["configuration_fingerprint"],
        }
        payload.update(overrides)
        return self.client.post(self.url, payload, format="json")

    def test_phoenix_cve_uses_the_same_generic_assessment_api(self):
        """The former experimental CVE must work without a hard-coded CVE UI."""
        self.confirm_hardware_cpe()
        installation = self.link()
        url = (
            f"/api/vulnerabilities/cves/{EXPERIMENTAL_CVE_ID}/"
            f"hardware/{self.hw.pk}/assessment/"
        )
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200, result.data)
        data = result.data
        self.assertEqual(data["hardware_asset_id"], self.hw.pk)
        self.assertEqual(
            len(data["configurations"]), len(self.cve.configurations)
        )
        phoenix = next(
            (row for row in data["relevant_configurations"]
             if row["position"] == 12), None
        )
        self.assertIsNotNone(phoenix)
        self.assertEqual(phoenix["hardware_scope"], "MATCHED")
        self.assertTrue(phoenix["conditional_supported"])
        self.assertIn(
            installation.pk,
            [row["installation_id"] for row in data["installed_software"]],
        )
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

        # The new UI uses the generic endpoint to register a conditional
        # decision without inventing a verified firmware CPE identity.
        submitted = self.client.post(url, {
            "configuration_index": phoenix["index"],
            "verdict": "CONDITIONAL",
            "software_installation_id": None,
            "selected_nvd_criterion": FIRMWARE_CRITERION,
            "inventory_fingerprint": data["inventory_fingerprint"],
            "configuration_fingerprint": phoenix["fingerprint"],
            "justification": "Firmware identificado, versión por verificar.",
        }, format="json")
        self.assertEqual(submitted.status_code, 201, submitted.data)
        self.assertEqual(
            submitted.data["assessment"]["status"], "APPLIES_CONDITIONAL"
        )
        self.assertIsNone(
            submitted.data["assessment"]["software_installation_id"]
        )
        self.assertEqual(AssetCveAssessment.objects.count(), 1)

    def test_multilingual_nvd_descriptions_are_returned_without_translating_or_overwriting(self):
        descriptions = [
            {"lang": "en", "value": "NVD English original"},
            {"lang": "es", "value": "Descripción oficial en español"},
        ]
        self.cve.descriptions = descriptions
        self.cve.save(update_fields=["descriptions"])
        info = self.context()
        self.assertEqual(info["descriptions"], descriptions)
        self.assertEqual(info["description"], "Undocumented FTP access")

    def test_without_hardware_confirmation_or_installation_stays_pending(self):
        info = self.context()
        self.assertEqual(info["configuration_position"], 12)
        self.assertEqual(info["initial_status"], "PENDING_REVIEW")
        self.assertEqual(info["criteria_evidence"]["hardware"]["state"], "UNVERIFIED")
        self.assertEqual(info["criteria_evidence"]["firmware"]["criteria"], FIRMWARE_CRITERION)
        self.assertEqual(info["active_firmware_installations"], [])
        self.assertFalse(info["software_asset_4"]["installed_on_hardware"])
        pending = self.post_decision()
        self.assertEqual(pending.status_code, 201, pending.data)
        self.assertEqual(pending.data["assessment"]["status"], "PENDING_REVIEW")

    def test_hardware_confirmed_but_firmware_unverified_is_pending(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        response = self.post_decision(installation=linked)
        self.assertEqual(response.status_code, 201, response.data)
        assessment = response.data["assessment"]
        self.assertEqual(assessment["status"], "PENDING_REVIEW")
        self.assertEqual(assessment["criteria_evidence"]["hardware"]["state"], "SATISFIED")
        self.assertEqual(assessment["criteria_evidence"]["firmware"]["state"], "UNVERIFIED")

    def test_confirmed_firmware_plus_active_installation_and_confirmed_hardware_applies(self):
        confirmed = self.confirm_hardware_cpe()
        linked = self.link()
        response = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(response.status_code, 201, response.data)
        data = response.data["assessment"]
        self.assertEqual(data["status"], "APPLIES")
        self.assertEqual(data["criteria_evidence"]["hardware"]["asset_cpe_id"], confirmed.pk)
        self.assertEqual(data["criteria_evidence"]["firmware"]["software_asset_id"], 4)
        self.assertEqual(data["criteria_evidence"]["firmware"]["display_name"],
                         "Phoenix Contact IL PN BK-PAC Firmware")
        self.assertNotIn("source", data["criteria_evidence"]["firmware"])
        self.assertNotIn("source", data["criteria_evidence"]["hardware"])
        self.assertNotIn("note", data["criteria_evidence"]["firmware"])
        self.assertEqual(data["decided_by"], self.analyst.username)
        self.assertIsNotNone(data["decided_at"])
        self.assertEqual(data["justification"], "Decisión justificada por el analista")
        self.assertIsNone(data["criteria_evidence"]["firmware"]["official_cpe_name_id"])
        self.assertEqual(Cpe.objects.count(), 1)
        self.assertEqual(AssetCpe.objects.count(), 1)
        self.assertEqual(AssetCpeDecision.objects.count(), 0)
        stored = AssetCveAssessment.objects.get()
        self.assertEqual(stored.configuration_index, 11)
        self.assertEqual(stored.configuration_snapshot["operator"], "AND")
        self.assertEqual(stored.software_installation_id, linked.pk)

    def test_firmware_approved_without_confirmed_hardware_cannot_apply(self):
        linked = self.link()
        response = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["assessment"]["status"], "PENDING_REVIEW")

    def test_software_asset_alone_never_counts_as_installed(self):
        self.confirm_hardware_cpe()
        no_install = self.post_decision(verdict="CONFIRMED")
        self.assertEqual(no_install.status_code, 400, no_install.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_unlinked_installation_cannot_confirm_firmware(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        linked.unlinked_at = timezone.now()
        linked.unlinked_by = self.analyst
        linked.save(update_fields=["unlinked_at", "unlinked_by"])
        self.assertEqual(self.context()["active_firmware_installations"], [])
        response = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_negative_verdict_requires_complete_installation_evidence(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        uncertain = self.post_decision(verdict="NOT_MATCH", installation=linked)
        self.assertEqual(uncertain.status_code, 201, uncertain.data)
        self.assertEqual(uncertain.data["assessment"]["status"], "PENDING_REVIEW")
        rejected = self.post_decision(verdict="NOT_MATCH", installation=linked,
                                      complete=True,
                                      justification="Inspección completa: otro firmware instalado")
        self.assertEqual(rejected.status_code, 201, rejected.data)
        self.assertEqual(rejected.data["assessment"]["status"], "NOT_APPLICABLE")

    def test_negative_one_of_two_installed_firmwares_does_not_exclude_others(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        other_asset = Asset.objects.create(
            name="Second firmware", asset_type="SOFTWARE",
            created_by=self.analyst, updated_by=self.analyst,
        )
        other_sw = Software.objects.create(
            asset=other_asset, software_type="FIRMWARE", manufacturer="Second",
            product="Different Firmware", version="1.0",
        )
        self.link(software=other_sw)
        response = self.post_decision(verdict="NOT_MATCH", installation=linked, complete=True)
        self.assertEqual(response.status_code, 400)
        pending = self.post_decision(verdict="NOT_MATCH", installation=linked)
        self.assertEqual(pending.status_code, 201, pending.data)
        self.assertEqual(pending.data["assessment"]["status"], "PENDING_REVIEW")

    def test_wrong_hardware_relation_and_software_type_cannot_be_used(self):
        self.confirm_hardware_cpe()
        other_asset = Asset.objects.create(
            name="Other device", asset_type="HARDWARE",
            created_by=self.analyst, updated_by=self.analyst,
        )
        other_hw = Hardware.objects.create(asset=other_asset, model="Other", role="OTHER")
        foreign = self.link(hardware=other_hw)
        response = self.post_decision(verdict="CONFIRMED", installation=foreign)
        self.assertEqual(response.status_code, 400)
        self.firmware.software_type = "APPLICATION"
        self.firmware.save(update_fields=["software_type"])
        linked = self.link()
        response = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(response.status_code, 400)

    def test_identity_change_invalidates_existing_decision_but_keeps_history(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        approved = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(approved.status_code, 201, approved.data)
        self.firmware.version = "2.1"
        self.firmware.save(update_fields=["version"])
        info = self.context()
        self.assertTrue(info["latest_assessment"]["stale"])
        self.assertEqual(info["latest_assessment"]["status"], "APPLIES")
        self.assertEqual(info["latest_assessment"]["effective_status"], "PENDING_REVIEW")
        self.assertEqual(AssetCveAssessment.objects.count(), 1)

    def test_revoking_hardware_cpe_makes_prior_assessment_stale(self):
        assoc = self.confirm_hardware_cpe()
        linked = self.link()
        result = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(result.status_code, 201, result.data)
        assoc.validation_status = AssetCpe.Validation.REJECTED
        assoc.save(update_fields=["validation_status"])
        info = self.context()
        self.assertFalse(info["hardware_cpe_confirmed"])
        self.assertTrue(info["latest_assessment"]["stale"])
        self.assertEqual(info["latest_assessment"]["effective_status"], "PENDING_REVIEW")

    def test_unimplemented_nvd_version_bounds_prevent_false_applies(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        configs = self.cve.configurations
        configs[11]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "1.0"
        self.cve.configurations = configs
        self.cve.save(update_fields=["configurations"])
        response = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["assessment"]["status"], "PENDING_REVIEW")
        evidence = response.data["assessment"]["criteria_evidence"]["firmware"]
        self.assertEqual(evidence["version_check"], "REQUIRES_REVIEW")

    def test_updated_nvd_configuration_invalidates_old_evaluation(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        result = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(result.status_code, 201, result.data)
        configs = self.cve.configurations
        configs[11]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "3.0"
        self.cve.configurations = configs
        self.cve.save(update_fields=["configurations"])
        info = self.context()
        self.assertTrue(info["latest_assessment"]["stale"])
        self.assertNotEqual(info["configuration_fingerprint"],
                            info["latest_assessment"]["configuration_fingerprint"])

    def test_stale_fingerprint_rejected_without_saving_decision(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        info = self.context()
        self.firmware.version = "3.0"
        self.firmware.save(update_fields=["version"])
        result = self.client.post(self.url, {
            "firmware_verdict": "CONFIRMED", "software_installation_id": linked.pk,
            "justification": "Vieja evidencia", "inventory_fingerprint": info["inventory_fingerprint"],
            "configuration_fingerprint": info["configuration_fingerprint"],
        }, format="json")
        self.assertEqual(result.status_code, 400)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_append_only_history_and_not_nvd_global_applicability(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        first = self.post_decision(verdict="UNKNOWN", installation=linked)
        second = self.post_decision(verdict="CONFIRMED", installation=linked)
        self.assertEqual(first.status_code, 201, first.data)
        self.assertEqual(second.status_code, 201, second.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
        info = self.context()
        self.assertEqual(len(info["history"]), 2)
        self.assertEqual(info["latest_assessment"]["status"], "APPLIES")
        self.assertEqual(info["configuration_position"], 12)
        self.assertEqual(len(self.cve.configurations), 18)

    def test_analyst_and_admin_can_write_operator_read_only(self):
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        self.assertEqual(self.client.post(self.url, {}, format="json").status_code, 403)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.client.get(self.url).status_code, 401)

    def test_no_other_hardware_or_cve_allowed(self):
        self.assertEqual(self.client.get(
            "/api/vulnerabilities/assets/5/cve-assessments/CVE-2021-33540/"
        ).status_code, 404)
        self.assertEqual(self.client.get(
            "/api/vulnerabilities/assets/2/cve-assessments/CVE-2021-11111/"
        ).status_code, 404)

    def test_obsolete_source_is_ignored_and_old_json_preserved(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        response = self.post_decision(
            verdict="CONFIRMED", installation=linked, evidence_source="SIMULATION"
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn("source", response.data["assessment"]["criteria_evidence"]["firmware"])
        record = AssetCveAssessment.objects.get()
        legacy = record.criteria_evidence
        legacy["firmware"]["source"] = "DOCUMENTATION"
        legacy["firmware"]["note"] = "Nota antigua"
        legacy["hardware"]["source"] = "CONFIRMED_CPE"
        record.criteria_evidence = legacy
        record.save(update_fields=["criteria_evidence"])
        history = self.context()["history"][0]
        self.assertNotIn("source", history["criteria_evidence"]["hardware"])
        self.assertNotIn("source", history["criteria_evidence"]["firmware"])
        self.assertNotIn("note", history["criteria_evidence"]["firmware"])
        self.assertEqual(history["decided_by"], self.analyst.username)
        self.assertIsNotNone(history["decided_at"])
        record.refresh_from_db()
        self.assertEqual(record.criteria_evidence["firmware"]["source"], "DOCUMENTATION")

    def test_reversing_firmware_decision_keeps_original_audit_row(self):
        self.confirm_hardware_cpe()
        linked = self.link()
        first = self.post_decision(verdict="CONFIRMED", installation=linked)
        second = self.post_decision(
            verdict="NOT_MATCH", installation=linked, complete=True,
            justification="Tras inspección se descartó el firmware"
        )
        self.assertEqual(first.status_code, 201, first.data)
        self.assertEqual(second.status_code, 201, second.data)
        self.assertEqual(first.data["assessment"]["status"], "APPLIES")
        self.assertEqual(second.data["assessment"]["status"], "NOT_APPLICABLE")
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
        history = self.context()["history"]
        self.assertEqual(history[0]["status"], "NOT_APPLICABLE")
        self.assertEqual(history[1]["status"], "APPLIES")
        self.assertTrue(all(row["decided_by"] == self.analyst.username for row in history))

    def test_undo_returns_to_pending_without_asserting_not_applicable(self):
        self.confirm_hardware_cpe()
        installation = self.link()
        confirmed = self.post_decision(verdict="CONFIRMED", installation=installation)
        undone = self.post_decision(
            verdict="UNKNOWN", installation=installation,
            justification="Retiro la correspondencia hasta una nueva inspección"
        )
        self.assertEqual(confirmed.status_code, 201, confirmed.data)
        self.assertEqual(undone.status_code, 201, undone.data)
        self.assertEqual(confirmed.data["assessment"]["status"], "APPLIES")
        self.assertEqual(undone.data["assessment"]["status"], "PENDING_REVIEW")
        self.assertEqual(undone.data["assessment"]["criteria_evidence"]["firmware"]["state"],
                         "UNVERIFIED")
        current = self.context()
        self.assertEqual(current["latest_assessment"]["effective_status"], "PENDING_REVIEW")
        self.assertEqual([record["status"] for record in current["history"][:2]],
                         ["PENDING_REVIEW", "APPLIES"])
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
        self.assertEqual(Cpe.objects.count(), 1)
        self.assertEqual(AssetCpe.objects.count(), 1)
