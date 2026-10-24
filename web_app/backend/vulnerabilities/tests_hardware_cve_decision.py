"""Phase 2: analyst decisions for the whole hardware/CVE with external evidence."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from vulnerabilities.models import AssetCveAssessment, HardwareCveDecision
from vulnerabilities import tests_cve_contextualization as fixtures


class WholeHardwareCveDecisionTests(TestCase):
    def setUp(self):
        fixtures.SiemensContextualHttpTests.setUp(self)
        self.decision_url = self.url.replace("/assessment/", "/decision/")

    def payload(self, *, verdict="APPLIES", override=False):
        current = self.client.get(self.url).data
        return {
            "verdict": verdict,
            "justification": "Verifiqué el alcance de la vulnerabilidad en el equipo seleccionado.",
            "evidence_description": (
                "Revisión documental de SIMATIC STEP 7/TIA Portal en estación de ingeniería."
            ),
            "evidence_reference": "Informe de revisión OT — ENG-2026-15",
            "inventory_fingerprint": current["inventory_fingerprint"],
            "nvd_fingerprint": current["hardware_review"]["nvd_fingerprint"],
            "override_confirmed_match": override,
        }

    def test_step7_external_evidence_can_confirm_without_plc_installation(self):
        self.cve.configurations = [{"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [
                {"criteria": fixtures.CPU_HW, "vulnerable": False},
            ]},
            {"operator": "OR", "cpeMatch": [
                {"criteria": fixtures.STEP7, "vulnerable": True},
            ]},
        ]}]
        self.cve.save(update_fields=["configurations"])
        before = self.client.get(self.url).data
        self.assertEqual(before["applicability"]["status"], "PENDING_REVIEW")
        response = self.client.post(self.decision_url, self.payload(), format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["decision"]["status"], "APPLIES")
        self.assertEqual(response.data["decision"]["decided_by"], self.user.username)
        refreshed = self.client.get(self.url).data
        self.assertEqual(refreshed["applicability"]["status"], "APPLIES")
        self.assertEqual(refreshed["applicability"]["source"], "ANALYST")
        self.assertIsNone(refreshed["applicability"]["automatic_evidence"])
        self.assertEqual(len(refreshed["hardware_review"]["history"]), 1)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_system_positive_needs_explicit_ack_to_record_human_no_aplica(self):
        payload = self.payload(verdict="NOT_APPLICABLE")
        refused = self.client.post(self.decision_url, payload, format="json")
        self.assertEqual(refused.status_code, 400, refused.data)
        self.assertIn("override_confirmed_match", refused.data)
        self.assertEqual(HardwareCveDecision.objects.count(), 0)
        payload["override_confirmed_match"] = True
        saved = self.client.post(self.decision_url, payload, format="json")
        self.assertEqual(saved.status_code, 201, saved.data)
        self.assertEqual(self.client.get(self.url).data["applicability"]["source"], "ANALYST")
        self.assertEqual(self.client.get(self.url).data["applicability"]["status"],
                         "NOT_APPLICABLE")
        catalogue = self.client.get("/api/vulnerabilities/cves/", {
            "status": "NOT_APPLICABLE", "technical": "ALL",
        })
        self.assertEqual(catalogue.data["count"], 1)
        self.assertEqual(catalogue.data["results"][0]["applicability_source"], "ANALYST")

    def test_decision_is_append_only_and_undo_returns_to_system_result(self):
        first = self.client.post(self.decision_url, self.payload(), format="json")
        self.assertEqual(first.status_code, 201, first.data)
        undo = self.client.post(
            self.decision_url, self.payload(verdict="PENDING_REVIEW"), format="json",
        )
        self.assertEqual(undo.status_code, 201, undo.data)
        context = self.client.get(self.url).data
        self.assertEqual(context["hardware_review"]["latest"]["status"], "PENDING_REVIEW")
        self.assertEqual(context["applicability"]["source"], "SYSTEM")
        self.assertEqual(context["applicability"]["status"], "APPLIES")
        self.assertEqual(len(context["hardware_review"]["history"]), 2)
        self.assertEqual(HardwareCveDecision.objects.count(), 2)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_new_hardware_decision_supersedes_legacy_config_result_without_deletion(self):
        context = self.client.get(self.url).data
        cfg = context["configurations"][8]
        legacy = self.client.post(self.url, {
            "configuration_index": 8,
            "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": False,
            "justification": "Evaluación histórica ligada a una configuración NVD.",
            "inventory_fingerprint": context["inventory_fingerprint"],
            "configuration_fingerprint": cfg["fingerprint"],
        }, format="json")
        self.assertEqual(legacy.status_code, 201, legacy.data)
        self.assertEqual(self.client.get(self.url).data["applicability"]["source"], "ANALYST")
        overriding = self.client.post(
            self.decision_url, self.payload(verdict="NOT_APPLICABLE", override=True),
            format="json",
        )
        self.assertEqual(overriding.status_code, 201, overriding.data)
        result = self.client.get(self.url).data
        self.assertEqual(result["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(result["applicability"]["source"], "ANALYST")
        self.assertEqual(result["configurations"][8]["latest_assessment"]["status"],
                         "APPLIES")
        self.assertEqual(self.client.get("/api/vulnerabilities/cves/", {
            "status": "NOT_APPLICABLE", "technical": "ALL",
        }).data["count"], 1)
        self.assertEqual(AssetCveAssessment.objects.count(), 1)
        self.assertEqual(HardwareCveDecision.objects.count(), 1)

    def test_inventory_update_invalidates_previous_human_verdict(self):
        self.assertEqual(self.client.post(
            self.decision_url, self.payload(), format="json",
        ).status_code, 201)
        self.sw.version = "4.6.0"
        self.sw.save(update_fields=["version"])
        context = self.client.get(self.url).data
        self.assertTrue(context["hardware_review"]["latest"]["stale"])
        self.assertEqual(context["applicability"]["status"], "STALE")
        self.assertEqual(context["applicability"]["source"], "NONE")
        self.assertEqual(self.client.get("/api/vulnerabilities/cves/", {
            "status": "STALE", "technical": "ALL"
        }).data["count"], 1)
        self.assertEqual(HardwareCveDecision.objects.count(), 1)

    def test_changed_nvd_invalidates_human_decision_and_stale_form(self):
        payload = self.payload()
        self.assertEqual(self.client.post(
            self.decision_url, payload, format="json",
        ).status_code, 201)
        self.cve.configurations.append({"operator": "OR", "cpeMatch": []})
        self.cve.save(update_fields=["configurations"])
        self.assertEqual(self.client.post(
            self.decision_url, payload, format="json",
        ).status_code, 400)
        current = self.client.get(self.url).data
        self.assertTrue(current["hardware_review"]["latest"]["stale"])
        self.assertEqual(current["hardware_review"]["history"][0]["status"], "APPLIES")
        self.assertEqual(HardwareCveDecision.objects.count(), 1)

    def test_justification_and_external_evidence_required_for_final_decisions(self):
        payload = self.payload()
        payload["evidence_description"] = ""
        self.assertEqual(self.client.post(
            self.decision_url, payload, format="json",
        ).status_code, 400)
        payload = self.payload()
        payload["justification"] = "Insuficiente"
        self.assertEqual(self.client.post(
            self.decision_url, payload, format="json",
        ).status_code, 400)
        self.assertEqual(HardwareCveDecision.objects.count(), 0)

    def test_operator_may_read_but_not_record_human_verdict(self):
        operator = get_user_model().objects.create_user(
            username="phase-2-operator", role="OPERATOR"
        )
        self.client.force_authenticate(operator)
        self.assertEqual(self.client.get(self.decision_url).status_code, 200)
        self.assertEqual(self.client.post(
            self.decision_url, self.payload(), format="json",
        ).status_code, 403)
        self.assertEqual(HardwareCveDecision.objects.count(), 0)

    def test_unrelated_hardware_cannot_receive_arbitrary_assessment(self):
        self.finding.delete()
        response = self.client.post(
            self.decision_url, self.payload(), format="json",
        )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(HardwareCveDecision.objects.count(), 0)
