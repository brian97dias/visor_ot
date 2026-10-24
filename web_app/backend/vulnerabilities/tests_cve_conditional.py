"""Conditional analyst applicability uses the existing hardware/NVD audit."""
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from vulnerabilities import tests_cve_contextualization as fixtures
from vulnerabilities.models import AssetCveAssessment
from vulnerabilities.services.cve_general_assessment import general_assessment_context


class ConditionalSiemensTests(TestCase):
    def setUp(self):
        fixtures.SiemensContextualHttpTests.setUp(self)
        self.cve.configurations = [{
            "operator": "AND", "nodes": [
                {"operator": "OR", "cpeMatch": [
                    {"criteria": fixtures.CPU_HW, "vulnerable": False},
                ]},
                {"operator": "OR", "cpeMatch": [
                    {"criteria": fixtures.STEP7, "vulnerable": True},
                ]},
            ],
        }]
        self.cve.save(update_fields=["configurations"])

    def payload(self, *, software_installation_id=None, justification=None):
        current = self.client.get(self.url).data
        return {
            "configuration_index": 0, "verdict": "CONDITIONAL",
            "inventory_fingerprint": current["inventory_fingerprint"],
            "configuration_fingerprint": current["configurations"][0]["fingerprint"],
            "justification": justification or (
                "Se mantiene el CVE bajo gestión condicionada: plataforma CPU "
                "identificada, falta comprobar el uso y configuración histórica "
                "de STEP 7/TIA Portal."
            ),
            "software_installation_id": software_installation_id,
        }

    def test_step7_not_in_inventory_can_be_recorded_without_firmware_link(self):
        before = self.client.get(self.url).data
        self.assertEqual(before["applicability"]["status"], "PENDING_REVIEW")
        self.assertEqual(before["configurations"][0]["candidate_installation_ids"], [])
        self.assertTrue(before["configurations"][0]["conditional_supported"])
        recorded = self.client.post(self.url, self.payload(), format="json")
        self.assertEqual(recorded.status_code, 201, recorded.data)
        self.assertEqual(recorded.data["assessment"]["status"], "APPLIES_CONDITIONAL")
        audit = AssetCveAssessment.objects.get()
        self.assertIsNone(audit.software_installation_id)
        self.assertEqual(audit.criteria_evidence["origin"], "ANALYST")
        self.assertEqual(audit.criteria_evidence["hardware_roles"][0]["role"], "PLATFORM")
        self.assertIn(fixtures.STEP7, [
            row["criteria"] for row in audit.criteria_evidence["vulnerable_criteria"]
        ])
        after = self.client.get(self.url).data
        self.assertEqual(after["applicability"]["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(after["applicability"]["source"], "ANALYST")
        self.assertEqual(after["applicability"]["hardening_category"], "CONDITIONAL")
        self.assertEqual(after["configurations"][0]["history"][0]["conditional_evidence"]["origin"],
                         "ANALYST")

    def test_catalogue_displays_only_hardware_as_platform_with_four_states(self):
        self.assertEqual(self.client.post(
            self.url, self.payload(), format="json"
        ).status_code, 201)
        result = self.client.get("/api/vulnerabilities/cves/", {
            "status": "APPLIES_CONDITIONAL",
        })
        self.assertEqual(result.status_code, 200, result.data)
        self.assertEqual(result.data["count"], 1)
        self.assertEqual(result.data["summary"], {
            "total": 1, "applies": 0, "applies_conditional": 1,
            "not_applicable": 0, "pending_review": 0, "validated": 1,
        })
        row = result.data["results"][0]
        self.assertEqual(row["applicability_source"], "ANALYST")
        self.assertEqual(row["hardening_category"], "CONDITIONAL")
        assets = row["related_assets"][0]["assets"]
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["asset_type"], "HARDWARE")
        self.assertEqual(assets[0]["role"], "PLATFORM")
        self.assertEqual(self.client.get("/api/vulnerabilities/cves/", {
            "status": "PENDING_REVIEW",
        }).data["count"], 0)

    def test_unrelated_firmware_cannot_be_linked_to_step7(self):
        refused = self.client.post(self.url, self.payload(
            software_installation_id=self.installation.pk,
        ), format="json")
        self.assertEqual(refused.status_code, 400, refused.data)
        self.assertIn("software_installation_id", refused.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_requires_specific_justification_and_hardware_match(self):
        short = self.client.post(self.url, self.payload(
            justification="Pendiente",
        ), format="json")
        self.assertEqual(short.status_code, 400, short.data)
        self.cve.configurations[0]["nodes"][0]["cpeMatch"][0]["criteria"] = (
            fixtures.PLCSIM_HW
        )
        self.cve.save(update_fields=["configurations"])
        refused = self.client.post(self.url, self.payload(), format="json")
        self.assertEqual(refused.status_code, 400, refused.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_configuration_update_marks_conditional_decision_stale(self):
        self.assertEqual(self.client.post(
            self.url, self.payload(), format="json"
        ).status_code, 201)
        self.cve.configurations[0]["nodes"][1]["cpeMatch"][0][
            "matchCriteriaId"
        ] = "updated-by-nvd"
        self.cve.save(update_fields=["configurations"])
        state = self.client.get(self.url).data
        self.assertTrue(state["configurations"][0]["history"][0]["stale"])
        self.assertNotEqual(state["applicability"]["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(AssetCveAssessment.objects.count(), 1)

    def test_hardware_only_nvd_vulnerable_needs_no_firmware_relation(self):
        self.cve.configurations = [{
            "operator": "OR", "cpeMatch": [
                {"criteria": fixtures.CPU_HW, "vulnerable": True},
            ],
        }]
        self.cve.save(update_fields=["configurations"])
        context = self.client.get(self.url).data
        self.assertEqual(context["applicability"]["status"], "APPLIES")
        self.assertEqual(context["applicability"]["source"], "SYSTEM")
        self.assertEqual(context["applicability"]["hardening_category"], "CONFIRMED")
        self.assertEqual(context["configurations"][0]["candidate_installation_ids"], [])
        self.assertEqual(self.client.post(self.url, self.payload(), format="json").status_code, 400)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
