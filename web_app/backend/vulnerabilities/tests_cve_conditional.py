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

    def test_analyst_can_mark_unresolved_software_configuration_no_corresponde(self):
        context = self.client.get(self.url).data
        data = {
            "configuration_index": 0, "verdict": "NOT_MATCH",
            "software_installation_id": None,
            "inventory_declared_complete": True,
            "justification": (
                "Revisión documentada del inventario y de las instalaciones "
                "del controlador: el software requerido no participa en este activo."
            ),
            "configuration_fingerprint": context["configurations"][0]["fingerprint"],
            "inventory_fingerprint": context["inventory_fingerprint"],
        }
        saved = self.client.post(self.url, data, format="json")
        self.assertEqual(saved.status_code, 201, saved.data)
        self.assertEqual(saved.data["assessment"]["status"], "NOT_APPLICABLE")
        record = AssetCveAssessment.objects.get()
        self.assertIsNone(record.software_installation_id)
        self.assertEqual(record.criteria_evidence["negative_scope"], "HARDWARE_CVE")
        result = self.client.get(self.url).data
        self.assertEqual(result["technical_result"], "INDETERMINATE")
        self.assertEqual(result["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(result["applicability"]["source"], "ANALYST")
        duplicate = self.client.post(self.url, data, format="json")
        self.assertEqual(duplicate.status_code, 400, duplicate.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 1)

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

    def _installed_step7_without_confirmed_cpe(self):
        application = self.fixture.make_software("STEP 7 registrado por el analista")
        application.software_type = "APPLICATION"
        application.manufacturer = "Siemens"
        application.product = "SIMATIC STEP 7"
        application.version = "17"
        application.save(update_fields=[
            "software_type", "manufacturer", "product", "version",
        ])
        installation = self.fixture.link(software=application)
        return application, installation

    def test_manual_software_link_is_conditional_without_cpe_proof(self):
        software, installation = self._installed_step7_without_confirmed_cpe()
        context = self.client.get(self.url).data
        self.assertTrue(context["configurations"][0]["conditional_supported"])
        self.assertEqual(context["configurations"][0]["candidate_installation_ids"], [])
        posted = self.client.post(self.url, self.payload(
            software_installation_id=installation.pk,
        ), format="json")
        self.assertEqual(posted.status_code, 201, posted.data)
        self.assertEqual(posted.data["assessment"]["status"], "APPLIES_CONDITIONAL")
        record = AssetCveAssessment.objects.get()
        self.assertIsNone(record.software_installation_id)
        self.assertEqual(record.criteria_evidence["decision_scope"], "HARDWARE_CVE")
        self.assertEqual(record.criteria_evidence.get("linked_software"), None)
        linked = record.criteria_evidence["reviewed_software"]
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0]["software_asset_id"], software.pk)
        self.assertEqual(linked[0]["link_source"], "ANALYST_DISCRETION")
        self.assertIsNone(linked[0]["matched_cpe"])
        self.assertIsNone(linked[0]["criteria"])
        self.assertEqual(linked[0]["candidate_nvd_criteria"], [fixtures.STEP7])
        self.assertFalse(linked[0]["identity_verified"])
        self.assertFalse(linked[0]["version_verified"])
        result = self.client.get(self.url).data
        self.assertIsNone(result["configurations"][0]["latest_assessment"]
                          ["software_installation_id"])
        self.assertEqual(result["applicability"]["status"], "APPLIES_CONDITIONAL")

    def test_unchecked_software_link_remains_empty_even_when_installed(self):
        self._installed_step7_without_confirmed_cpe()
        posted = self.client.post(self.url, self.payload(), format="json")
        self.assertEqual(posted.status_code, 201, posted.data)
        record = AssetCveAssessment.objects.get()
        self.assertIsNone(record.software_installation_id)
        self.assertEqual(record.criteria_evidence.get("linked_software"), None)
        self.assertEqual(record.criteria_evidence["reviewed_software"], [])

    def test_discretionary_link_cannot_use_non_installed_software(self):
        software = self.fixture.make_software("STEP 7 sin instalacion")
        software.software_type = "APPLICATION"
        software.save(update_fields=["software_type"])
        rejected = self.client.post(self.url, self.payload(
            software_installation_id=999999,
        ), format="json")
        self.assertEqual(rejected.status_code, 400, rejected.data)
        self.assertIn("software_installation_id", rejected.data)
        self.assertFalse(AssetCveAssessment.objects.exists())

    def test_manual_association_stales_when_software_identity_changes(self):
        application, installation = self._installed_step7_without_confirmed_cpe()
        self.assertEqual(self.client.post(self.url, self.payload(
            software_installation_id=installation.pk,
        ), format="json").status_code, 201)
        application.version = "18"
        application.save(update_fields=["version"])
        reread = self.client.get(self.url).data
        self.assertTrue(reread["configurations"][0]["latest_assessment"]["stale"])
        self.assertNotEqual(
            reread["applicability"]["status"], "APPLIES_CONDITIONAL"
        )

    def test_unrelated_firmware_cannot_be_linked_to_step7(self):
        refused = self.client.post(self.url, self.payload(
            software_installation_id=self.installation.pk,
        ), format="json")
        self.assertEqual(refused.status_code, 400, refused.data)
        self.assertIn("software_installation_id", refused.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_short_justification_allowed_but_hardware_identity_enforced(self):
        short = self.client.post(self.url, self.payload(
            justification="Pendiente",
        ), format="json")
        self.assertEqual(short.status_code, 201, short.data)
        self.cve.configurations[0]["nodes"][0]["cpeMatch"][0]["criteria"] = (
            fixtures.PLCSIM_HW
        )
        self.cve.save(update_fields=["configurations"])
        refused = self.client.post(self.url, self.payload(), format="json")
        self.assertEqual(refused.status_code, 400, refused.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 1)

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

    def test_negated_nvd_condition_is_not_eligible_for_conditional_decision(self):
        self.cve.configurations[0]["nodes"][1]["negate"] = True
        self.cve.save(update_fields=["configurations"])
        before = self.client.get(self.url).data
        self.assertFalse(before["configurations"][0]["conditional_supported"])
        response = self.client.post(self.url, self.payload(), format="json")
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def _excluded_firmware_config(self):
        self.cve.configurations[0]["nodes"][1]["cpeMatch"] = [{
            "criteria": fixtures.CPU_FW_CRITERION,
            "vulnerable": True, "versionEndExcluding": "4.5.2",
        }]
        self.cve.save(update_fields=["configurations"])

    def test_technical_exclusion_requires_explicit_human_acknowledgement(self):
        self._excluded_firmware_config()
        info = self.client.get(self.url).data
        self.assertEqual(info["configurations"][0]["technical_result"], "EXCLUDED")
        self.assertTrue(info["configurations"][0]["conditional_supported"])
        self.assertTrue(info["configurations"][0]["technical_override_supported"])
        rejected = self.client.post(self.url, self.payload(), format="json")
        self.assertEqual(rejected.status_code, 400, rejected.data)
        self.assertIn("technical_override_acknowledged", rejected.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_analyst_may_conditionally_manage_excluded_firmware_without_link(self):
        self._excluded_firmware_config()
        payload = self.payload()
        payload["technical_override_acknowledged"] = True
        saved = self.client.post(self.url, payload, format="json")
        self.assertEqual(saved.status_code, 201, saved.data)
        self.assertEqual(saved.data["assessment"]["status"], "APPLIES_CONDITIONAL")
        record = AssetCveAssessment.objects.get()
        self.assertIsNone(record.software_installation_id)
        self.assertTrue(record.criteria_evidence["technical_override"]["acknowledged"])
        self.assertEqual(record.criteria_evidence["technical_override"]["technical_result"],
                         "EXCLUDED")
        read = self.client.get(self.url).data
        self.assertEqual(read["technical_result"], "EXCLUDED")
        self.assertEqual(read["applicability"]["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(read["applicability"]["source"], "ANALYST")

    def test_analyst_can_confirm_excluded_firmware_but_technical_stays_excluded(self):
        self._excluded_firmware_config()
        payload = self.payload(software_installation_id=self.installation.pk)
        payload["verdict"] = "CONFIRMED"
        payload["technical_override_acknowledged"] = True
        saved = self.client.post(self.url, payload, format="json")
        self.assertEqual(saved.status_code, 201, saved.data)
        self.assertEqual(saved.data["assessment"]["status"], "APPLIES")
        record = AssetCveAssessment.objects.get()
        self.assertEqual(record.software_installation_id, self.installation.pk)
        self.assertEqual(record.criteria_evidence["linked_software"][0]["link_source"],
                         "ANALYST_OVERRIDE")
        self.assertFalse(record.criteria_evidence["linked_software"][0]["version_verified"])
        self.assertEqual(record.criteria_evidence["technical_override"]["analyst_verdict"],
                         "CONFIRMED")
        read = self.client.get(self.url).data
        self.assertEqual(read["technical_result"], "EXCLUDED")
        self.assertEqual(read["applicability"]["status"], "APPLIES")
        self.assertEqual(read["applicability"]["source"], "ANALYST")
        self.assertTrue(read["configurations"][0]["history"][0][
            "technical_override"]["acknowledged"])

    def test_manual_override_must_use_actual_installed_software(self):
        self._excluded_firmware_config()
        payload = self.payload(software_installation_id=999999)
        payload["technical_override_acknowledged"] = True
        rejected = self.client.post(self.url, payload, format="json")
        self.assertEqual(rejected.status_code, 400, rejected.data)
        self.assertIn("software_installation_id", rejected.data)
        self.assertFalse(AssetCveAssessment.objects.exists())
