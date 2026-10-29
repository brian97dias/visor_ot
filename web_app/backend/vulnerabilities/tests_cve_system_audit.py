"""Persist SYSTEM positives in the existing configuration audit (no new UI/model)."""
from django.test import TestCase

from vulnerabilities import tests_cve_contextualization as fixtures
from vulnerabilities.models import AssetCveAssessment


class SystemCveAuditTests(TestCase):
    def setUp(self):
        fixtures.SiemensContextualHttpTests.setUp(self)
        self.sync_url = self.url + "automatic/"

    def test_get_is_read_only_and_auto_post_logs_same_configuration(self):
        before = self.client.get(self.url)
        self.assertEqual(before.status_code, 200, before.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
        self.assertTrue(before.data["automatic_audit_pending"])
        first = self.client.post(self.sync_url, {}, format="json")
        self.assertEqual(first.status_code, 200, first.data)
        self.assertTrue(first.data["created"])
        record = AssetCveAssessment.objects.get()
        self.assertEqual(record.status, "APPLIES")
        self.assertEqual(record.configuration_index, 8)
        self.assertIsNone(record.decided_by)
        self.assertEqual(record.criteria_evidence["origin"], "SYSTEM")
        self.assertEqual(record.software_installation_id, self.installation.pk)
        self.assertIn("4.5.2", record.justification)
        self.assertIn("4.6.0", record.justification)
        self.assertIn("CPE confirmado", record.justification)
        self.assertTrue(record.justification.startswith(
            "El sistema confirmó automáticamente"
        ))
        context = first.data["context"]
        latest = context["configurations"][8]["latest_assessment"]
        self.assertEqual(latest["status"], "APPLIES")
        self.assertEqual(latest["source"], "SYSTEM")
        self.assertEqual(latest["decided_by"], "VISOR OT")
        self.assertEqual(latest["software_display"][0]["software_name"],
                         self.sw.asset.name)
        self.assertEqual(latest["software_display"][0]["installed_version"], "4.5.2")
        self.assertEqual(context["applicability"]["source"], "SYSTEM")
        self.assertFalse(context["automatic_audit_pending"])

    def test_system_negative_records_evaluated_firmware_without_vulnerability_link(self):
        self._set_negative_siemens_range()
        before = self.client.get(self.url).data
        self.assertEqual(before["configurations"][0]["evaluated_software"][0]
                         ["software_installation_id"], self.installation.pk)
        self.client.post(self.sync_url, {}, format="json")
        record = AssetCveAssessment.objects.get(configuration_index=0)
        self.assertEqual(record.status, "NOT_APPLICABLE")
        self.assertIsNone(record.software_installation_id)
        evidence = record.criteria_evidence["evaluated_software"][0]
        self.assertEqual(evidence["software_installation_id"], self.installation.pk)
        current = self.client.get(self.url).data["configurations"][0]
        self.assertEqual(current["latest_assessment"]["evaluated_software"][0]
                         ["software_installation_id"], self.installation.pk)

    def test_automatic_negative_cannot_be_reconfirmed_but_can_be_reversed(self):
        self._set_negative_siemens_range()
        self.client.post(self.sync_url, {}, format="json")
        context = self.client.get(self.url).data
        data = {
            "configuration_index": 0,
            "configuration_fingerprint": context["configurations"][0]["fingerprint"],
            "inventory_fingerprint": context["inventory_fingerprint"],
            "verdict": "NOT_MATCH",
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": True,
            "justification": "La versión 4.5.2 está fuera del intervalo vulnerable confirmado.",
        }
        refused = self.client.post(self.url, data, format="json")
        self.assertEqual(refused.status_code, 400, refused.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
        data.update({
            "verdict": "CONDITIONAL", "software_installation_id": None,
            "technical_override_acknowledged": True,
            "justification": (
                "Se mantiene una correspondencia parcial por investigación "
                "humana de evidencia adicional fuera de los criterios NVD."
            ),
        })
        changed = self.client.post(self.url, data, format="json")
        self.assertEqual(changed.status_code, 201, changed.data)
        self.assertEqual(changed.data["assessment"]["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(AssetCveAssessment.objects.count(), 3)
        latest = self.client.get(self.url).data
        self.assertEqual(latest["technical_result"], "EXCLUDED")
        self.assertEqual(latest["applicability"]["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(latest["applicability"]["source"], "ANALYST")
        self.assertEqual(latest["configurations"][0]["latest_assessment"]
                         ["software_installation_id"], None)
        duplicate = self.client.post(self.url, data, format="json")
        self.assertEqual(duplicate.status_code, 400, duplicate.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 3)

    def test_automatic_positive_may_be_negated_only_with_explicit_acknowledgement(self):
        self.client.post(self.sync_url, {}, format="json")
        context = self.client.get(self.url).data
        base = {
            "configuration_index": 8,
            "configuration_fingerprint": context["configurations"][8]["fingerprint"],
            "inventory_fingerprint": context["inventory_fingerprint"],
            "software_installation_id": self.installation.pk,
            "justification": (
                "El analista ha verificado las condiciones del entorno y cuenta "
                "con evidencia externa para descartar esta configuración."
            ),
        }
        reaffirm = self.client.post(self.url, {**base, "verdict": "CONFIRMED"}, format="json")
        self.assertEqual(reaffirm.status_code, 400, reaffirm.data)
        unack = self.client.post(self.url, {
            **base, "verdict": "NOT_MATCH", "inventory_declared_complete": True,
        }, format="json")
        self.assertEqual(unack.status_code, 400, unack.data)
        updated = self.client.post(self.url, {
            **base, "verdict": "NOT_MATCH", "inventory_declared_complete": True,
            "technical_override_acknowledged": True,
        }, format="json")
        self.assertEqual(updated.status_code, 201, updated.data)
        self.assertEqual(updated.data["assessment"]["status"], "NOT_APPLICABLE")
        record = AssetCveAssessment.objects.order_by("-decided_at", "-pk").first()
        self.assertIsNone(record.software_installation_id)
        self.assertTrue(record.criteria_evidence["technical_override"]["acknowledged"])
        self.assertEqual(record.criteria_evidence["evaluated_software"][0]
                         ["software_installation_id"], self.installation.pk)
        # The verifiable NVD result was not mutated by the human decision.
        after = self.client.get(self.url).data
        self.assertEqual(after["technical_result"], "COMPATIBLE")
        self.assertEqual(after["configurations"][8]["latest_assessment"]["source"], "ANALYST")
        catalogue = self.client.get("/api/vulnerabilities/cves/", {
            "q": self.cve.cve_id,
        })
        self.assertEqual(catalogue.status_code, 200, catalogue.data)
        item = next(row for row in catalogue.data["results"]
                    if row["cve_id"] == self.cve.cve_id)
        self.assertEqual(item["applicability_status"], after["applicability"]["status"])
        self.assertEqual(item["applicability_source"], after["applicability"]["source"])
        linked_assets = [
            asset for related in item["related_assets"]
            for asset in related["assets"] if asset["asset_type"] == "SOFTWARE"
        ]
        self.assertFalse(linked_assets)

    def test_automatic_positive_can_be_reopened_as_conditional_without_link(self):
        self.client.post(self.sync_url, {}, format="json")
        current = self.client.get(self.url).data
        data = {
            "configuration_index": 8, "verdict": "CONDITIONAL",
            "software_installation_id": None,
            "technical_override_acknowledged": True,
            "justification": (
                "La identificación automática se mantiene como evidencia, "
                "pero el analista requiere comprobar una condición adicional."
            ),
            "inventory_fingerprint": current["inventory_fingerprint"],
            "configuration_fingerprint": current["configurations"][8]["fingerprint"],
        }
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["assessment"]["status"], "APPLIES_CONDITIONAL")
        record = AssetCveAssessment.objects.order_by("-decided_at", "-pk").first()
        self.assertIsNone(record.software_installation_id)
        self.assertTrue(record.criteria_evidence["technical_override"]["acknowledged"])
        result = self.client.get(self.url).data
        self.assertEqual(result["technical_result"], "COMPATIBLE")
        self.assertEqual(result["applicability"]["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(result["applicability"]["source"], "ANALYST")
        self.assertEqual(AssetCveAssessment.objects.count(), 2)

    def test_system_audit_history_shows_product_version_and_keeps_snapshot(self):
        self._set_negative_siemens_range()
        self.client.post(self.sync_url, {}, format="json")
        recorded = AssetCveAssessment.objects.get(configuration_index=0)
        snapshot = recorded.criteria_evidence["software_snapshot"][0]
        self.assertEqual(snapshot["software_installation_id"], self.installation.pk)
        self.assertEqual(snapshot["software_name"], self.sw.asset.name)
        self.assertEqual(snapshot["installed_version"], "4.5.2")
        self.assertIn(self.sw.asset.name, recorded.justification)
        self.assertNotIn("instalación #" + str(self.installation.pk), recorded.justification)
        history = self.client.get(self.url).data["configurations"][0]["history"][0]
        self.assertEqual(history["software_display"][0]["software_name"],
                         self.sw.asset.name)
        self.assertEqual(history["software_display"][0]["installed_version"], "4.5.2")

        # The old decision keeps its original software/version even after
        # inventory changes invalidate its current technical conclusion.
        self.sw.version = "4.6.0"
        self.sw.save(update_fields=["version"])
        stale = self.client.get(self.url).data["configurations"][0]["history"][0]
        self.assertTrue(stale["stale"])
        self.assertEqual(stale["software_display"][0]["installed_version"], "4.5.2")
        self.assertEqual(stale["software_display"][0]["software_name"],
                         snapshot["software_name"])

    def test_manual_discrepancy_records_software_snapshot_without_vulnerable_fk(self):
        self.client.post(self.sync_url, {}, format="json")
        context = self.client.get(self.url).data
        payload = {
            "configuration_index": 8,
            "configuration_fingerprint": context["configurations"][8]["fingerprint"],
            "inventory_fingerprint": context["inventory_fingerprint"],
            "verdict": "NOT_MATCH",
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": True,
            "technical_override_acknowledged": True,
            "justification": (
                "El analista verificó documentación externa y registró una "
                "evaluación negativa independiente de la conclusión NVD."
            ),
        }
        result = self.client.post(self.url, payload, format="json")
        self.assertEqual(result.status_code, 201, result.data)
        self.assertEqual(result.data["assessment"]["status"], "NOT_APPLICABLE")
        self.assertIsNone(result.data["assessment"]["software_installation_id"])
        sw = result.data["assessment"]["software_display"][0]
        self.assertEqual(sw["software_name"], self.sw.asset.name)
        self.assertEqual(sw["installed_version"], "4.5.2")
        self.assertEqual(sw["software_installation_id"], self.installation.pk)
        self.assertEqual(AssetCveAssessment.objects.order_by("-pk").first()
                         .criteria_evidence["software_snapshot"][0], sw)

    def test_hardware_wide_analyst_negative_unlinks_every_automatic_finding(self):
        """A human no-match is for Hardware-CVE, not just NVD branch #9."""
        self.client.post(self.sync_url, {}, format="json")
        before = self.client.get(self.url).data
        payload = {
            "configuration_index": 8, "verdict": "NOT_MATCH",
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": False,
            "technical_override_acknowledged": True,
            "justification": "Revisado.",
            "inventory_fingerprint": before["inventory_fingerprint"],
            "configuration_fingerprint": before["configurations"][8]["fingerprint"],
        }
        saved = self.client.post(self.url, payload, format="json")
        self.assertEqual(saved.status_code, 201, saved.data)
        record = AssetCveAssessment.objects.order_by("-pk").first()
        self.assertEqual(record.status, "NOT_APPLICABLE")
        self.assertIsNone(record.software_installation_id)
        self.assertEqual(record.criteria_evidence["decision_scope"], "HARDWARE_CVE")
        self.assertFalse(record.criteria_evidence["inventory_declared_complete"])
        after = self.client.get(self.url).data
        self.assertEqual(after["technical_result"], "COMPATIBLE")
        self.assertEqual(after["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(after["applicability"]["source"], "ANALYST")
        self.assertEqual(after["hardware_cve_decision"]["id"], record.pk)
        listing = self.client.get("/api/vulnerabilities/cves/", {
            "q": self.cve.cve_id,
        }).data
        item = next(row for row in listing["results"]
                    if row["cve_id"] == self.cve.cve_id)
        self.assertEqual(item["applicability_status"], "NOT_APPLICABLE")
        related_software = [
            row for group in item["related_assets"]
            for row in group["assets"] if row["asset_type"] == "SOFTWARE"
        ]
        self.assertEqual(related_software, [])
        again = self.client.post(self.sync_url, {}, format="json")
        self.assertFalse(again.data["created"])
        self.assertEqual(self.client.get(self.url).data["applicability"]
                         ["status"], "NOT_APPLICABLE")

    def test_hardware_wide_partial_removes_confirmed_firmware_association(self):
        self.client.post(self.sync_url, {}, format="json")
        context = self.client.get(self.url).data
        payload = {
            "configuration_index": 8,
            "configuration_fingerprint": context["configurations"][8]["fingerprint"],
            "inventory_fingerprint": context["inventory_fingerprint"],
            "verdict": "CONDITIONAL",
            # Even if a frontend submits an installation ID, the conditional
            # state may not persist it as an active vulnerability association.
            "software_installation_id": self.installation.pk,
            "technical_override_acknowledged": True,
            "justification": "Por revisar",
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["assessment"]["status"], "APPLIES_CONDITIONAL")
        record = AssetCveAssessment.objects.order_by("-pk").first()
        self.assertIsNone(record.software_installation_id)
        self.assertEqual(record.criteria_evidence["decision_scope"], "HARDWARE_CVE")
        after = self.client.get(self.url).data
        self.assertEqual(after["applicability"]["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(after["applicability"]["source"], "ANALYST")
        listing = self.client.get("/api/vulnerabilities/cves/", {
            "q": self.cve.cve_id,
        }).data
        item = next(row for row in listing["results"]
                    if row["cve_id"] == self.cve.cve_id)
        self.assertEqual(item["applicability_status"], "APPLIES_CONDITIONAL")
        self.assertFalse(any(
            row["asset_type"] == "SOFTWARE"
            for group in item["related_assets"] for row in group["assets"]
        ))

    def test_manual_firmware_version_na_can_be_confirmed_by_matching_cpu_model(self):
        """No confirmed software CPE: the analyst may use documented evidence."""
        self.cve.configurations = [
            fixtures.nvd_platform_firmware(
                fixtures.CPU_HW,
                "cpe:2.3:o:siemens:simatic_s7-1200_cpu_1215c_firmware:-:*:*:*:*:*:*:*"
            )
        ]
        self.cve.save(update_fields=["configurations"])
        context = self.client.get(self.url).data
        config = context["relevant_configurations"][0]
        self.assertEqual(config["hardware_scope"], "MATCHED")
        self.assertEqual(config["manual_firmware_installation_ids"],
                         [self.installation.pk])
        self.assertTrue(config["manual_confirm_supported"])
        self.assertEqual(context["applicability"]["status"], "PENDING_REVIEW")
        payload = {
            "configuration_index": 0,
            "configuration_fingerprint": config["fingerprint"],
            "inventory_fingerprint": context["inventory_fingerprint"],
            "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "justification": "SSA",
        }
        saved = self.client.post(self.url, payload, format="json")
        self.assertEqual(saved.status_code, 201, saved.data)
        self.assertEqual(saved.data["assessment"]["status"], "APPLIES")
        self.assertEqual(self.client.get(self.url).data["applicability"]["source"],
                         "ANALYST")
        record = AssetCveAssessment.objects.get()
        manual = record.criteria_evidence["manual_identity_evidence"]
        self.assertFalse(manual["software_cpe_confirmed"])
        self.assertFalse(manual["version_verified_from_nvd"])
        self.assertEqual(record.software_installation_id, self.installation.pk)

    def test_manual_firmware_confirmation_rejects_different_cpu_product(self):
        self.cve.configurations = [fixtures.nvd_platform_firmware(
            fixtures.CPU_HW,
            "cpe:2.3:o:siemens:simatic_s7-1500_cpu_1515_firmware:*:*:*:*:*:*:*:*",
        )]
        self.cve.save(update_fields=["configurations"])
        context = self.client.get(self.url).data
        config = context["relevant_configurations"][0]
        self.assertEqual(config["manual_firmware_installation_ids"], [])
        bad = self.client.post(self.url, {
            "configuration_index": 0, "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "inventory_fingerprint": context["inventory_fingerprint"],
            "configuration_fingerprint": config["fingerprint"],
            "justification": "Producto diferente",
        }, format="json")
        self.assertEqual(bad.status_code, 400, bad.data)
        self.assertIn("verdict", bad.data)

    def test_repeating_automatic_sync_never_duplicates(self):
        first = self.client.post(self.sync_url, {}, format="json")
        second = self.client.post(self.sync_url, {}, format="json")
        self.assertTrue(first.data["created"])
        self.assertFalse(second.data["created"])
        self.assertEqual(first.data["assessment_id"], second.data["assessment_id"])
        self.assertEqual(AssetCveAssessment.objects.count(), 1)
        listing = self.client.get("/api/vulnerabilities/cves/", {
            "status": "APPLIES", "technical": "ALL",
        })
        self.assertEqual(listing.data["count"], 1)
        self.assertEqual(listing.data["results"][0]["applicability_source"], "SYSTEM")

    def test_automatic_positive_cannot_be_manually_reconfirmed(self):
        before = self.client.get(self.url).data
        payload = {
            "configuration_index": 8, "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "justification": "Reconfirmación sin cambio.",
            "inventory_fingerprint": before["inventory_fingerprint"],
            "configuration_fingerprint": before["configurations"][8]["fingerprint"],
        }
        posted = self.client.post(self.url, payload, format="json")
        self.assertEqual(posted.status_code, 400, posted.data)
        self.assertIn("verdict", posted.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
        sync = self.client.post(self.sync_url, {}, format="json")
        self.assertEqual(sync.status_code, 200, sync.data)
        self.assertTrue(sync.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 1)
        self.assertEqual(sync.data["context"]["applicability"]["source"], "SYSTEM")

    def test_manual_reopen_on_current_evidence_is_respected(self):
        self.client.post(self.sync_url, {}, format="json")
        context = self.client.get(self.url).data
        undone = self.client.post(self.url, {
            "configuration_index": 8, "verdict": "UNKNOWN",
            "software_installation_id": None,
            "inventory_declared_complete": False,
            "justification": "Reabro esta configuración para investigar adicionalmente.",
            "inventory_fingerprint": context["inventory_fingerprint"],
            "configuration_fingerprint": context["configurations"][8]["fingerprint"],
        }, format="json")
        self.assertEqual(undone.status_code, 201, undone.data)
        retry = self.client.post(self.sync_url, {}, format="json")
        self.assertFalse(retry.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
        latest = AssetCveAssessment.objects.order_by("-decided_at", "-pk").first()
        self.assertEqual(latest.status, "PENDING_REVIEW")
        self.assertIsNone(latest.software_installation_id)
        previous = AssetCveAssessment.objects.exclude(pk=latest.pk).get()
        self.assertEqual(previous.status, "APPLIES")
        self.assertEqual(previous.software_installation_id, self.installation.pk)
        self.assertEqual(retry.data["context"]["configurations"][8]["latest_assessment"]["source"],
                         "ANALYST")

    def test_unknown_external_software_never_creates_automatic_assessment(self):
        from vulnerabilities.tests_cve_contextualization import CPU_HW, STEP7
        self.cve.configurations = [{"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [
                {"criteria": CPU_HW, "vulnerable": False}]},
            {"operator": "OR", "cpeMatch": [
                {"criteria": STEP7, "vulnerable": True}]},
        ]}]
        self.cve.save(update_fields=["configurations"])
        result = self.client.post(self.sync_url, {}, format="json")
        self.assertEqual(result.status_code, 200, result.data)
        self.assertFalse(result.data["created"])
        self.assertIsNone(result.data["assessment_id"])
        self.assertEqual(result.data["context"]["applicability"]["status"], "PENDING_REVIEW")
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_version_outside_range_never_writes_negative_assessment(self):
        self.sw.version = "4.6.0"
        self.sw.save(update_fields=["version"])
        result = self.client.post(self.sync_url, {}, format="json")
        self.assertEqual(result.status_code, 200, result.data)
        self.assertFalse(result.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def _set_negative_siemens_range(self, *, unknown=False):
        from vulnerabilities.tests_cve_contextualization import (
            CPU_HW, CPU_FW_CRITERION, PLCSIM_HW, PLCSIM_FW,
            STEP7, nvd_platform_firmware,
        )
        excluded = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.5.2", after="4.5.0"
        )
        other = (nvd_platform_firmware(CPU_HW, STEP7)
                 if unknown else nvd_platform_firmware(
                     PLCSIM_HW, PLCSIM_FW, before="5.0"))
        self.cve.configurations = [excluded, other]
        self.cve.save(update_fields=["configurations"])

    def test_verified_negative_firmware_logs_system_no_aplica_globally(self):
        self._set_negative_siemens_range()
        context = self.client.get(self.url).data
        self.assertEqual(context["technical_result"], "EXCLUDED")
        self.assertEqual(context["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(context["applicability"]["source"], "SYSTEM")
        self.assertTrue(context["automatic_audit_pending"])
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
        first = self.client.post(self.sync_url, {}, format="json")
        self.assertEqual(first.status_code, 200, first.data)
        self.assertTrue(first.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
        self.assertFalse(first.data["context"]["automatic_audit_pending"])
        decisions = list(AssetCveAssessment.objects.order_by("configuration_index"))
        self.assertTrue(all(item.status == "NOT_APPLICABLE" for item in decisions))
        self.assertTrue(all(item.decided_by_id is None for item in decisions))
        self.assertTrue(all(item.criteria_evidence["origin"] == "SYSTEM"
                            for item in decisions))
        self.assertEqual(
            decisions[0].criteria_evidence["negative_evidence"]["excluded_by"][0]
            ["installed_version"], "4.5.2"
        )
        self.assertIn("antes de (excluido) 4.5.2", decisions[0].justification)
        history = first.data["context"]["configurations"][0]["history"][0]
        self.assertEqual(history["source"], "SYSTEM")
        self.assertEqual(history["negative_evidence"]["excluded_by"][0]["installed_version"], "4.5.2")
        second = self.client.post(self.sync_url, {}, format="json")
        self.assertFalse(second.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 2)

    def test_partial_negative_is_audited_without_global_no_aplica(self):
        self._set_negative_siemens_range(unknown=True)
        before = self.client.get(self.url).data
        self.assertEqual(before["technical_result"], "INDETERMINATE")
        self.assertEqual(before["applicability"]["status"], "PENDING_REVIEW")
        self.assertTrue(before["automatic_audit_pending"])
        result = self.client.post(self.sync_url, {}, format="json")
        self.assertTrue(result.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 1)
        row = AssetCveAssessment.objects.get()
        self.assertEqual(row.configuration_index, 0)
        self.assertEqual(row.status, "NOT_APPLICABLE")
        self.assertEqual(result.data["context"]["applicability"]["status"],
                         "PENDING_REVIEW")
        self.assertFalse(result.data["context"]["automatic_audit_pending"])

    def test_manual_override_of_negative_is_not_replaced_by_system(self):
        self._set_negative_siemens_range()
        before = self.client.get(self.url).data
        self.assertTrue(before["configurations"][0]["technical_override_supported"])
        payload = {
            "configuration_index": 0, "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "technical_override_acknowledged": True,
            "justification": (
                "Se registra una asociación manual preventiva y documentada "
                "aunque la versión esté excluida de la configuración NVD."
            ),
            "inventory_fingerprint": before["inventory_fingerprint"],
            "configuration_fingerprint": before["configurations"][0]["fingerprint"],
        }
        saved = self.client.post(self.url, payload, format="json")
        self.assertEqual(saved.status_code, 201, saved.data)
        self.assertEqual(saved.data["assessment"]["status"], "APPLIES")
        sync = self.client.post(self.sync_url, {}, format="json")
        self.assertEqual(sync.status_code, 200, sync.data)
        decision = AssetCveAssessment.objects.filter(
            configuration_index=0
        ).order_by("-decided_at", "-pk").first()
        self.assertEqual(decision.status, "APPLIES")
        self.assertIsNotNone(decision.decided_by_id)
        self.assertTrue(decision.criteria_evidence["technical_override"]["acknowledged"])
        self.assertEqual(sync.data["context"]["technical_result"], "EXCLUDED")
        self.assertEqual(sync.data["context"]["applicability"]["status"], "APPLIES")
        self.assertEqual(sync.data["context"]["applicability"]["source"], "ANALYST")

    def test_manual_reopening_negative_evidence_prevents_system_overwrite(self):
        self._set_negative_siemens_range()
        self.client.post(self.sync_url, {}, format="json")
        before = self.client.get(self.url).data
        payload = {
            "configuration_index": 0, "verdict": "UNKNOWN",
            "software_installation_id": None,
            "inventory_declared_complete": False,
            "justification": "Reabrir la exclusión técnica y revisar nueva evidencia.",
            "inventory_fingerprint": before["inventory_fingerprint"],
            "configuration_fingerprint": before["configurations"][0]["fingerprint"],
        }
        posted = self.client.post(self.url, payload, format="json")
        self.assertEqual(posted.status_code, 201, posted.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 3)
        retry = self.client.post(self.sync_url, {}, format="json")
        self.assertFalse(retry.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 3)
        self.assertEqual(retry.data["context"]["applicability"]["status"], "IN_REVIEW")

    def test_version_change_invalidates_previous_automatic_negative(self):
        self._set_negative_siemens_range()
        self.client.post(self.sync_url, {}, format="json")
        self.sw.version = "4.5.3"
        self.sw.save(update_fields=["version"])
        current = self.client.get(self.url).data
        self.assertNotEqual(current["applicability"]["status"], "NOT_APPLICABLE")
        self.assertTrue(current["configurations"][0]["latest_assessment"]["stale"])

    def test_new_current_positive_after_nvd_update_is_a_new_audit(self):
        first = self.client.post(self.sync_url, {}, format="json")
        self.assertTrue(first.data["created"])
        changed = self.cve.configurations
        changed[8]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "4.7.0"
        self.cve.configurations = changed
        self.cve.save(update_fields=["configurations"])
        second = self.client.post(self.sync_url, {}, format="json")
        self.assertEqual(second.status_code, 200, second.data)
        self.assertTrue(second.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
        history = second.data["context"]["configurations"][8]["history"]
        self.assertFalse(history[0]["stale"])
        self.assertTrue(history[1]["stale"])
