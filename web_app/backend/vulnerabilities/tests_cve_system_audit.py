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
        self.assertEqual(context["applicability"]["source"], "SYSTEM")
        self.assertFalse(context["automatic_audit_pending"])

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

    def test_manual_confirmation_is_not_duplicated_or_overridden(self):
        before = self.client.get(self.url).data
        payload = {
            "configuration_index": 8, "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": False,
            "justification": "Confirmación humana independiente de la detección automática.",
            "inventory_fingerprint": before["inventory_fingerprint"],
            "configuration_fingerprint": before["configurations"][8]["fingerprint"],
        }
        posted = self.client.post(self.url, payload, format="json")
        self.assertEqual(posted.status_code, 201, posted.data)
        sync = self.client.post(self.sync_url, {}, format="json")
        self.assertEqual(sync.status_code, 200, sync.data)
        self.assertFalse(sync.data["created"])
        self.assertEqual(AssetCveAssessment.objects.count(), 1)
        self.assertEqual(sync.data["context"]["applicability"]["source"], "ANALYST")
        self.assertEqual(sync.data["context"]["configurations"][8]["latest_assessment"]["source"],
                         "ANALYST")

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
