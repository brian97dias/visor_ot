"""Phase D: full HTTP -> live inventory -> CVE -> communications -> PDF regression.

Uses the real data collector and ReportLab renderer against SQLite fixtures,
rather than replacing their return values with an artificial JSON contract.
No NVD HTTP calls, persistent PDFs or background jobs should be created.
"""
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from assets.models import (
    Asset, NetworkInterface, OTSystem, SoftwareInstallation, SystemMembership,
)
from ingestion.models import (
    CommunicationObservation, Ingestion, InterfaceObservation,
)
from network.models import Communication
from vulnerabilities.models import (
    AssetCpe, AssetCveAssessment, AssetCveFinding, Cpe, CpeSearchRun,
    Cve, CveDiscoveryRun,
)
from vulnerabilities.services.hardening_pdf import render_hardening_pdf
from vulnerabilities import tests_hardening_diagnostic_network as _fixtures


SNAPSHOT_MODELS = (
    Asset, NetworkInterface, OTSystem, SoftwareInstallation, SystemMembership,
    Ingestion, InterfaceObservation, Communication, CommunicationObservation,
    AssetCpe, AssetCveAssessment, AssetCveFinding, Cpe, CpeSearchRun,
    Cve, CveDiscoveryRun,
)


class HardeningFullRegressionTests(TestCase):
    """Real collector, real network aggregation, real PDF, real HTTP view."""

    def _ingestion(self, prefix, status):
        # The reused fixture calls self._ingestion() during setUp().
        return _fixtures.DiagnosticCommunicationTests._ingestion(
            self, prefix, status
        )

    def setUp(self):
        # Reuse the proven Siemens CPE, firmware and active/excluded PCAP fixture.
        _fixtures.DiagnosticCommunicationTests.setUp(self)
        # A real NVD-style CVSS 3.1 source, without calling an external API.
        self.cve.description = "Packets targeting TCP/102 can cause denial of service."
        self.cve.descriptions = [
            {"lang": "en", "value": self.cve.description},
            {"lang": "es", "value": "Paquetes dirigidos a TCP/102 pueden provocar denegación de servicio."},
        ]
        self.cve.metrics = {"cvssMetricV31": [{
            "type": "Primary",
            "cvssData": {
                "version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "attackVector": "NETWORK", "attackComplexity": "LOW",
                "privilegesRequired": "NONE", "userInteraction": "NONE",
                "scope": "UNCHANGED", "confidentialityImpact": "NONE",
                "integrityImpact": "NONE", "availabilityImpact": "HIGH",
            },
        }]}
        self.cve.severity = "HIGH"
        self.cve.base_score = "7.5"
        self.cve.save(update_fields=[
            "description", "descriptions", "metrics", "severity", "base_score"
        ])
        self.url = reverse("vulnerabilities:hardening-pdf-download")

    def _capture_persisted_state(self):
        # Compare entire model rows, not just counts: status/justification
        # mutations would otherwise pass a read-only regression.
        return {
            model._meta.label: list(model.objects.order_by("pk").values())
            for model in SNAPSHOT_MODELS
        }

    def _communication(self, number, count, *, ingestion=None):
        return _fixtures.DiagnosticCommunicationTests._comm(
            self, number, count, ingestion=ingestion
        )

    def _post_with_live_report(self):
        # Spy on the real renderer; capture the actual report without mocking
        # the DB collector or the report/PDF implementation.
        with patch(
            "vulnerabilities.hardening_report_views.render_hardening_pdf",
            wraps=render_hardening_pdf,
        ) as render:
            response = self.client.post(self.url)
        return response, render

    def test_live_export_preserves_every_inventory_and_evidence_row(self):
        communication = self._communication(1, 24)
        CommunicationObservation.objects.create(
            communication=communication,
            ingestion=self.excluded,
            client_ip=communication.source_ip,
            server_ip=communication.destination_ip,
            client_macs=[self.interface.mac], server_macs=None,
            transport_protocol="TCP", service_port=communication.service_port,
            packet_count=999_999,
            first_seen="2015-10-01 00:00:00",
            last_seen="2015-10-01 01:00:00",
        )
        before = self._capture_persisted_state()
        # Existing NVD modules have their own direct URL openers.
        # Neither path may be reached during a PDF export.
        with patch(
            "vulnerabilities.services.nvd_client.urlopen",
            side_effect=AssertionError("PDF must not contact NVD CPE"),
        ) as cpe_http, patch(
            "vulnerabilities.services.nvd_cve_client.urlopen",
            side_effect=AssertionError("PDF must not contact NVD CVE"),
        ) as cve_http:
            response, render = self._post_with_live_report()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", response.content[-128:])
        self.assertEqual(render.call_count, 1)
        self.assertEqual(render.call_args.kwargs["author"],
                         self.user.get_full_name().strip() or self.user.get_username())
        report = render.call_args.args[0]
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["summary"]["applicable_hardware_cve_pairs"], 1)
        self.assertEqual(report["summary"]["conditional_hardware_cve_pairs"], 0)
        device = report["diagnosis"]["prioritized_hardware"][0]
        self.assertEqual(device["hardware_id"], self.hw.pk)
        self.assertEqual(device["priority"], "P1")
        self.assertEqual(device["findings"][0]["description_es"],
                         "Paquetes dirigidos a TCP/102 pueden provocar denegación de servicio.")
        self.assertEqual(device["findings"][0]["cvss"]["version"], "3.1")
        self.assertEqual(
            [finding["cve_id"] for finding in device["findings"]],
            [self.cve.cve_id],
        )
        self.assertEqual(
            [row["id"] for row in device["attributed_communications"]],
            [communication.pk],
        )
        self.assertEqual(
            device["attributed_communications"][0]["packets_observed"], 24
        )
        self.assertEqual(report["communications"][0]["packets_observed"], 24)
        self.assertEqual(self._capture_persisted_state(), before)
        cpe_http.assert_not_called()
        cve_http.assert_not_called()

    def test_excluded_pcap_alone_does_not_appear_in_downloaded_diagnosis(self):
        self._communication(2, 123456, ingestion=self.excluded)
        before = self._capture_persisted_state()
        response, renderer = self._post_with_live_report()
        self.assertEqual(response.status_code, 200)
        report = renderer.call_args.args[0]
        self.assertEqual(report["communications"], [])
        device = report["diagnosis"]["prioritized_hardware"][0]
        self.assertEqual(device["attributed_communications"], [])
        self.assertEqual(
            device["communications_evidence_status"],
            "INSUFFICIENT_ATTRIBUTION_EVIDENCE",
        )
        self.assertEqual(self._capture_persisted_state(), before)

    def test_changed_firmware_identity_cannot_resurrect_old_positive_cve(self):
        self.sw.version = "9.9.9"
        self.sw.save(update_fields=["version"])
        before = self._capture_persisted_state()
        response, renderer = self._post_with_live_report()
        self.assertEqual(response.status_code, 200)
        report = renderer.call_args.args[0]
        self.assertEqual(report["summary"]["hardware"], 1)
        self.assertEqual(report["summary"]["applicable_hardware_cve_pairs"], 0)
        self.assertEqual(report["diagnosis"]["prioritized_hardware"], [])
        self.assertTrue(response.content.startswith(b"%PDF-"))
        self.assertEqual(self._capture_persisted_state(), before)

    def test_invalid_inventory_denies_pdf_without_mutating_evidence(self):
        self.system.criticality = "UNDEFINED"
        self.system.save(update_fields=["criticality"])
        before = self._capture_persisted_state()
        with patch(
            "vulnerabilities.hardening_report_views.render_hardening_pdf"
        ) as renderer:
            response = self.client.post(self.url)
        self.assertEqual(response.status_code, 400)
        self.assertIn("application/json", response["Content-Type"])
        self.assertNotIn("Content-Disposition", response)
        renderer.assert_not_called()
        self.assertEqual(self._capture_persisted_state(), before)

    def test_consecutive_downloads_do_not_create_persistent_report_records(self):
        before = self._capture_persisted_state()
        first = self.client.post(self.url)
        second = self.client.post(self.url)
        for response in (first, second):
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.content.startswith(b"%PDF-"))
            self.assertIn("no-store", response["Cache-Control"])
            self.assertIn("attachment;", response["Content-Disposition"])
        self.assertEqual(self._capture_persisted_state(), before)
