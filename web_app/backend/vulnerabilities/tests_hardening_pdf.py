"""Phase four PDF tests with no database access or NVD HTTP."""
import copy
import json
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase
from rest_framework.exceptions import ValidationError

from vulnerabilities.services.hardening_pdf import render_hardening_pdf


REPORT = {
    "schema_version": 1,
    "generated_at": "2026-10-31T15:17:18+00:00",
    "scope": "ACTIVE_INVENTORY",
    "summary": {
        "systems": 1, "hardware": 1, "software_variants": 1,
        "network_interfaces": 1, "confirmed_cpes": 1,
        "applicable_hardware_cve_pairs": 1,
        "conditional_hardware_cve_pairs": 1,
    },
    "systems": [{"id": 1, "name": "Control <agua> & bombeo",
                 "criticality": "HIGH", "description": "Pruebas OT",
                 "hardware_ids": [21]}],
    "hardware": [{
        "id": 21, "name": "PLC & <Control>", "manufacturer": "Siemens",
        "model": "S7-1200", "role": "PLC", "criticality": "HIGH",
        "interfaces": [{"id": 4, "mac": "00:12:34:56:78:99",
                        "declared_ip": "10.0.0.2"}],
        "confirmed_cpes": [{"cpe_name": "cpe:2.3:h:siemens:s7-1200:-:*:*:*:*:*:*:*"}],
    }],
    "software": [{"id": 55, "name": "Firmware", "software_type": "FIRMWARE",
                  "version": "4.5.2", "hardware_ids": [21], "confirmed_cpes": []}],
    "communications": [{
        "source_ip": "10.0.0.2", "destination_ip": "10.0.0.3",
        "transport_protocol": "TCP", "service_port": 102,
        "service": "S7", "classification_status": "NO_AUTORIZADA",
        "packets_observed": 142, "first_seen": "2015-10-20 10:10:00",
        "last_seen": "2015-10-20 11:10:00",
        "source_resolution_status": "UNKNOWN",
        "destination_resolution_status": "AMBIGUOUS",
        "source_hardware": None, "destination_hardware": None,
    }],
    "applicable_vulnerabilities": [{
        "cve_id": "CVE-2021-44695", "hardware_id": 21,
        "hardware_name": "PLC & <Control>", "hardware_criticality": "HIGH",
        "applicability_status": "APPLIES", "applicability_source": "SYSTEM",
        "severity": "HIGH", "cvss_base_score": "7.5",
        "description": "Denegación de servicio & texto <externo>",
        "nvd_references": [{"url": "https://cert.example.org/advisories/abc?x=1&z=2"}],
        "automatic_nvd_evidence": {
            "configuration_position": 1, "criteria": [
                {"criterion": "cpe:2.3:o:siemens:s7_firmware:*:*:*:*:*:*:*:*",
                 "vulnerable": True},
            ],
        },
        "evaluated_software": [{
            "name": "Firmware", "version": "4.5.2", "role_nvd": "VULNERABLE"
        }],
    }],
    "conditional_vulnerabilities": [{
        "cve_id": "CVE-2022-30694", "hardware_id": 21,
        "hardware_name": "PLC & <Control>",
        "hardware_criticality": "HIGH",
        "applicability_status": "APPLIES_CONDITIONAL",
        "applicability_source": "ANALYST", "severity": "MEDIUM",
        "description": "Verificar condiciones.",
        "justifications": [{
            "justification": "Versión no verificada", "decided_by": "analyst",
            "decided_at": "2026-10-31T15:00:00+00:00",
        }],
        "nvd_references": [],
    }],
}


class HardeningPdfTests(SimpleTestCase):
    def test_pdf_bytes_from_contract_without_db(self):
        output = BytesIO()
        render_hardening_pdf(copy.deepcopy(REPORT), output)
        binary = output.getvalue()
        self.assertTrue(binary.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", binary[-128:])
        self.assertGreater(len(binary), 3000)

    def test_empty_sections_can_render(self):
        report = copy.deepcopy(REPORT)
        report.update(
            systems=[], hardware=[], software=[], communications=[],
            applicable_vulnerabilities=[], conditional_vulnerabilities=[],
        )
        render_hardening_pdf(report, BytesIO())

    def test_escaped_and_very_long_content(self):
        report = copy.deepcopy(REPORT)
        report["applicable_vulnerabilities"][0]["description"] = (
            "Prueba técnica & <sistema> " * 150
        )
        report["applicable_vulnerabilities"][0]["nvd_references"] = [
            {"url": "https://example.org/" + "long_fragment" * 25}
        ]
        render_hardening_pdf(report, BytesIO())

    def test_rejects_incomplete_or_wrong_schema(self):
        for report in (None, [], {}, {"schema_version": 2},
                       {"schema_version": 1}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                render_hardening_pdf(report, BytesIO())

    def test_command_generates_from_current_collector(self):
        with TemporaryDirectory() as tmp:
            pdf = Path(tmp) / "hardening.pdf"
            with patch(
                "vulnerabilities.management.commands.generate_hardening_pdf."
                "collect_hardening_report_data", return_value=copy.deepcopy(REPORT)
            ) as collector:
                call_command(
                    "generate_hardening_pdf", "--output", str(pdf),
                    stdout=StringIO(),
                )
            collector.assert_called_once_with()
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))

    def test_command_uses_snapshot_without_database(self):
        with TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "data.json"
            pdf = Path(tmp) / "report.pdf"
            json_path.write_text(json.dumps(REPORT), encoding="utf-8")
            with patch(
                "vulnerabilities.management.commands.generate_hardening_pdf."
                "collect_hardening_report_data"
            ) as collector:
                call_command(
                    "generate_hardening_pdf", "--input-json", str(json_path),
                    "--output", str(pdf), stdout=StringIO(),
                )
            collector.assert_not_called()
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))

    def test_invalid_json_does_not_overwrite_previous_report(self):
        with TemporaryDirectory() as tmp:
            pdf = Path(tmp) / "report.pdf"
            bad_json = Path(tmp) / "broken.json"
            pdf.write_bytes(b"previous report")
            bad_json.write_text("not-json", encoding="utf-8")
            with self.assertRaises(CommandError):
                call_command(
                    "generate_hardening_pdf", "--input-json", str(bad_json),
                    "--output", str(pdf), stdout=StringIO(),
                )
            self.assertEqual(pdf.read_bytes(), b"previous report")

    def test_missing_inventory_does_not_overwrite_previous_report(self):
        with TemporaryDirectory() as tmp:
            pdf = Path(tmp) / "report.pdf"
            pdf.write_bytes(b"previous report")
            with patch(
                "vulnerabilities.management.commands.generate_hardening_pdf."
                "collect_hardening_report_data",
                side_effect=ValidationError("Missing inventory"),
            ), self.assertRaises(CommandError):
                call_command("generate_hardening_pdf", "--output", str(pdf),
                             stdout=StringIO())
            self.assertEqual(pdf.read_bytes(), b"previous report")
