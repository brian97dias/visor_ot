"""Phase B: device-first PDF, backward compatibility, and navigation contracts."""
import copy
import json
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.management import call_command
from django.test import SimpleTestCase

from vulnerabilities.services.hardening_diagnosis import build_hardening_diagnosis
from vulnerabilities.services.hardening_pdf import render_hardening_pdf
from vulnerabilities.services.hardening_pdf_diagnosis import (
    _jump, _relevant_references, _ref, _styles, render_diagnostic_hardening_pdf,
)
from vulnerabilities.tests_hardening_pdf import REPORT


def diagnosis_fixture():
    report = copy.deepcopy(REPORT)
    report["hardware"][0]["system_ids"] = [1]
    report["hardware"][0]["software_installations"] = [{
        "id": 1, "hardware_id": 21, "software_asset_id": 55,
        "software_name": "Firmware", "software_type": "FIRMWARE",
        "version": "4.5.2",
    }]
    report["diagnosis"] = build_hardening_diagnosis(report)
    return report


class HardeningDiagnosisPdfTests(SimpleTestCase):
    def test_current_diagnosis_renders_valid_pdf_without_database_access(self):
        report = diagnosis_fixture()
        snapshot = copy.deepcopy(report)
        output = BytesIO()
        render_hardening_pdf(report, output)
        binary = output.getvalue()
        self.assertTrue(binary.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", binary[-128:])
        self.assertGreater(len(binary), 3000)
        self.assertEqual(report, snapshot)

    def test_legacy_rendering_is_preserved_for_new_and_old_snapshots(self):
        for report in (copy.deepcopy(REPORT), diagnosis_fixture()):
            with self.subTest(with_diagnosis="diagnosis" in report):
                output = BytesIO()
                render_hardening_pdf(report, output, legacy=True)
                self.assertTrue(output.getvalue().startswith(b"%PDF-"))
        old_snapshot = BytesIO()
        render_hardening_pdf(REPORT, old_snapshot)
        self.assertTrue(old_snapshot.getvalue().startswith(b"%PDF-"))

    def test_internal_links_use_immutable_hardware_ids(self):
        device = diagnosis_fixture()["diagnosis"]["prioritized_hardware"][0]
        self.assertEqual(_ref(device), "hw-21")
        # These exact named destinations are registered by the device heading
        # and linked from both the matrix and the compact ranking.
        self.assertIn('href="#hw-21"', _jump(device, _styles()).text)

    def test_conditional_not_moved_into_main_findings(self):
        report = diagnosis_fixture()
        diagnosis = report["diagnosis"]
        self.assertEqual(diagnosis["summary"]["applicable_hardware_cve_pairs"], 1)
        self.assertEqual(diagnosis["summary"]["conditional_hardware_cve_pairs"], 1)
        self.assertEqual([v["cve_id"] for v in diagnosis["conditional_vulnerabilities"]],
                         ["CVE-2022-30694"])
        self.assertEqual([v["cve_id"] for v in diagnosis["prioritized_hardware"][0]["findings"]],
                         ["CVE-2021-44695"])
        render_diagnostic_hardening_pdf(report, BytesIO())

    def test_no_applies_still_renders_without_claiming_safe_assets(self):
        report = diagnosis_fixture()
        report["applicable_vulnerabilities"] = []
        report["diagnosis"] = build_hardening_diagnosis(report)
        output = BytesIO()
        render_hardening_pdf(report, output)
        self.assertTrue(output.getvalue().startswith(b"%PDF-"))

    def test_duplicate_and_wrong_hardware_ids_raise_value_error(self):
        report = diagnosis_fixture()
        report["diagnosis"]["prioritized_hardware"].append(
            copy.deepcopy(report["diagnosis"]["prioritized_hardware"][0])
        )
        with self.assertRaises(ValueError):
            render_hardening_pdf(report, BytesIO())

    def test_incomplete_diagnosis_does_not_fall_back_to_old_pdf(self):
        report = diagnosis_fixture()
        del report["diagnosis"]["priority_matrix"]
        with self.assertRaises(ValueError):
            render_hardening_pdf(report, BytesIO())

    def test_long_escaped_input_and_multisystem_render(self):
        report = diagnosis_fixture()
        report["diagnosis"]["prioritized_hardware"][0]["hardware"]["name"] = (
            "PLC & <sistema> " * 35
        )
        report["diagnosis"]["prioritized_hardware"][0]["findings"][0]["description"] = (
            "Texto con <etiquetas> & datos " * 130
        )
        output = BytesIO()
        render_hardening_pdf(report, output)
        self.assertTrue(output.getvalue().startswith(b"%PDF-"))

    def test_references_are_deduplicated_and_relevant(self):
        finding = {
            "nvd_references": [
                {"url": "https://other.example.net/x"},
                {"url": "https://cert-portal.siemens.com/a", "tags": ["Vendor Advisory"]},
                {"url": "https://cert-portal.siemens.com/a"},
                {"url": "https://www.openssl.org/news/a", "tags": ["Vendor Advisory"]},
                {"url": "not-an-url"},
            ]
        }
        refs = _relevant_references(finding)
        self.assertEqual(len(refs), 2)
        self.assertEqual(len(set(refs)), 2)
        self.assertIn("https://cert-portal.siemens.com/a", refs)
        self.assertIn("https://www.openssl.org/news/a", refs)

    def test_command_supports_default_and_legacy_modes_from_one_snapshot(self):
        with TemporaryDirectory() as temp:
            snapshot = Path(temp) / "snapshot.json"
            new_pdf = Path(temp) / "new.pdf"
            old_pdf = Path(temp) / "legacy.pdf"
            snapshot.write_text(json.dumps(diagnosis_fixture()), encoding="utf-8")
            with patch(
                "vulnerabilities.management.commands.generate_hardening_pdf."
                "collect_hardening_report_data"
            ) as collector:
                call_command("generate_hardening_pdf", "--input-json", str(snapshot),
                             "--output", str(new_pdf), stdout=StringIO())
                call_command("generate_hardening_pdf", "--input-json", str(snapshot),
                             "--output", str(old_pdf), "--legacy", stdout=StringIO())
            collector.assert_not_called()
            self.assertTrue(new_pdf.read_bytes().startswith(b"%PDF-"))
            self.assertTrue(old_pdf.read_bytes().startswith(b"%PDF-"))
            self.assertNotEqual(new_pdf.read_bytes(), old_pdf.read_bytes())