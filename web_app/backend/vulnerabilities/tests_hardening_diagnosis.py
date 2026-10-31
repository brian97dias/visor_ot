"""Phase A: independent tests of device-oriented report projections.

Run with SQLite test settings. The JSON projection is pure, while network
tests reuse actual Django consolidation/endpoint-resolution models.
"""
import copy
import json

from django.test import SimpleTestCase, TestCase

from vulnerabilities.services.hardening_diagnosis import (
    build_hardening_diagnosis, extract_nvd_cvss,
)


def report_fixture():
    hardware = [{
        "id": hid, "name": f"Equipment {hid}",
        "criticality": "MEDIUM", "system_ids": [1],
        "interfaces": [], "software_installations": [], "confirmed_cpes": [],
    } for hid in range(1, 25)]
    hardware[9].update(name="Siemens S7-1200", criticality="HIGH",
                       system_ids=[1, 2])
    hardware[1].update(name="Phoenix Contact", criticality="LOW")
    findings = [{
        "hardware_id": 10, "hardware_name": "Siemens S7-1200",
        "cve_id": f"CVE-2021-{40000 + i}",
        "applicability_status": "APPLIES",
        "applicability_source": "SYSTEM",
        "severity": "HIGH" if i == 1 else "MEDIUM",
        "cvss_base_score": "7.5" if i == 1 else "5.5",
        "justifications": [], "evaluated_software": [],
    } for i in range(1, 6)]
    findings.append({
        "hardware_id": 2, "hardware_name": "Phoenix Contact",
        "cve_id": "CVE-2021-33540",
        "applicability_status": "APPLIES",
        "applicability_source": "ANALYST",
        "severity": "HIGH", "cvss_base_score": "7.3",
        "justifications": [{"justification": "Es el CVE"}],
    })
    return {
        "schema_version": 1,
        "summary": {"confirmed_cpes": 7},
        "hardware": hardware,
        "software": [],
        "systems": [
            {"id": 1, "name": "Sistema 4SICS"},
            {"id": 2, "name": "Sistema de prueba"},
        ],
        "applicable_vulnerabilities": findings,
        "conditional_vulnerabilities": [{
            "hardware_id": 10, "cve_id": "CVE-2022-30694",
            "applicability_status": "APPLIES_CONDITIONAL",
            "applicability_source": "ANALYST", "justifications": [],
        }],
        "communications": [],
    }


class DeviceDiagnosisProjectionTests(SimpleTestCase):
    def test_experimental_24_hardware_two_devices_six_pairs_one_conditional(self):
        data = report_fixture()
        original = copy.deepcopy(data)
        diagnosis = build_hardening_diagnosis(data)
        counts = diagnosis["summary"]
        self.assertEqual(counts["active_hardware"], 24)
        self.assertEqual(counts["hardware_with_applicable_cves"], 2)
        self.assertEqual(counts["hardware_without_identified_applies"], 22)
        self.assertEqual(counts["applicable_hardware_cve_pairs"], 6)
        self.assertEqual(counts["conditional_hardware_cve_pairs"], 1)
        self.assertEqual(counts["priority_counts"]["P1"], 1)
        self.assertEqual(counts["priority_counts"]["P2"], 1)
        self.assertEqual(counts["priority_counts"]["P3"], 0)
        self.assertEqual([(d["hardware_id"], d["priority"], d["applicable_cve_count"])
                          for d in diagnosis["prioritized_hardware"]],
                         [(10, "P1", 5), (2, "P2", 1)])
        self.assertEqual(diagnosis["prioritized_hardware"][0]["device_ref"], "HW-10")
        self.assertEqual(data, original, "La proyección no debe mutar el contrato legado.")
        json.dumps(diagnosis)

    def test_matrix_contains_each_device_once_even_with_multiple_systems(self):
        result = build_hardening_diagnosis(report_fixture())
        cells = [
            cell for row in result["priority_matrix"] for cell in row["cells"]
        ]
        device_ids = [hid for cell in cells for hid in cell["hardware_ids"]]
        self.assertEqual(sorted(device_ids), [2, 10])
        self.assertEqual(len(result["prioritized_systems"]), 2)
        siemens = result["prioritized_hardware"][0]
        self.assertEqual(siemens["system_ids"], [1, 2])
        self.assertEqual(len([d for d in result["prioritized_hardware"]
                              if d["hardware_id"] == 10]), 1)

    def test_priority_matrix_matches_approved_nine_distinct_rules(self):
        expected = {
            "HIGH": ["P1", "P1", "P2", "P3"],
            "MEDIUM": ["P1", "P2", "P2", "P3"],
            "LOW": ["P2", "P2", "P3", "P3"],
        }
        matrix = build_hardening_diagnosis(report_fixture())["priority_matrix"]
        for row in matrix:
            self.assertEqual(
                [cell["priority"] for cell in row["cells"]],
                expected[row["hardware_criticality"]],
            )

    def test_missing_severity_never_creates_a_priority(self):
        data = report_fixture()
        for finding in data["applicable_vulnerabilities"]:
            if finding["hardware_id"] == 2:
                finding["severity"] = "UNKNOWN"
                finding["cvss_base_score"] = None
        result = build_hardening_diagnosis(data)
        phoenix = next(d for d in result["prioritized_hardware"]
                       if d["hardware_id"] == 2)
        self.assertIsNone(phoenix["priority"])
        self.assertEqual(result["summary"]["priority_counts"]["UNCLASSIFIED"], 1)
        self.assertIn("PRIORITY_UNCLASSIFIED",
                      [x["code"] for x in result["evidence_observations"]])

    def test_same_cve_on_multiple_devices_counts_hardware_cve_pairs(self):
        data = report_fixture()
        extra = copy.deepcopy(data["applicable_vulnerabilities"][0])
        extra["hardware_id"] = 2
        data["applicable_vulnerabilities"].append(extra)
        result = build_hardening_diagnosis(data)
        self.assertEqual(result["summary"]["hardware_with_applicable_cves"], 2)
        self.assertEqual(result["summary"]["applicable_hardware_cve_pairs"], 7)
        self.assertEqual(
            sum(d["applicable_cve_count"] for d in result["prioritized_hardware"]),
            7,
        )

    def test_conditional_and_pending_never_enter_main_priorities(self):
        data = report_fixture()
        data["applicable_vulnerabilities"].append({
            "hardware_id": 3, "cve_id": "CVE-2020-1111",
            "applicability_status": "PENDING_REVIEW", "severity": "CRITICAL",
            "cvss_base_score": "10.0",
        })
        data["conditional_vulnerabilities"].append({
            "hardware_id": 3, "cve_id": "CVE-2020-2222",
            "applicability_status": "NOT_APPLICABLE",
        })
        result = build_hardening_diagnosis(data)
        self.assertEqual(result["summary"]["hardware_with_applicable_cves"], 2)
        self.assertEqual(len(result["conditional_vulnerabilities"]), 1)
        self.assertNotIn(3, [d["hardware_id"]
                            for d in result["prioritized_hardware"]])

    def test_no_positive_findings_does_not_claim_no_vulnerabilities(self):
        data = report_fixture()
        data["applicable_vulnerabilities"] = []
        result = build_hardening_diagnosis(data)
        self.assertEqual(result["prioritized_hardware"], [])
        self.assertEqual(result["summary"]["hardware_without_identified_applies"], 24)
        self.assertEqual(result["summary"]["priority_counts"]["P1"], 0)
        self.assertEqual(result["summary"]["conditional_hardware_cve_pairs"], 1)

    def test_weak_analyst_justification_is_observation_not_modified_verdict(self):
        data = report_fixture()
        result = build_hardening_diagnosis(data)
        observations = result["evidence_observations"]
        self.assertTrue(any(o["code"] == "BRIEF_ANALYST_JUSTIFICATION"
                            and o["hardware_id"] == 2 for o in observations))
        phoenix = next(d for d in result["prioritized_hardware"]
                       if d["hardware_id"] == 2)
        self.assertEqual(phoenix["findings"][0]["justifications"][0]["justification"],
                         "Es el CVE")
        self.assertEqual(phoenix["priority"], "P2")

    def test_cvss_v31_primary_vector_and_metrics_are_kept(self):
        metrics = {"cvssMetricV31": [
            {"type": "Secondary", "cvssData": {
                "version": "3.1", "baseScore": 4.9,
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
            }},
            {"type": "Primary", "source": "nvd@nist.gov", "cvssData": {
                "version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "attackVector": "NETWORK", "attackComplexity": "LOW",
                "privilegesRequired": "NONE", "userInteraction": "NONE",
                "scope": "UNCHANGED", "availabilityImpact": "HIGH",
            }},
        ]}
        result = extract_nvd_cvss(metrics)
        self.assertEqual(result["version"], "3.1")
        self.assertEqual(result["source"], "nvd@nist.gov")
        self.assertEqual(result["base_score"], "7.5")
        self.assertEqual(result["metrics"]["attackVector"], "NETWORK")
        self.assertTrue(result["vector"].startswith("CVSS:3.1/"))

    def test_absent_cvss_metrics_are_never_invented(self):
        self.assertIsNone(extract_nvd_cvss(None))
        self.assertIsNone(extract_nvd_cvss({}))
        self.assertIsNone(extract_nvd_cvss({"cvssMetricV31": [{"cvssData": {}}]}))

    def test_conditional_version_context_is_review_not_contradiction(self):
        data = report_fixture()
        data["hardware"][9]["software_installations"] = [
            {"version": "4.5.2", "software_asset_id": 25},
        ]
        data["conditional_vulnerabilities"][0]["justifications"] = [{
            "justification": "No se sabe la versión especifica del firmware"
        }]
        result = build_hardening_diagnosis(data)
        self.assertTrue(any(
            o["code"] == "CONDITIONAL_VERSION_REVIEW"
            and o["cve_id"] == "CVE-2022-30694"
            for o in result["evidence_observations"]
        ))
        self.assertEqual(result["summary"]["conditional_hardware_cve_pairs"], 1)

    def test_hardware_tie_break_is_deterministic(self):
        data = report_fixture()
        data["hardware"][1]["criticality"] = "HIGH"
        data["applicable_vulnerabilities"][-1]["cvss_base_score"] = "7.5"
        result = build_hardening_diagnosis(data)
        self.assertEqual(result["prioritized_hardware"][0]["hardware_id"], 10)
        self.assertEqual(result["prioritized_hardware"][1]["hardware_id"], 2)
