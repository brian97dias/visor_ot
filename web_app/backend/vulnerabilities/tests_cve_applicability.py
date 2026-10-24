"""Phase 1: automatic positives need verified NVD paths; no negative automation."""
from django.test import SimpleTestCase

from vulnerabilities.services.cve_applicability import (
    automatic_positive_evidence, resolve_applicability,
)
from vulnerabilities.services.cve_configuration_evaluator import (
    COMPATIBLE, EXCLUDED, INDETERMINATE, evaluate_configurations,
)
from vulnerabilities.tests_cve_contextualization import (
    CPU_HW, CPU_FW_CRITERION, PLCSIM_FW, PLCSIM_HW, STEP7,
    installed, nvd_platform_firmware,
)


class AutomaticApplicabilityProofTests(SimpleTestCase):
    def test_siemens_1215c_with_452_proves_a_positive_branch(self):
        config = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.6.0"
        )
        result = evaluate_configurations([config], [CPU_HW], installed())
        evidence = automatic_positive_evidence(result)
        self.assertEqual(result["result"], COMPATIBLE)
        self.assertEqual(evidence["configuration_position"], 1)
        self.assertEqual(len(evidence["criteria"]), 2)
        firmware = [row for row in evidence["criteria"] if row["vulnerable"]][0]
        self.assertEqual(firmware["installed_version"], "4.5.2")
        self.assertEqual(firmware["software_asset_id"], 25)
        self.assertEqual(firmware["software_installation_id"], 5)
        self.assertEqual(
            resolve_applicability(result["result"], "PENDING_REVIEW",
                                  automatic_evidence=evidence),
            {"status": "APPLIES", "source": "SYSTEM"},
        )

    def test_negative_technical_result_cannot_automatically_mark_no_aplica(self):
        old = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.5.2"
        )
        result = evaluate_configurations([old], [CPU_HW], installed())
        self.assertEqual(result["result"], EXCLUDED)
        self.assertIsNone(automatic_positive_evidence(result))
        self.assertEqual(resolve_applicability(
            result["result"], "PENDING_REVIEW",
            automatic_evidence=None,
        ), {"status": "PENDING_REVIEW", "source": "NONE"})

    def test_cpe_version_na_must_not_become_automatic_positive(self):
        criterion = CPU_FW_CRITERION.replace(":*:", ":-:", 1)
        config = nvd_platform_firmware(CPU_HW, criterion)
        result = evaluate_configurations([config], [CPU_HW], installed())
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertIsNone(automatic_positive_evidence(result))

    def test_external_step7_not_installed_requires_review(self):
        config = {"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [
                {"criteria": CPU_HW, "vulnerable": False},
            ]},
            {"operator": "OR", "cpeMatch": [
                {"criteria": STEP7, "vulnerable": True},
            ]},
        ]}
        result = evaluate_configurations([config], [CPU_HW], installed())
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertIsNone(automatic_positive_evidence(result))

    def test_plcsim_alternative_does_not_block_verified_cpu_1215c(self):
        nvd = [nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
               for _ in range(96)]
        nvd[8] = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.6.0"
        )
        result = evaluate_configurations(nvd, [CPU_HW], installed())
        proof = automatic_positive_evidence(result)
        self.assertEqual(proof["configuration_position"], 9)
        self.assertEqual(proof["configuration_index"], 8)

    def test_negated_criterion_never_becomes_auto_positive(self):
        config = {"operator": "OR", "negate": True, "cpeMatch": [
            {"criteria": PLCSIM_HW, "vulnerable": True},
        ]}
        evaluated = evaluate_configurations([config], [CPU_HW], installed())
        self.assertEqual(evaluated["result"], COMPATIBLE)
        self.assertIsNone(automatic_positive_evidence(evaluated))
        self.assertEqual(resolve_applicability(
            evaluated["result"], "PENDING_REVIEW",
            automatic_evidence=None,
        )["status"], "PENDING_REVIEW")

    def test_platform_only_is_not_a_vulnerable_component(self):
        config = {"operator": "OR", "cpeMatch": [
            {"criteria": CPU_HW, "vulnerable": False},
        ]}
        result = evaluate_configurations([config], [CPU_HW], installed())
        self.assertEqual(result["result"], COMPATIBLE)
        self.assertIsNone(automatic_positive_evidence(result))

    def test_unverified_and_branch_does_not_create_automatic_positive(self):
        config = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.6.0"
        )
        result = evaluate_configurations([config], [CPU_HW], installed(confirmed=False))
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertIsNone(automatic_positive_evidence(result))

    def test_valid_manual_decision_retains_distinct_origin(self):
        self.assertEqual(resolve_applicability(
            COMPATIBLE, "NOT_APPLICABLE", automatic_evidence={"criteria": []}),
            {"status": "NOT_APPLICABLE", "source": "ANALYST"},
        )
        self.assertEqual(resolve_applicability(
            INDETERMINATE, "APPLIES", automatic_evidence=None,
        ), {"status": "APPLIES", "source": "ANALYST"})

    def test_human_in_progress_or_stale_is_not_final_auto_negative(self):
        self.assertEqual(resolve_applicability(
            EXCLUDED, "IN_REVIEW",
        ), {"status": "IN_REVIEW", "source": "NONE"})
        self.assertEqual(resolve_applicability(
            EXCLUDED, "STALE",
        ), {"status": "STALE", "source": "NONE"})
