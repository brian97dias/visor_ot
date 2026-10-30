"""CVE-by-asset contextualization: Siemens CPU vs PLCSIM alternative.

The data below reproduces the relevant NVD *shapes*, not a downloaded copy
of all 96 configurations. The live NVD JSON is still stored unchanged.
"""
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from vulnerabilities.models import (
    AssetCveAssessment, AssetCveFinding, Cve, CveDiscoveryRun,
)
from vulnerabilities.services.cve_configuration_evaluator import (
    COMPATIBLE, EXCLUDED, INDETERMINATE, evaluate_configurations,
    SCOPE_PERTINENT, SCOPE_FOREIGN, SCOPE_UNCERTAIN, SCOPE_OUT_OF_SCOPE,
)
from vulnerabilities.services.cve_applicability import (
    automatic_negative_evidence, verified_negative_configurations,
    project_configuration_decisions, scoped_applicability,
)
from vulnerabilities.services.cve_general_assessment import (
    general_assessment_context, summarize_hardware_cve_review,
    _manual_firmware_installations,
)
from vulnerabilities.tests_cve_discovery_plan import CveDiscoveryPlanTests

CPU_HW = "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c:-:*:*:*:*:*:*:*"
CPU_FW = "cpe:2.3:o:siemens:simatic_s7-1200_cpu_1215c_firmware:4.5.2:*:*:*:*:*:*:*"
CPU_FW_CRITERION = "cpe:2.3:o:siemens:simatic_s7-1200_cpu_1215c_firmware:*:*:*:*:*:*:*:*"
PLCSIM_HW = "cpe:2.3:h:siemens:simatic_s7-plcsim_advanced:-:*:*:*:*:*:*:*"
PLCSIM_FW = "cpe:2.3:o:siemens:simatic_s7-plcsim_advanced_firmware:*:*:*:*:*:*:*:*"
STEP7 = "cpe:2.3:a:siemens:simatic_step_7:*:*:*:*:*:*:*:*"


def nvd_platform_firmware(hardware, firmware, *, before=None, after=None):
    target = {"criteria": firmware, "vulnerable": True}
    if before:
        target["versionEndExcluding"] = before
    if after:
        target["versionStartIncluding"] = after
    return {"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [target]},
        {"operator": "OR", "cpeMatch": [
            {"criteria": hardware, "vulnerable": False},
        ]},
    ]}


def nvd_2021_37205_configurations():
    """Reconstruct the 48 original NVD branches for regression testing.

    Device CPE identifiers, ordering, version windows and the standalone
    Software Controller branch are taken from the saved NVD 2.0 response.
    The supplied data remains the source of truth, not a list of UI options.
    """
    products = [
        "simatic_drive_controller_cpu_1504d_tf",
        "simatic_drive_controller_cpu_1507d_tf",
        "simatic_et_200sp_open_controller_cpu_1515sp_pc2",
        "simatic_s7-plcsim_advanced",
        "tim_1531_irc",
        None,  # A software-only branch without a hardware CPE.
        *["simatic_s7-1200_cpu_" + model for model in (
            "1211c", "1212c", "1212fc", "1214fc",
            "1214c", "1215fc", "1215c", "1217c",
        )],
        *["simatic_s7-1500_cpu_" + model for model in (
            "1510sp-1", "1510sp", "1511-1", "1511c-1", "1511f-1",
            "1511t-1", "1511tf-1", "1512c-1", "1512sp-1",
            "1512spf-1", "1513-1", "1513f-1", "1513r-1",
        )],
        "simatic_s7-1500_cpu_cpu_1513prof-2",
        "simatic_s7-1500_cpu_cpu_1513pro-2",
        *["simatic_s7-1500_cpu_" + model for model in (
            "1515-2", "1515f-2", "1515r-2", "1515t-2",
            "1515tf-2", "1516pro_f", "1516pro-2",
            "1516-3", "1516f-3", "1516t-3", "1516tf-3",
            "1517-3", "1517f-3", "1517tf-3",
            "1518-4", "1518f-4", "1518hf-4",
            "1518t-4", "1518tf-4",
        )],
    ]
    assert len(products) == 48
    cases = []
    for position, product in enumerate(products, start=1):
        if product is None:
            cases.append({"nodes": [{"operator": "OR", "cpeMatch": [{
                "vulnerable": True,
                "criteria": ("cpe:2.3:a:siemens:"
                    "simatic_s7-1500_software_controller:*:*:*:*:*:*:*:*"),
            }]}]})
            continue
        firmware = {"vulnerable": True, "criteria":
            "cpe:2.3:o:siemens:" + product + "_firmware:*:*:*:*:*:*:*:*"}
        if position in (1, 2):
            firmware["versionEndExcluding"] = "2.9.4"
        elif position == 4:
            firmware["versionEndExcluding"] = "4.0"
        elif position == 5:
            firmware["versionStartIncluding"] = "2.2"
        elif 7 <= position <= 14:
            firmware["versionStartIncluding"] = "4.5.0"
            firmware["versionEndExcluding"] = "4.5.2"
        elif position >= 15:
            firmware["versionStartIncluding"] = "2.9.2"
            firmware["versionEndExcluding"] = "2.9.4"
        alternatives = [firmware]
        if position == 4:
            alternatives.append({"vulnerable": True,
                "criteria": firmware["criteria"]})
        cases.append({"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": alternatives},
            {"operator": "OR", "cpeMatch": [{
                "vulnerable": False,
                "criteria": ("cpe:2.3:h:siemens:" +
                    product + ":-:*:*:*:*:*:*:*"),
            }]},
        ]})
    return cases


def installed(version="4.5.2", *, confirmed=True):
    return [{
        "installation_id": 5, "software_asset_id": 25,
        "software_name": "Firmware SIMATIC S7-1200 CPU 1215C",
        "software_type": "FIRMWARE", "version": version,
        "confirmed_cpes": [CPU_FW] if confirmed else [],
    }]


class HardwareCveReviewSummaryTests(SimpleTestCase):
    """A global human verdict must be conservative across all NVD alternatives."""

    @staticmethod
    def alternative(status=None, *, stale=False):
        return {
            "latest_assessment": (
                {"status": status,
                 "effective_status": "PENDING_REVIEW" if stale else status,
                 "stale": stale}
                if status else None
            ),
        }

    def test_no_analyst_decisions_is_pending_not_automatically_applicable(self):
        info = summarize_hardware_cve_review([
            self.alternative(), self.alternative(),
        ])
        self.assertEqual(info["status"], "PENDING_REVIEW")
        self.assertEqual(info["reviewed_configurations"], 0)
        self.assertEqual(info["pending_configurations"], 2)

    def test_one_confirmed_alternative_proves_only_scoped_positive(self):
        info = summarize_hardware_cve_review([
            self.alternative("APPLIES"), self.alternative(),
        ])
        self.assertEqual(info["status"], "APPLIES")
        self.assertEqual(info["confirmed_configurations"], 1)
        self.assertEqual(info["pending_configurations"], 1)

    def test_negative_does_not_exclude_the_cve_when_any_alternative_is_pending(self):
        info = summarize_hardware_cve_review([
            self.alternative("NOT_APPLICABLE"), self.alternative(),
        ])
        self.assertEqual(info["status"], "IN_REVIEW")
        self.assertEqual(info["excluded_configurations"], 1)

    def test_no_aplica_requires_every_alternative_to_be_current_and_negative(self):
        rows = [self.alternative("NOT_APPLICABLE") for _ in range(2)]
        self.assertEqual(
            summarize_hardware_cve_review(rows)["status"], "NOT_APPLICABLE"
        )
        rows[1] = self.alternative("NOT_APPLICABLE", stale=True)
        changed = summarize_hardware_cve_review(rows)
        self.assertEqual(changed["status"], "STALE")
        self.assertEqual(changed["stale_configurations"], 1)

    def test_reopened_evaluation_is_reviewed_but_no_longer_positive(self):
        info = summarize_hardware_cve_review([
            self.alternative("PENDING_REVIEW"),
        ])
        self.assertEqual(info["status"], "IN_REVIEW")
        self.assertEqual(info["reviewed_configurations"], 1)
        self.assertEqual(summarize_hardware_cve_review([])["status"], "PENDING_REVIEW")


class CveScopedProjectionTests(SimpleTestCase):
    """The catalog and hardware detail must preserve the same state contract."""

    def setUp(self):
        self.positive = evaluate_configurations(
            [nvd_platform_firmware(
                CPU_HW, CPU_FW_CRITERION, before="4.6.0",
            )], [CPU_HW], installed(),
        )
        self.negative = evaluate_configurations(
            [nvd_platform_firmware(
                CPU_HW, CPU_FW_CRITERION,
                before="4.5.2", after="4.5.0",
            )], [CPU_HW], installed(),
        )

    def test_unknown_reopening_retains_system_positive_evidence(self):
        self.assertEqual(project_configuration_decisions(
            self.positive, {0: "PENDING_REVIEW"},
        ), {"status": "APPLIES", "source": "SYSTEM"})

    def test_reopening_proved_exclusion_does_not_restore_no_aplica(self):
        self.assertEqual(project_configuration_decisions(
            self.negative, {0: "PENDING_REVIEW"},
        ), {"status": "IN_REVIEW", "source": "NONE"})

    def test_current_human_negative_and_conditional_override_their_branch(self):
        self.assertEqual(project_configuration_decisions(
            self.positive, {0: "NOT_APPLICABLE"},
        ), {"status": "NOT_APPLICABLE", "source": "ANALYST"})
        self.assertEqual(project_configuration_decisions(
            self.positive, {0: "APPLIES_CONDITIONAL"},
        ), {"status": "APPLIES_CONDITIONAL", "source": "ANALYST"})

    def test_stale_human_verdict_is_neither_current_positive_nor_negative(self):
        self.assertEqual(project_configuration_decisions(
            self.positive, {}, stale_human_evidence=True,
        ), {"status": "STALE", "source": "NONE"})
        self.assertEqual(project_configuration_decisions(
            self.negative, {}, stale_human_evidence=True,
        ), {"status": "STALE", "source": "NONE"})


class ManualFirmwareProductIdentityTests(SimpleTestCase):
    def test_firmware_model_correspondence_is_not_a_type_only_match(self):
        def leaf(part, cpe, *, matched=False):
            return {
                "kind": "CRITERION", "part": part, "criteria": cpe,
                "technical_identity": "MATCHED" if matched else "UNKNOWN",
                "vulnerable": part == "o",
            }

        cases = [
            (
                "cpe:2.3:h:phoenixcontact:il_pn_bk-pac:-:*:*:*:*:*:*:*",
                "cpe:2.3:o:phoenixcontact:il_pn_bk-pac_firmware:2.0:*:*:*:*:*:*:*",
                "Phoenix Contact", "IL PN BK-PAC Firmware",
            ),
            (
                CPU_HW, CPU_FW_CRITERION,
                "Siemens", "SIMATIC S7-1200 CPU 1215C Firmware",
            ),
        ]
        for hardware_cpe, software_cpe, manufacturer, product in cases:
            tree = {
                "kind": "GROUP", "children": [
                    leaf("h", hardware_cpe, matched=True),
                    leaf("o", software_cpe),
                ],
            }
            installation = {
                "installation_id": 5,
                "software_type": "FIRMWARE",
                "manufacturer": manufacturer,
                "product": product,
            }
            self.assertEqual(
                _manual_firmware_installations(tree, [installation]), [5],
            )
            self.assertEqual(_manual_firmware_installations(tree, [{
                **installation, "product": "Different CPU Firmware",
            }]), [])
            self.assertEqual(_manual_firmware_installations(tree, [{
                **installation, "manufacturer": "Different Vendor",
            }]), [])


class ContextualNvdConfigurationScopeTests(SimpleTestCase):
    """Phase 2: scope classification only, not the phase-3 global verdict."""

    def evaluate(self, scenarios, *, inventory=None):
        return evaluate_configurations(
            scenarios, [CPU_HW], installed() if inventory is None else inventory
        )

    def test_version_excluded_firmware_still_has_pertinent_hardware_scope(self):
        config = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.4"
        )
        result = self.evaluate([config])
        self.assertEqual(result["result"], EXCLUDED)
        scope = result["contextual_selection"]
        self.assertEqual(scope["pertinent_indexes"], [0])
        self.assertEqual(scope["foreign_indexes"], [])
        self.assertEqual(scope["uncertain_indexes"], [])
        self.assertEqual(scope["configurations"][0]["technical_result"], EXCLUDED)
        self.assertEqual(scope["configurations"][0]["relation"], SCOPE_PERTINENT)

    def test_other_confirmed_physical_controller_is_foreign(self):
        excluded = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
        result = self.evaluate([excluded])
        self.assertEqual(result["contextual_selection"]["foreign_indexes"], [0])
        self.assertEqual(result["contextual_selection"]["configurations"][0]["relation"],
                         SCOPE_FOREIGN)

    def test_family_or_unknown_hardware_never_proves_foreign(self):
        ambiguous = "cpe:2.3:h:siemens:simatic_s7-1200:-:*:*:*:*:*:*:*"
        unknown_cpu = "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1213c:-:*:*:*:*:*:*:*"
        for hardware in (ambiguous, unknown_cpu):
            with self.subTest(hardware=hardware):
                config = nvd_platform_firmware(hardware, CPU_FW_CRITERION)
                result = self.evaluate([config])
                self.assertEqual(result["contextual_selection"]["uncertain_indexes"], [0])
                self.assertEqual(result["contextual_selection"]["foreign_indexes"], [])

    def test_explicit_et200sp_pc_is_distinct_from_cpu1215c(self):
        et200sp = (
            "cpe:2.3:h:siemens:"
            "simatic_et_200sp_open_controller_cpu_1515sp_pc:-:*:*:*:*:*:*:*"
        )
        result = self.evaluate([nvd_platform_firmware(et200sp, CPU_FW_CRITERION)])
        self.assertEqual(result["contextual_selection"]["foreign_indexes"], [0])
        self.assertEqual(result["contextual_selection"]["uncertain_indexes"], [])

    def test_software_only_match_is_pertinent_but_unanchored_is_out_of_scope(self):
        application = {"operator": "OR", "cpeMatch": [{
            "criteria": STEP7, "vulnerable": True
        }]}
        self.assertEqual(
            self.evaluate([application])["contextual_selection"]["out_of_scope_indexes"],
            [0],
        )
        installed_app = [{
            "installation_id": 88, "software_asset_id": 99,
            "software_name": "STEP 7", "software_type": "APPLICATION",
            "version": "16", "confirmed_cpes": [
                STEP7.replace(":*:*:*:*:*:*:*:*", ":16:*:*:*:*:*:*:*")
            ],
        }]
        self.assertEqual(
            self.evaluate([application], inventory=installed_app)
                ["contextual_selection"]["pertinent_indexes"],
            [0],
        )

    def test_nested_or_does_not_discard_a_matching_hardware_path(self):
        other_hw = PLCSIM_HW
        condition = {"operator": "OR", "nodes": [
            {"operator": "AND", "cpeMatch": [
                {"criteria": other_hw, "vulnerable": False},
                {"criteria": STEP7, "vulnerable": True},
            ]},
            {"operator": "AND", "cpeMatch": [
                {"criteria": CPU_HW, "vulnerable": False},
                {"criteria": STEP7, "vulnerable": True},
            ]},
        ]}
        result = self.evaluate([condition])
        self.assertEqual(result["contextual_selection"]["pertinent_indexes"], [0])
        self.assertEqual(result["result"], INDETERMINATE)

    def test_and_with_proven_other_hardware_is_foreign_even_if_software_unknown(self):
        config = {"operator": "AND", "cpeMatch": [
            {"criteria": PLCSIM_HW, "vulnerable": False},
            {"criteria": STEP7, "vulnerable": True},
        ]}
        self.assertEqual(
            self.evaluate([config])["contextual_selection"]["foreign_indexes"],
            [0],
        )

    def test_nvd_negation_is_uncertain_for_scope_not_a_false_exclusion(self):
        nested = {"operator": "AND", "nodes": [
            {"operator": "OR", "negate": True, "cpeMatch": [{
                "criteria": CPU_HW, "vulnerable": False
            }]},
            {"operator": "OR", "cpeMatch": [{
                "criteria": STEP7, "vulnerable": True
            }]},
        ]}
        self.assertEqual(
            self.evaluate([nested])["contextual_selection"]["uncertain_indexes"],
            [0],
        )

    def test_cve_2019_10943_shape_keeps_other_platform_uncertainties(self):
        # Representative NVD branches, not a substitute for the stored JSON:
        # #1 unknown ET200SP model, #6 CPU1215C out of range,
        # #11 OR of incompatible Software Controller and unverified PLCSIM.
        et200sp = (
            "cpe:2.3:h:siemens:"
            "simatic_et_200sp_open_controller_cpu_1515sp_pc:-:*:*:*:*:*:*:*"
        )
        software_controller = (
            "cpe:2.3:a:siemens:"
            "simatic_s7-1500_software_controller:*:*:*:*:*:*:*:*"
        )
        plcsim_app = (
            "cpe:2.3:a:siemens:"
            "simatic_s7_plcsim_advanced:*:*:*:*:*:*:*:*"
        )
        unrelated = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW)
        configs = [unrelated for _ in range(11)]
        configs[0] = nvd_platform_firmware(et200sp, CPU_FW_CRITERION)
        configs[5] = nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION, before="4.4")
        configs[10] = {"operator": "OR", "cpeMatch": [
            {"criteria": software_controller, "vulnerable": True},
            {"criteria": plcsim_app, "vulnerable": True},
        ]}
        original = __import__("copy").deepcopy(configs)
        result = self.evaluate(configs)
        self.assertEqual(result["contextual_selection"]["pertinent_indexes"], [5])
        self.assertEqual(result["contextual_selection"]["uncertain_indexes"], [])
        self.assertEqual(result["contextual_selection"]["out_of_scope_indexes"], [10])
        self.assertEqual(len(result["contextual_selection"]["foreign_indexes"]), 9)
        self.assertEqual(result["configurations"][5]["result"], EXCLUDED)
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertEqual(result["contextual_result"], EXCLUDED)
        self.assertEqual(configs, original)

    def test_regression_cpu1215c_firmware452_positive_among_other_branches(self):
        unrelated = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW)
        pertinent = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.6.0"
        )
        configs = [unrelated for _ in range(12)]
        configs[8] = pertinent
        result = self.evaluate(configs)
        self.assertEqual(result["result"], COMPATIBLE)
        self.assertEqual(result["contextual_selection"]["pertinent_indexes"], [8])
        self.assertEqual(len(result["contextual_selection"]["foreign_indexes"]), 11)

    def test_cve_2021_37205_all_48_original_branches_keep_exact_positions(self):
        configs = nvd_2021_37205_configurations()
        result = self.evaluate(configs)
        scope = result["contextual_selection"]
        self.assertEqual(len(configs), 48)
        self.assertEqual(len(result["configurations"]), 48)
        # Positions are the original order, not an index of filtered branches.
        self.assertEqual(scope["pertinent_indexes"], [12])
        # The software-only S7-1500 Software Controller branch is known to
        # require a PC/IPC, so its platform is also foreign to a physical CPU.
        self.assertEqual(scope["uncertain_indexes"], [])
        self.assertEqual(len(scope["foreign_indexes"]), 47)
        self.assertEqual(scope["configurations"][12]["position"], 13)
        self.assertEqual(result["configurations"][12]["result"], EXCLUDED)

    def test_external_step7_requires_review_without_excluding_cpu_platform(self):
        config = {"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [
                {"criteria": CPU_HW, "vulnerable": False}
            ]},
            {"operator": "OR", "cpeMatch": [
                {"criteria": STEP7, "vulnerable": True}
            ]},
        ]}
        result = self.evaluate([config])
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertEqual(result["contextual_selection"]["pertinent_indexes"], [0])


class ContextualHardwareCveConsolidationTests(SimpleTestCase):
    """Phase 3: contextual Hardware-CVE verdict and audit-grade negative proof."""

    @staticmethod
    def evaluate(configurations, software=None):
        return evaluate_configurations(
            configurations, [CPU_HW], installed() if software is None else software,
        )

    @staticmethod
    def application(technical, configurations, analyst_status="PENDING_REVIEW"):
        cve = SimpleNamespace(
            configurations=configurations, last_modified=None, retrieved_at=None
        )
        return scoped_applicability(
            technical, analyst_status,
            inventory_fingerprint="a" * 64, cve=cve, hardware_id=10,
        )

    def test_foreign_branches_do_not_block_proven_pertinent_version_exclusion(self):
        # Matching CPU 1215C, firmware 4.5.2, vulnerable below 4.4.
        relevant = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.4"
        )
        foreign = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW)
        configs = [foreign, relevant, foreign]
        technical = self.evaluate(configs)
        self.assertEqual(technical["result"], EXCLUDED)
        self.assertEqual(technical["contextual_result"], EXCLUDED)
        scope = technical["contextual_selection"]
        self.assertEqual(scope["evaluated_indexes"], [1])
        self.assertEqual(scope["ignored_foreign_indexes"], [0, 2])
        evidence = automatic_negative_evidence(technical)
        self.assertIsNotNone(evidence)
        self.assertEqual(len(evidence["configurations"]), 1)
        self.assertEqual(evidence["configurations"][0]["configuration_index"], 1)
        self.assertEqual(evidence["foreign_configuration_indexes"], [0, 2])
        self.assertEqual(evidence["evaluated_configuration_indexes"], [1])
        verdict = self.application(technical, configs)
        self.assertEqual(verdict["status"], "NOT_APPLICABLE")
        self.assertEqual(verdict["source"], "SYSTEM")
        self.assertEqual(verdict["nvd_technical_result"], EXCLUDED)
        self.assertEqual(verdict["technical_result"], EXCLUDED)
        self.assertEqual(
            project_configuration_decisions(technical, {}),
            {"status": "NOT_APPLICABLE", "source": "SYSTEM"},
        )

    def test_foreign_vulnerable_hardware_without_negative_proof_is_not_safe(self):
        # A different identified hardware product is not by itself a proven
        # safe verdict when NVD marks that hardware itself as vulnerable.
        config = {"operator": "OR", "cpeMatch": [
            {"criteria": PLCSIM_HW, "vulnerable": True}
        ]}
        technical = self.evaluate([config])
        self.assertEqual(technical["contextual_selection"]["foreign_indexes"], [0])
        self.assertEqual(technical["contextual_result"], INDETERMINATE)
        self.assertIsNone(automatic_negative_evidence(technical))
        self.assertEqual(
            self.application(technical, [config])["status"], "PENDING_REVIEW"
        )
        self.assertEqual(
            project_configuration_decisions(technical, {})["status"],
            "PENDING_REVIEW",
        )

    def test_uncertain_hardware_family_prevents_global_negative(self):
        uncertain_hardware = (
            "cpe:2.3:h:siemens:simatic_s7-1200:-:*:*:*:*:*:*:*"
        )
        pending = nvd_platform_firmware(uncertain_hardware, CPU_FW_CRITERION)
        relevant = nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION, before="4.4")
        foreign = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW)
        configs = [pending, relevant, foreign]
        technical = self.evaluate(configs)
        self.assertEqual(technical["contextual_selection"]["uncertain_indexes"], [0])
        self.assertEqual(technical["contextual_selection"]["pertinent_indexes"], [1])
        self.assertEqual(technical["contextual_selection"]["foreign_indexes"], [2])
        self.assertEqual(technical["contextual_result"], INDETERMINATE)
        self.assertIsNone(automatic_negative_evidence(technical))
        self.assertEqual(
            self.application(technical, configs)["status"], "PENDING_REVIEW"
        )
        self.assertEqual(
            project_configuration_decisions(technical, {})["status"],
            "PENDING_REVIEW",
        )

    def test_technical_positive_preserved_with_foreign_alternatives(self):
        pertinent = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.6.0"
        )
        unrelated = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW)
        configurations = [unrelated, pertinent]
        technical = self.evaluate(configurations)
        self.assertEqual(technical["contextual_result"], COMPATIBLE)
        verdict = self.application(technical, configurations)
        self.assertEqual(verdict["status"], "APPLIES")
        self.assertEqual(verdict["source"], "SYSTEM")
        self.assertEqual(
            project_configuration_decisions(technical, {}),
            {"status": "APPLIES", "source": "SYSTEM"},
        )

    def test_manually_reviewed_pair_remains_authoritative(self):
        config = nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION, before="4.4")
        technical = self.evaluate([config])
        human = self.application(technical, [config], "APPLIES_CONDITIONAL")
        self.assertEqual(human["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(human["source"], "ANALYST")
        self.assertEqual(
            project_configuration_decisions(
                technical, {}, global_decision="APPLIES"
            ),
            {"status": "APPLIES", "source": "ANALYST"},
        )
        self.assertEqual(
            project_configuration_decisions(
                technical, {}, global_decision="PENDING_REVIEW"
            ),
            {"status": "IN_REVIEW", "source": "NONE"},
        )

    def test_empty_or_ambiguous_configurations_never_prove_no_aplica(self):
        for configurations in ([], [{"operator": "OR", "nodes": []}]):
            with self.subTest(configurations=configurations):
                technical = self.evaluate(configurations)
                self.assertEqual(technical["contextual_result"], INDETERMINATE)
                self.assertIsNone(automatic_negative_evidence(technical))
                self.assertEqual(
                    project_configuration_decisions(technical, {})["status"],
                    "PENDING_REVIEW",
                )


class SiemensContextualLogicTests(SimpleTestCase):
    def test_plcsim_is_a_verified_distinct_product_line(self):
        configuration = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
        result = evaluate_configurations([configuration], [CPU_HW], installed())
        self.assertEqual(result["result"], EXCLUDED)
        platform = result["configurations"][0]["children"][1]["children"][0]
        self.assertEqual(platform["identity"], "DISTINCT")

    def test_family_relation_requires_evidence_not_string_guess(self):
        family = "cpe:2.3:h:siemens:simatic_s7-1200:-:*:*:*:*:*:*:*"
        config = nvd_platform_firmware(family, CPU_FW_CRITERION, before="4.6.0")
        result = evaluate_configurations([config], [CPU_HW], installed())
        self.assertEqual(result["result"], INDETERMINATE)

    def test_config_nine_competes_with_95_unrelated_plcsim_alternatives(self):
        plcsim = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
        relevant = nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION, before="4.6.0")
        configs = [plcsim for _ in range(96)]
        configs[8] = relevant
        result = evaluate_configurations(configs, [CPU_HW], installed())
        self.assertEqual(result["result"], COMPATIBLE)
        self.assertEqual(result["configurations"][0]["result"], EXCLUDED)
        self.assertEqual(result["configurations"][8]["result"], COMPATIBLE)

    def test_version_can_exclude_one_or_all_relevant_configurations(self):
        old = nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION,
                                    before="3.0.0", after="2.0.0")
        newer = nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION,
                                      before="4.5.2", after="4.5.0")
        unrelated = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
        self.assertEqual(
            evaluate_configurations([old, newer, unrelated], [CPU_HW],
                                    installed())["result"], EXCLUDED,
        )
        self.assertEqual(
            evaluate_configurations([old, newer, unrelated], [CPU_HW],
                                    installed(confirmed=False))["result"],
            INDETERMINATE,
        )

    def test_unknown_step7_does_not_become_not_applicable(self):
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


class AutomaticNegativeProofTests(SimpleTestCase):
    """Negative classification requires verifiable NVD evidence, never missing assets."""

    def test_exact_upper_bound_excludes_firmware_and_distinct_platform(self):
        target = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.5.2", after="4.5.0"
        )
        other = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
        result = evaluate_configurations([target, other], [CPU_HW], installed())
        self.assertEqual(result["result"], EXCLUDED)
        proof = automatic_negative_evidence(result)
        self.assertIsNotNone(proof)
        self.assertEqual(len(proof["configurations"]), 2)
        software = proof["configurations"][0]["excluded_by"][0]
        self.assertEqual(software["reason"], "FIRMWARE_OR_SOFTWARE_VERSION_EXCLUDED")
        self.assertEqual(software["installed_version"], "4.5.2")
        self.assertEqual(software["software_installation_id"], 5)
        self.assertEqual(
            software["version_constraints"]["versionEndExcluding"], "4.5.2"
        )
        other_proof = proof["configurations"][1]["excluded_by"][0]
        self.assertEqual(other_proof["reason"], "DISTINCT_PLATFORM_VERIFIED")
        self.assertTrue(other_proof["confirmed_hardware_cpes"])

    def test_version_inside_range_is_never_automatically_excluded(self):
        vulnerable = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.5.2", after="4.5.0"
        )
        result = evaluate_configurations(
            [vulnerable], [CPU_HW], installed("4.5.1")
        )
        # A different recorded firmware version from its confirmed 4.5.2 CPE
        # must be treated as unknown rather than silently using that CPE.
        self.assertIsNone(automatic_negative_evidence(result))
        inclusive = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.6.0", after="4.5.0"
        )
        inside = evaluate_configurations([inclusive], [CPU_HW], installed())
        self.assertEqual(inside["result"], COMPATIBLE)
        self.assertIsNone(automatic_negative_evidence(inside))

    def test_one_unknown_alternative_prevents_global_no_aplica(self):
        excluded = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.5.2", after="4.5.0"
        )
        unknown = nvd_platform_firmware(CPU_HW, STEP7)
        result = evaluate_configurations([excluded, unknown], [CPU_HW], installed())
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertIsNone(automatic_negative_evidence(result))
        verified = verified_negative_configurations(result)
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0]["configuration_index"], 0)

    def test_unknown_inventory_or_vulnerable_hardware_is_not_negative_proof(self):
        target = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.5.2", after="4.5.0"
        )
        missing_cpe = evaluate_configurations(
            [target], [CPU_HW], installed(confirmed=False)
        )
        self.assertIsNone(automatic_negative_evidence(missing_cpe))
        vulnerable_hardware = {"operator": "OR", "cpeMatch": [
            {"criteria": PLCSIM_HW, "vulnerable": True},
        ]}
        technical = evaluate_configurations(
            [vulnerable_hardware], [CPU_HW], installed()
        )
        self.assertEqual(technical["result"], EXCLUDED)
        self.assertIsNone(automatic_negative_evidence(technical))

    def test_nvd_negation_never_counts_as_proven_negative(self):
        negated = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.5.2", after="4.5.0"
        )
        negated["negate"] = True
        result = evaluate_configurations([negated], [CPU_HW], installed())
        self.assertIsNone(automatic_negative_evidence(result))


class SiemensHardwareIdentityExclusions(SimpleTestCase):
    """Only confirmed, concrete and mutually exclusive Siemens CPU identities."""

    @staticmethod
    def hardware(product):
        return f"cpe:2.3:h:siemens:{product}:-:*:*:*:*:*:*:*"

    def test_distinct_s7_1200_cpu_models_exclude_platform_configuration(self):
        other = self.hardware("simatic_s7-1200_cpu_1214c")
        scenario = nvd_platform_firmware(
            other, CPU_FW_CRITERION, before="4.5.2", after="4.5.0"
        )
        evaluated = evaluate_configurations([scenario], [CPU_HW], installed())
        self.assertEqual(evaluated["result"], EXCLUDED)
        hardware = evaluated["configurations"][0]["children"][1]["children"][0]
        self.assertEqual(hardware["identity"], "DISTINCT")
        self.assertEqual(hardware["result"], EXCLUDED)
        proof = automatic_negative_evidence(evaluated)
        self.assertIsNotNone(proof)
        self.assertEqual(
            proof["configurations"][0]["excluded_by"][0]["reason"],
            "FIRMWARE_OR_SOFTWARE_VERSION_EXCLUDED",
        )
        # Even with unknown firmware, the *platform* itself excludes the AND.
        no_firmware = evaluate_configurations([scenario], [CPU_HW], [])
        self.assertEqual(no_firmware["result"], EXCLUDED)
        self.assertEqual(
            automatic_negative_evidence(no_firmware)["configurations"][0]
            ["excluded_by"][0]["reason"], "DISTINCT_PLATFORM_VERIFIED"
        )

    def test_explicit_other_cpu_family_is_distinct(self):
        s7_1500 = self.hardware("simatic_s7-1500_cpu_1515")
        scenario = nvd_platform_firmware(s7_1500, STEP7)
        assessed = evaluate_configurations([scenario], [CPU_HW], installed())
        self.assertEqual(assessed["result"], EXCLUDED)
        evidence = automatic_negative_evidence(assessed)
        self.assertEqual(evidence["configurations"][0]["excluded_by"][0]
                         ["reason"], "DISTINCT_PLATFORM_VERIFIED")

    def test_explicit_other_siemens_controller_models_are_distinct(self):
        other_models = [
            "simatic_drive_controller_cpu_1504d_tf",
            "simatic_drive_controller_cpu_1507d_tf",
            "simatic_et_200sp_open_controller_cpu_1515sp_pc2",
            "tim_1531_irc",
        ]
        for product in other_models:
            with self.subTest(product=product):
                scenario = nvd_platform_firmware(self.hardware(product), STEP7)
                technical = evaluate_configurations(
                    [scenario], [CPU_HW], installed()
                )
                self.assertEqual(technical["result"], EXCLUDED)
                self.assertEqual(
                    automatic_negative_evidence(technical)
                    ["configurations"][0]["excluded_by"][0]["reason"],
                    "DISTINCT_PLATFORM_VERIFIED",
                )


    def test_s7_1500_cpu_suffix_variants_are_distinct_platforms(self):
        for model in ("1510sp-1", "1511c-1", "1511f-1", "1511t-1",
                      "1511tf-1", "1512sp-1", "1512spf-1"):
            with self.subTest(model=model):
                other = self.hardware("simatic_s7-1500_cpu_" + model)
                scenario = nvd_platform_firmware(other, STEP7)
                result = evaluate_configurations([scenario], [CPU_HW], installed())
                self.assertEqual(result["result"], EXCLUDED)
                proof = automatic_negative_evidence(result)
                self.assertIsNotNone(proof)
                self.assertEqual(proof["configurations"][0]["excluded_by"][0]
                                 ["reason"], "DISTINCT_PLATFORM_VERIFIED")

    def test_pc_only_s7_1500_software_controller_is_platform_distinct(self):
        sw_cpe = "cpe:2.3:a:siemens:simatic_s7-1500_software_controller:*:*:*:*:*:*:*:*"
        scenario = {"operator": "OR", "cpeMatch": [
            {"criteria": sw_cpe, "vulnerable": True},
        ]}
        result = evaluate_configurations([scenario], [CPU_HW], installed())
        self.assertEqual(result["result"], EXCLUDED)
        proof = automatic_negative_evidence(result)
        self.assertIsNotNone(proof)
        self.assertEqual(proof["configurations"][0]["excluded_by"][0]
                         ["reason"], "SOFTWARE_PLATFORM_DISTINCT")
        unknown = evaluate_configurations([scenario], [], installed())
        self.assertEqual(unknown["result"], INDETERMINATE)
        self.assertIsNone(automatic_negative_evidence(unknown))
        other_app = {"operator": "OR", "cpeMatch": [
            {"criteria": STEP7, "vulnerable": True},
        ]}
        self.assertEqual(
            evaluate_configurations([other_app], [CPU_HW], installed())["result"],
            INDETERMINATE,
        )


    def test_explicit_application_cpe_conflict_is_not_auto_excluded(self):
        sw_cpe = "cpe:2.3:a:siemens:simatic_s7-1500_software_controller:*:*:*:*:*:*:*:*"
        installed_app = [{
            "installation_id": 22, "software_asset_id": 55,
            "software_name": "S7-1500 Software Controller",
            "software_type": "APPLICATION", "version": "1.0",
            "confirmed_cpes": [sw_cpe.replace(
                ":*:*:*:*:*:*:*:*", ":1.0:*:*:*:*:*:*:*",
            )],
        }]
        configuration = {"operator": "OR", "cpeMatch": [
            {"criteria": sw_cpe, "vulnerable": True},
        ]}
        result = evaluate_configurations(
            [configuration], [CPU_HW], installed_app,
        )
        self.assertEqual(result["result"], COMPATIBLE)
        self.assertIsNone(automatic_negative_evidence(result))

    def test_same_cpu_remains_matched_not_distinct(self):
        evaluated = evaluate_configurations(
            [nvd_platform_firmware(CPU_HW, STEP7)], [CPU_HW], installed()
        )
        self.assertEqual(evaluated["result"], INDETERMINATE)
        self.assertIsNone(automatic_negative_evidence(evaluated))

    def test_family_names_and_unknown_variants_never_prove_distinctness(self):
        family = self.hardware("simatic_s7-1200")
        unspecified = self.hardware("simatic_s7-1200_cpu_1213c")
        unrelated_vendor = "cpe:2.3:h:other:simatic_s7-1200_cpu_1214c:-:*:*:*:*:*:*:*"
        generic_s7_1500 = self.hardware("simatic_s7-1500_cpu_family")
        for candidate in (family, unspecified, unrelated_vendor, generic_s7_1500):
            with self.subTest(candidate=candidate):
                result = evaluate_configurations(
                    [nvd_platform_firmware(candidate, STEP7)],
                    [CPU_HW], installed()
                )
                self.assertEqual(result["result"], INDETERMINATE)
                self.assertIsNone(automatic_negative_evidence(result))

    def test_distinct_vulnerable_hardware_is_still_analyst_only(self):
        scenario = {"operator": "OR", "cpeMatch": [
            {"criteria": self.hardware("simatic_s7-1200_cpu_1214c"),
             "vulnerable": True},
        ]}
        evaluated = evaluate_configurations([scenario], [CPU_HW], installed())
        self.assertEqual(evaluated["result"], EXCLUDED)
        self.assertIsNone(automatic_negative_evidence(evaluated))


class CveCatalogueNegativeAggregationTests(SimpleTestCase):
    """A catalogue CVE spans every related hardware, not just the first."""

    @staticmethod
    def row(hardware_id, technical, *, positive=None, negative=None):
        return {
            "hardware_id": hardware_id,
            "technical_result": technical,
            "automatic_evidence": positive,
            "automatic_negative_evidence": negative,
        }

    def test_one_verified_exclusion_is_visible_in_status_and_counts(self):
        from vulnerabilities.cve_catalogue_views import _catalogue_applicability
        actual = _catalogue_applicability("PENDING_REVIEW", [
            self.row(10, EXCLUDED, negative={"configurations": [{"configuration_index": 0}]}),
        ])
        self.assertEqual(actual["status"], "NOT_APPLICABLE")
        self.assertEqual(actual["source"], "SYSTEM")

    def test_other_unknown_hardware_prevents_global_not_aplicable(self):
        from vulnerabilities.cve_catalogue_views import _catalogue_applicability
        actual = _catalogue_applicability("PENDING_REVIEW", [
            self.row(10, EXCLUDED, negative={"configurations": [{"configuration_index": 0}]}),
            self.row(11, INDETERMINATE),
        ])
        self.assertEqual(actual["status"], "PENDING_REVIEW")

    def test_all_hardware_need_verified_exclusion(self):
        from vulnerabilities.cve_catalogue_views import _catalogue_applicability
        a = self.row(10, EXCLUDED, negative={"configurations": [1]})
        b = self.row(11, EXCLUDED, negative={"configurations": [2]})
        self.assertEqual(_catalogue_applicability("PENDING_REVIEW", [a,b])["status"],
                         "NOT_APPLICABLE")
        self.assertEqual(_catalogue_applicability("PENDING_REVIEW", [
            a, self.row(11, EXCLUDED)
        ])["status"], "PENDING_REVIEW")

    def test_positive_on_any_hardware_wins_over_other_negative(self):
        from vulnerabilities.cve_catalogue_views import _catalogue_applicability
        a = self.row(10, EXCLUDED, negative={"configurations": [1]})
        b = self.row(11, COMPATIBLE, positive={"configuration_index": 0})
        self.assertEqual(_catalogue_applicability("PENDING_REVIEW", [a,b])["status"],
                         "APPLIES")

    def test_catalogue_without_linked_hardware_cannot_autodiscard(self):
        from vulnerabilities.cve_catalogue_views import _catalogue_applicability
        self.assertEqual(_catalogue_applicability("PENDING_REVIEW", [])["status"],
                         "PENDING_REVIEW")


class SiemensContextualHttpTests(TestCase):
    def setUp(self):
        fixture = CveDiscoveryPlanTests(
            methodName="test_hardware_only_cpe_is_eligible_without_firmware_cpe"
        )
        fixture.setUp()
        self.fixture = fixture
        self.hw = fixture.hardware
        self.sw = fixture.firmware
        self.user = fixture.user
        self.hw.manufacturer = "Siemens"
        self.hw.model = "SIMATIC S7-1200 CPU 1215C"
        self.hw.save(update_fields=["manufacturer", "model"])
        self.sw.manufacturer = "Siemens"
        self.sw.product = "SIMATIC S7-1200 CPU 1215C Firmware"
        self.sw.version = "4.5.2"
        self.sw.save(update_fields=["manufacturer", "product", "version"])
        fixture.confirm(self.hw.asset, CPU_HW)
        fixture.confirm(self.sw.asset, CPU_FW)
        self.installation = fixture.link()
        plcsim = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
        target = nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION, before="4.6.0")
        configs = [plcsim for _ in range(12)]
        configs[8] = target
        self.cve = Cve.objects.create(
            cve_id="CVE-2021-44695",
            fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(),
            configurations=configs,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.run = CveDiscoveryRun.objects.create(
            requested_by=self.user, selected_hardware_ids=[self.hw.pk],
            status=CveDiscoveryRun.Status.COMPLETED,
        )
        from vulnerabilities.services.cve_discovery import build_cve_discovery_plan

        plan = build_cve_discovery_plan([self.hw.pk])
        self.assertEqual(len(plan["queries"]), 1)
        self.finding = AssetCveFinding.objects.create(
            hardware=self.hw, cve=self.cve,
            first_discovery_run=self.run, last_discovery_run=self.run,
            sources=plan["queries"][0]["sources"],
            evidence_fingerprint=plan["evidence_fingerprints"][str(self.hw.pk)],
        )
        self.url = (
            "/api/vulnerabilities/cves/" + self.cve.cve_id
            + "/hardware/" + str(self.hw.pk) + "/assessment/"
        )

    def test_detail_is_one_cve_per_hardware_with_relevant_evidence_only(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        data = response.data
        self.assertEqual(data["context_unit"], "HARDWARE_CVE")
        self.assertEqual(data["technical_result"], COMPATIBLE)
        self.assertEqual(data["applicability"]["status"], "APPLIES")
        self.assertEqual(data["applicability"]["source"], "SYSTEM")
        proof = data["applicability"]["automatic_evidence"]
        self.assertEqual(proof["configuration_position"], 9)
        self.assertEqual(proof["configuration_index"], 8)
        self.assertEqual(proof["hardware_id"], self.hw.pk)
        self.assertEqual(proof["inventory_fingerprint"], data["inventory_fingerprint"])
        self.assertEqual(proof["configuration_fingerprint"],
                         data["configurations"][8]["fingerprint"])
        self.assertEqual(len(proof["criteria"]), 2)
        self.assertEqual(data["assessment_summary"]["status"], "PENDING_REVIEW")
        self.assertEqual(data["assessment_summary"]["total_configurations"], 12)
        self.assertEqual(data["assessment_summary"]["pending_configurations"], 12)
        self.assertEqual(len(data["configurations"]), 12)  # NVD preserved
        # Scope classification is a read-only projection for phase 2:
        # it does not rewrite automatic applicability (phase 3).
        scope = data["contextual_selection"]
        self.assertEqual(scope["pertinent_indexes"], [8])
        self.assertEqual(len(scope["foreign_indexes"]), 11)
        self.assertEqual(scope["uncertain_indexes"], [])
        self.assertEqual(data["configurations"][8]["contextual_scope"], SCOPE_PERTINENT)
        self.assertTrue(data["configurations"][0]["contextual_scope_reason"])
        self.assertEqual([row["position"] for row in data["relevant_configurations"]], [9])
        self.assertEqual(data["unrelated_configuration_count"], 11)
        criterion = data["relevant_configurations"][0]["tree"]["children"][0]["children"][0]
        self.assertEqual(criterion["technical_matched_cpe"], CPU_FW)
        self.assertEqual(criterion["technical_installed_version"], "4.5.2")
        self.assertEqual(criterion["technical_software_asset_id"], self.sw.pk)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)


    def test_primary_software_identity_precedes_unknown_software_on_same_hardware(self):
        verified_firmware = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, after="4.5.0", before="4.5.2"
        )
        unknown_firmware = nvd_platform_firmware(
            CPU_HW,
            "cpe:2.3:o:siemens:alternate_cpu_1215c_firmware:*:*:*:*:*:*:*:*",
            before="8.0",
        )
        self.cve.configurations = [unknown_firmware, verified_firmware]
        self.cve.save(update_fields=["configurations"])
        data = self.client.get(self.url).data
        self.assertEqual(data["technical_result"], INDETERMINATE)
        self.assertEqual(
            [row["position"] for row in data["hardware_software_configurations"]],
            [2, 1],
        )
        self.assertEqual(
            [row["technical_result"] for row in data["hardware_software_configurations"]],
            [EXCLUDED, INDETERMINATE],
        )
        self.assertEqual(
            [row["hardware_scope"] for row in data["hardware_software_configurations"]],
            ["MATCHED", "MATCHED"],
        )
        self.assertEqual(data["candidate_configurations"], [])
        self.assertEqual(data["unverified_platform_configurations"], [])

    def test_48_nvd_branches_are_excluded_for_confirmed_cpu_1215c_452(self):
        self.cve.cve_id = "CVE-2021-37205"
        self.cve.configurations = nvd_2021_37205_configurations()
        self.cve.save(update_fields=["cve_id", "configurations"])
        url = ("/api/vulnerabilities/cves/CVE-2021-37205/hardware/" +
               str(self.hw.pk) + "/assessment/")
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200, result.data)
        data = result.data
        self.assertEqual(len(data["configurations"]), 48)
        self.assertEqual(data["technical_result"], EXCLUDED)
        self.assertEqual(data["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(data["applicability"]["source"], "SYSTEM")
        self.assertEqual(data["technical_configuration_counts"], {
            "COMPATIBLE": 0, "EXCLUDED": 48, "INDETERMINATE": 0,
        })
        self.assertEqual(
            [row["position"] for row in data["hardware_software_configurations"]],
            [13],
        )
        self.assertEqual(data["candidate_configurations"], [])
        self.assertEqual(data["unverified_platform_configurations"], [])
        self.assertEqual(data["configurations"][12]["hardware_scope"], "MATCHED")
        self.assertEqual(data["configurations"][27]["hardware_scope"], "DISTINCT")
        self.assertEqual(data["configurations"][28]["hardware_scope"], "DISTINCT")
        self.assertEqual(data["configurations"][34]["hardware_scope"], "DISTINCT")
        self.assertEqual(data["configurations"][35]["hardware_scope"], "DISTINCT")
        self.assertEqual(data["configurations"][45]["hardware_scope"], "DISTINCT")
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_system_negative_audits_of_47_other_cpus_never_become_relevant(self):
        """Automatic decision history must not select an unrelated NVD CPU."""
        self.cve.cve_id = "CVE-2021-37205"
        self.cve.configurations = nvd_2021_37205_configurations()
        self.cve.save(update_fields=["cve_id", "configurations"])
        url = (
            "/api/vulnerabilities/cves/CVE-2021-37205/hardware/"
            + str(self.hw.pk) + "/assessment/"
        )
        synced = self.client.post(url + "automatic/", {}, format="json")
        self.assertEqual(synced.status_code, 200, synced.data)
        data = self.client.get(url).data
        self.assertEqual(len(data["configurations"]), 48)
        self.assertEqual(data["technical_result"], EXCLUDED)
        self.assertEqual(data["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(data["applicability"]["source"], "SYSTEM")
        self.assertTrue(any(
            row["history"] for row in data["configurations"]
            if row["position"] != 13
        ))
        self.assertEqual(
            [row["position"] for row in data["relevant_configurations"]], [13]
        )
        self.assertEqual(
            [row["position"] for row in data["hardware_software_configurations"]],
            [13],
        )
        self.assertEqual(data["unrelated_configuration_count"], 47)
        self.assertEqual(data["candidate_configurations"], [])
        self.assertEqual(data["unverified_platform_configurations"], [])
        self.assertEqual(data["configurations"][0]["hardware_scope"], "DISTINCT")

    def test_matched_standalone_software_is_relevant_without_hardware_condition(self):
        self.cve.configurations = [
            {"nodes": [{"operator": "OR", "cpeMatch": [
                {"criteria": CPU_FW_CRITERION, "vulnerable": True},
            ]}]},
            nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0"),
        ]
        self.cve.save(update_fields=["configurations"])
        data = self.client.get(self.url).data
        self.assertEqual(data["configurations"][0]["hardware_scope"], "UNSCOPED")
        self.assertEqual(
            [row["position"] for row in data["relevant_configurations"]], [1]
        )
        self.assertEqual(data["hardware_software_configurations"], [])
        self.assertEqual(data["candidate_configurations"], [])
        self.assertEqual(data["unrelated_configuration_count"], 1)

    def test_unverified_other_hardware_is_auditable_not_a_firmware_candidate(self):
        ambiguous_hw = (
            "cpe:2.3:h:siemens:simatic_s7-1500_cpu_family:-:*:*:*:*:*:*:*"
        )
        ambiguous_fw = (
            "cpe:2.3:o:siemens:simatic_s7-1500_cpu_family_firmware:*:*:*:*:*:*:*:*"
        )
        excluded = nvd_platform_firmware(
            CPU_HW, CPU_FW_CRITERION, before="4.5.2", after="4.5.0"
        )
        self.cve.configurations = [
            excluded, nvd_platform_firmware(ambiguous_hw, ambiguous_fw),
        ]
        self.cve.save(update_fields=["configurations"])
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        data = response.data
        self.assertEqual(data["technical_result"], INDETERMINATE)
        self.assertEqual(data["applicability"]["status"], "PENDING_REVIEW")
        self.assertEqual(
            [config["position"] for config in data["hardware_software_configurations"]],
            [1],
        )
        self.assertEqual(data["candidate_configurations"], [])
        self.assertEqual(
            [config["position"] for config in data["unverified_platform_configurations"]],
            [2],
        )
        ambiguous = data["unverified_platform_configurations"][0]
        self.assertFalse(ambiguous["manual_platform_review_required"])
        payload = {
            "configuration_index": 1,
            "configuration_fingerprint": ambiguous["fingerprint"],
            "inventory_fingerprint": data["inventory_fingerprint"],
            "verdict": "CONDITIONAL",
            "software_installation_id": self.installation.pk,
            "platform_unverified_acknowledged": True,
            "justification": (
                "La plataforma NVD no coincide con el equipo y se pretende "
                "vincular su firmware al hardware físico sin evidencia."
            ),
        }
        rejected = self.client.post(self.url, payload, format="json")
        self.assertEqual(rejected.status_code, 400, rejected.data)
        self.assertIn("verdict", rejected.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_unscoped_software_cannot_be_linked_without_matching_installation_cpe(self):
        unknown_fw = (
            "cpe:2.3:o:siemens:unknown_unscoped_firmware:*:*:*:*:*:*:*:*"
        )
        config = {"nodes": [{"operator": "OR", "cpeMatch": [
            {"criteria": unknown_fw, "vulnerable": True},
        ]}]}
        self.cve.configurations = [config]
        self.cve.save(update_fields=["configurations"])
        data = self.client.get(self.url).data
        self.assertEqual(data["technical_result"], INDETERMINATE)
        self.assertEqual(
            [c["position"] for c in data["candidate_configurations"]],
            [1],
        )
        row = data["candidate_configurations"][0]
        self.assertEqual(row["hardware_scope"], "UNSCOPED")
        self.assertTrue(row["manual_platform_review_required"])
        payload = {
            "configuration_index": 0,
            "configuration_fingerprint": row["fingerprint"],
            "inventory_fingerprint": data["inventory_fingerprint"],
            "verdict": "CONDITIONAL",
            "software_installation_id": self.installation.pk,
            "justification": (
                "El analista relaciona discrecionalmente el componente "
                "sin afirmar una coincidencia exacta con la identidad NVD."
            ),
        }
        rejected = self.client.post(self.url, payload, format="json")
        self.assertEqual(rejected.status_code, 400, rejected.data)
        self.assertIn("platform_unverified_acknowledged", rejected.data)
        payload["platform_unverified_acknowledged"] = True
        rejected_identity = self.client.post(self.url, payload, format="json")
        self.assertEqual(rejected_identity.status_code, 400, rejected_identity.data)
        self.assertIn("software_installation_id", rejected_identity.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_catalogue_contains_named_hardware_and_only_corresponding_firmware(self):
        response = self.client.get("/api/vulnerabilities/cves/")
        self.assertEqual(response.status_code, 200, response.data)
        row = response.data["results"][0]
        self.assertEqual(row["technical_result"], COMPATIBLE)
        self.assertEqual(row["applicability_status"], "APPLIES")
        self.assertEqual(row["applicability_source"], "SYSTEM")
        self.assertEqual(response.data["summary"], {
            "total": 1, "applies": 1, "not_applicable": 0,
            "pending_review": 0, "validated": 1, "applies_conditional": 0,
        })
        self.assertEqual(row["evaluation_status"], "PENDING_REVIEW")
        self.assertEqual(len(row["related_assets"]), 1)
        found = row["related_assets"][0]["assets"]
        self.assertEqual([item["asset_type"] for item in found],
                         ["HARDWARE", "SOFTWARE"])
        self.assertEqual(found[0]["asset_id"], self.hw.pk)
        self.assertEqual(found[1]["asset_id"], self.sw.pk)
        self.assertEqual(found[1]["version"], "4.5.2")
        self.assertEqual(found[0]["role"], "PLATFORM")
        self.assertEqual(found[1]["role"], "VULNERABLE")

    def test_contextual_result_is_shared_by_hardware_detail_and_catalogue(self):
        # Same 2019-10943 representative shape used in the pure evaluator
        # tests: two uncertain branches prevent an automatic "No aplica".
        et200sp = (
            "cpe:2.3:h:siemens:"
            "simatic_et_200sp_open_controller_cpu_1515sp_pc:-:*:*:*:*:*:*:*"
        )
        software_controller = (
            "cpe:2.3:a:siemens:"
            "simatic_s7-1500_software_controller:*:*:*:*:*:*:*:*"
        )
        plcsim_app = (
            "cpe:2.3:a:siemens:"
            "simatic_s7_plcsim_advanced:*:*:*:*:*:*:*:*"
        )
        foreign = nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW)
        configs = [foreign for _ in range(11)]
        configs[0] = nvd_platform_firmware(et200sp, CPU_FW_CRITERION)
        configs[5] = nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION, before="4.4")
        configs[10] = {"operator": "OR", "cpeMatch": [
            {"criteria": software_controller, "vulnerable": True},
            {"criteria": plcsim_app, "vulnerable": True},
        ]}
        self.cve.configurations = configs
        self.cve.save(update_fields=["configurations"])
        detail = self.client.get(self.url)
        self.assertEqual(detail.status_code, 200, detail.data)
        data = detail.data
        self.assertEqual(data["contextual_selection"]["pertinent_indexes"], [5])
        self.assertEqual(data["contextual_selection"]["uncertain_indexes"], [])
        self.assertEqual(data["contextual_selection"]["out_of_scope_indexes"], [10])
        self.assertEqual(len(data["contextual_selection"]["foreign_indexes"]), 9)
        self.assertEqual(data["configurations"][5]["technical_result"], EXCLUDED)
        self.assertEqual(data["technical_result"], EXCLUDED)
        self.assertEqual(data["nvd_technical_result"], INDETERMINATE)
        self.assertEqual(data["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(data["applicability"]["source"], "SYSTEM")
        self.assertEqual(
            data["applicability"]["automatic_evidence"]["evaluated_configuration_indexes"], [5]
        )
        self.assertEqual(
            data["applicability"]["technical_result"], data["technical_result"]
        )
        self.assertIsNone(data["applicability"]["automatic_evidence"])
        catalog = self.client.get("/api/vulnerabilities/cves/")
        self.assertEqual(catalog.status_code, 200, catalog.data)
        self.assertEqual(catalog.data["results"][0]["technical_result"],
                         data["technical_result"])
        self.assertEqual(catalog.data["results"][0]["applicability_status"],
                         data["applicability"]["status"])

    def test_version_bounded_automatic_positive_requires_a_real_human_change(self):
        context = self.client.get(self.url)
        self.assertEqual(context.status_code, 200, context.data)
        info = context.data
        row = info["relevant_configurations"][0]
        self.assertTrue(row["review_supported"])
        self.assertEqual(info["applicability"]["status"], "APPLIES")
        payload = {
            "configuration_index": 8,
            "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "justification": "Sin cambios",
            "inventory_fingerprint": info["inventory_fingerprint"],
            "configuration_fingerprint": row["fingerprint"],
        }
        reaffirm = self.client.post(self.url, payload, format="json")
        self.assertEqual(reaffirm.status_code, 400, reaffirm.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

        payload.update({
            "verdict": "CONDITIONAL",
            "software_installation_id": None,
            "technical_override_acknowledged": True,
            "justification": "Pendiente",
        })
        changed = self.client.post(self.url, payload, format="json")
        self.assertEqual(changed.status_code, 201, changed.data)
        self.assertEqual(changed.data["assessment"]["status"], "APPLIES_CONDITIONAL")
        current = self.client.get(self.url).data
        self.assertEqual(current["applicability"]["status"], "APPLIES_CONDITIONAL")
        self.assertEqual(current["applicability"]["source"], "ANALYST")
        self.assertIsNone(current["hardware_cve_decision"]["software_installation_id"])
        self.assertEqual(current["technical_result"], COMPATIBLE)
        self.assertEqual(AssetCveAssessment.objects.count(), 1)

        payload.update({
            "verdict": "UNKNOWN",
            "justification": "Reabro la revisión",
        })
        reopened = self.client.post(self.url, payload, format="json")
        self.assertEqual(reopened.status_code, 201, reopened.data)
        context = self.client.get(self.url).data
        self.assertEqual(context["applicability"]["status"], "IN_REVIEW")
        self.assertEqual(context["assessment_summary"]["status"], "IN_REVIEW")
        self.assertEqual(AssetCveAssessment.objects.count(), 2)
    def test_verified_positive_requires_documented_technical_override_for_no_match(self):
        context = self.client.get(self.url).data
        config = context["relevant_configurations"][0]
        self.assertEqual(config["technical_result"], COMPATIBLE)
        self.assertTrue(config["review_supported"])
        response = self.client.post(self.url, {
            "configuration_index": config["index"],
            "verdict": "NOT_MATCH",
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": True,
            "justification": "Intento de descartar una coincidencia técnica demostrada.",
            "inventory_fingerprint": context["inventory_fingerprint"],
            "configuration_fingerprint": config["fingerprint"],
        }, format="json")
        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn("technical_override_acknowledged", response.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_stale_analyst_partial_can_be_reopened_after_firmware_change(self):
        context = self.client.get(self.url).data
        config = context["relevant_configurations"][0]
        confirmed = self.client.post(self.url, {
            "configuration_index": config["index"],
            "verdict": "CONDITIONAL",
            "software_installation_id": None,
            "technical_override_acknowledged": True,
            "inventory_declared_complete": False,
            "justification": "Revisión parcial de la afectación del firmware.",
            "inventory_fingerprint": context["inventory_fingerprint"],
            "configuration_fingerprint": config["fingerprint"],
        }, format="json")
        self.assertEqual(confirmed.status_code, 201, confirmed.data)
        self.sw.version = "4.6.0"
        self.sw.save(update_fields=["version"])
        changed = self.client.get(self.url).data
        stale_config = changed["relevant_configurations"][0]
        self.assertFalse(stale_config["review_supported"])
        self.assertTrue(stale_config["latest_assessment"]["stale"])
        self.assertEqual(changed["assessment_summary"]["status"], "STALE")
        reopened = self.client.post(self.url, {
            "configuration_index": stale_config["index"],
            "verdict": "UNKNOWN",
            "software_installation_id": None,
            "inventory_declared_complete": False,
            "justification": "Versión cambió; reabrir revisión.",
            "inventory_fingerprint": changed["inventory_fingerprint"],
            "configuration_fingerprint": stale_config["fingerprint"],
        }, format="json")
        self.assertEqual(reopened.status_code, 201, reopened.data)
        self.assertEqual(reopened.data["assessment"]["status"], "PENDING_REVIEW")
        self.assertEqual(self.client.get(self.url).data["assessment_summary"]["status"],
                         "IN_REVIEW")
        self.assertEqual(AssetCveAssessment.objects.count(), 2)

    def test_version_bounded_review_does_not_accept_stale_product_identity(self):
        self.sw.version = "4.6.0"
        self.sw.save(update_fields=["version"])
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(
            response.data["relevant_configurations"][0]["review_supported"]
        )
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_after_version_change_technical_result_returns_to_verification(self):
        self.sw.version = "4.6.0"
        self.sw.save(update_fields=["version"])
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["technical_result"], INDETERMINATE)
        self.assertEqual(response.data["applicability"]["status"], "PENDING_REVIEW")
        self.assertEqual(response.data["applicability"]["source"], "NONE")
        self.assertIsNone(response.data["applicability"]["automatic_evidence"])
        self.assertEqual(
            response.data["relevant_configurations"][0]["technical_result"],
            INDETERMINATE,
        )
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_plcsim_only_exclusion_is_read_only_system_no_aplica(self):
        self.cve.configurations = [
            nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
        ]
        self.cve.save(update_fields=["configurations"])
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["technical_result"], EXCLUDED)
        self.assertEqual(response.data["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(response.data["applicability"]["source"], "SYSTEM")
        self.assertEqual(response.data["relevant_configurations"], [])
        self.assertTrue(response.data["automatic_audit_pending"])
        # GET evaluates NVD but does not append audit records.
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_status_filters_include_system_positive_before_pagination(self):
        base = "/api/vulnerabilities/cves/"
        positive = self.client.get(base, {"status": "APPLIES", "technical": "ALL"})
        self.assertEqual(positive.status_code, 200, positive.data)
        self.assertEqual(positive.data["count"], 1)
        self.assertEqual(positive.data["results"][0]["applicability_source"], "SYSTEM")
        self.assertEqual(self.client.get(base, {
            "status": "PENDING_REVIEW", "technical": "ALL"
        }).data["count"], 0)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_version_na_and_external_step7_remain_pending_for_human_review(self):
        firmware_na = CPU_FW_CRITERION.replace(":*:", ":-:", 1)
        self.cve.configurations = [
            nvd_platform_firmware(CPU_HW, firmware_na),
        ]
        self.cve.save(update_fields=["configurations"])
        response = self.client.get(self.url).data
        self.assertEqual(response["technical_result"], INDETERMINATE)
        self.assertEqual(response["applicability"]["status"], "PENDING_REVIEW")
        self.assertEqual(response["applicability"]["source"], "NONE")

        self.cve.configurations = [{
            "operator": "AND", "nodes": [
                {"operator": "OR", "cpeMatch": [
                    {"criteria": CPU_HW, "vulnerable": False},
                ]},
                {"operator": "OR", "cpeMatch": [
                    {"criteria": STEP7, "vulnerable": True},
                ]},
            ],
        }]
        self.cve.save(update_fields=["configurations"])
        response = self.client.get(self.url).data
        self.assertEqual(response["technical_result"], INDETERMINATE)
        self.assertEqual(response["applicability"]["status"], "PENDING_REVIEW")
        self.assertEqual(response["applicability"]["source"], "NONE")
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_out_of_range_firmware_with_all_alternatives_excluded_is_auto_no_aplica(self):
        self.sw.version = "4.6.0"
        self.sw.save(update_fields=["version"])
        self.fixture.confirm(self.sw.asset, CPU_FW.replace(":4.5.2:", ":4.6.0:"))
        response = self.client.get(self.url).data
        self.assertEqual(response["technical_result"], EXCLUDED)
        self.assertEqual(response["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(response["applicability"]["source"], "SYSTEM")
        self.assertTrue(response["automatic_audit_pending"])
        catalog = self.client.get("/api/vulnerabilities/cves/", {
            "status": "NOT_APPLICABLE", "technical": "ALL"
        })
        self.assertEqual(catalog.data["count"], 1)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
