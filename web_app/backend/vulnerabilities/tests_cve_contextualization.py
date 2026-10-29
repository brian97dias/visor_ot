"""CVE-by-asset contextualization: Siemens CPU vs PLCSIM alternative.

The data below reproduces the relevant NVD *shapes*, not a downloaded copy
of all 96 configurations. The live NVD JSON is still stored unchanged.
"""
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from vulnerabilities.models import (
    AssetCveAssessment, AssetCveFinding, Cve, CveDiscoveryRun,
)
from vulnerabilities.services.cve_configuration_evaluator import (
    COMPATIBLE, EXCLUDED, INDETERMINATE, evaluate_configurations,
)
from vulnerabilities.services.cve_applicability import (
    automatic_negative_evidence, verified_negative_configurations,
)
from vulnerabilities.services.cve_general_assessment import (
    general_assessment_context, summarize_hardware_cve_review,
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
        self.finding = AssetCveFinding.objects.create(
            hardware=self.hw, cve=self.cve,
            first_discovery_run=self.run, last_discovery_run=self.run,
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
        self.assertEqual([row["position"] for row in data["relevant_configurations"]], [9])
        self.assertEqual(data["unrelated_configuration_count"], 11)
        criterion = data["relevant_configurations"][0]["tree"]["children"][0]["children"][0]
        self.assertEqual(criterion["technical_matched_cpe"], CPU_FW)
        self.assertEqual(criterion["technical_installed_version"], "4.5.2")
        self.assertEqual(criterion["technical_software_asset_id"], self.sw.pk)
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

    def test_version_bounded_confirmation_is_scoped_and_audited(self):
        context = self.client.get(self.url)
        self.assertEqual(context.status_code, 200, context.data)
        info = context.data
        row = info["relevant_configurations"][0]
        self.assertTrue(row["review_supported"])
        self.assertEqual(row["review_installation_id"], self.installation.pk)
        payload = {
            "configuration_index": 8,
            "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": False,
            "justification": "CPU y firmware confirmados, versión 4.5.2 < 4.6.0.",
            "inventory_fingerprint": info["inventory_fingerprint"],
            "configuration_fingerprint": row["fingerprint"],
        }
        created = self.client.post(self.url, payload, format="json")
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(created.data["assessment"]["status"], "APPLIES")
        current = self.client.get(self.url).data
        summary = current["assessment_summary"]
        self.assertEqual(current["applicability"]["source"], "ANALYST")
        self.assertEqual(summary["status"], "APPLIES")
        self.assertEqual(summary["confirmed_configurations"], 1)
        self.assertEqual(summary["pending_configurations"], 11)
        self.assertEqual(AssetCveAssessment.objects.count(), 1)
        listing = self.client.get("/api/vulnerabilities/cves/?technical=ALL")
        self.assertEqual(listing.data["results"][0]["evaluation_status"], "APPLIES")
        payload["verdict"] = "UNKNOWN"
        payload["software_installation_id"] = None
        payload["justification"] = "Reabrir análisis sin borrar la decisión previa."
        undone = self.client.post(self.url, payload, format="json")
        self.assertEqual(undone.status_code, 201, undone.data)
        self.assertEqual(undone.data["assessment"]["status"], "PENDING_REVIEW")
        reopened_context = self.client.get(self.url).data
        reopened_summary = reopened_context["assessment_summary"]
        self.assertEqual(reopened_context["applicability"]["source"], "SYSTEM")
        self.assertEqual(reopened_summary["status"], "IN_REVIEW")
        self.assertEqual(reopened_summary["confirmed_configurations"], 0)
        self.assertEqual(AssetCveAssessment.objects.count(), 2)

    def test_verified_version_range_cannot_be_marked_not_applicable(self):
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
        self.assertIn("verdict", response.data)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_stale_positive_can_be_reopened_without_current_matching_cpe(self):
        context = self.client.get(self.url).data
        config = context["relevant_configurations"][0]
        confirmed = self.client.post(self.url, {
            "configuration_index": config["index"],
            "verdict": "CONFIRMED",
            "software_installation_id": self.installation.pk,
            "inventory_declared_complete": False,
            "justification": "Firmware 4.5.2 dentro de rango y CPE vigentes.",
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
