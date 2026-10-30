"""NVD version/logic checks with no network, SQL changes or automatic audits."""
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from vulnerabilities.models import AssetCveAssessment, Cve
from vulnerabilities.services.cve_configuration_evaluator import (
    COMPATIBLE, EXCLUDED, INDETERMINATE,
    compare_numeric_versions, evaluate_version,
    evaluate_criterion, evaluate_configurations,
)
from vulnerabilities.services.cve_technical_status import technical_statuses
from vulnerabilities.tests_cve_discovery_plan import (
    CveDiscoveryPlanTests, HW_CPE, SW_CPE,
)

SIEMENS_HW = "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1215c:-:*:*:*:*:*:*:*"
SIEMENS_SW = "cpe:2.3:o:siemens:simatic_s7-1200_cpu_1215c_firmware:4.0:*:*:*:*:*:*:*"
SIEMENS_MATCH = "cpe:2.3:o:siemens:simatic_s7-1200_cpu_1215c_firmware:*:*:*:*:*:*:*:*"


def scenario(software=SIEMENS_MATCH, version_end="3.0.0", start="2.0.0",
             hardware=SIEMENS_HW):
    match = {"criteria": software, "vulnerable": True}
    if start is not None:
        match["versionStartIncluding"] = start
    if version_end is not None:
        match["versionEndExcluding"] = version_end
    return {"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [match]},
        {"operator": "OR", "cpeMatch": [
            {"criteria": hardware, "vulnerable": False}
        ]},
    ]}


def installed(cpe=SIEMENS_SW, version="4.0"):
    return [{
        "installation_id": 88, "software_type": "FIRMWARE",
        "software_asset_id": 25, "software_name": "Firmware Siemens",
        "version": version, "confirmed_cpes": [cpe] if cpe else [],
    }]


class NvdVersionEvaluatorTests(SimpleTestCase):
    def test_major_difference_is_decidable_despite_version_precision(self):
        self.assertEqual(compare_numeric_versions("4.0", "3.0.0"), 1)
        self.assertEqual(compare_numeric_versions("2.5.0", "3.0.0"), -1)
        self.assertEqual(compare_numeric_versions("4.0", "4.0"), 0)

    def test_unknown_when_only_precision_or_vendor_format_differs(self):
        self.assertIsNone(compare_numeric_versions("4.0", "4.0.0"))
        self.assertIsNone(compare_numeric_versions("4", "4.0"))
        self.assertIsNone(compare_numeric_versions("4.5.2-rc1", "4.6.0"))
        self.assertIsNone(compare_numeric_versions("1.1.1k", "1.1.1j"))
        self.assertEqual(evaluate_version("4", "*", {
            "versionEndIncluding": "4.0",
        })[0], INDETERMINATE)

    def test_siemens_range_excludes_four_and_includes_two_point_five(self):
        bounds = {"versionStartIncluding": "2.0.0",
                  "versionEndExcluding": "3.0.0"}
        self.assertEqual(evaluate_version("4.0", "*", bounds)[0], EXCLUDED)
        self.assertEqual(evaluate_version("2.5.0", "*", bounds)[0], COMPATIBLE)
        self.assertEqual(evaluate_version("2.0.0", "*", bounds)[0], COMPATIBLE)
        self.assertEqual(evaluate_version("3.0.0", "*", bounds)[0], EXCLUDED)

    def test_nvd_exclusive_and_inclusive_limits(self):
        self.assertEqual(evaluate_version("4.0", "*", {
            "versionEndExcluding": "4.0",
        })[0], EXCLUDED)
        self.assertEqual(evaluate_version("4.0", "*", {
            "versionEndIncluding": "4.0",
        })[0], COMPATIBLE)
        self.assertEqual(evaluate_version("4.0", "*", {
            "versionStartExcluding": "4.0",
        })[0], EXCLUDED)
        self.assertEqual(evaluate_version("4.0", "*", {
            "versionStartIncluding": "4.0",
        })[0], COMPATIBLE)

    def test_missing_or_na_is_not_any_version(self):
        self.assertEqual(evaluate_version("", "*", {
            "versionStartIncluding": "2.0.0",
        })[0], INDETERMINATE)
        self.assertEqual(evaluate_version("4.0", "-")[0], INDETERMINATE)
        self.assertEqual(evaluate_version("4.0", "*")[0], COMPATIBLE)

    def test_exact_match_requires_specific_product_not_generic_prefix(self):
        generic = "cpe:2.3:o:siemens:simatic_s7-1200_cpu_firmware:4.0:*:*:*:*:*:*:*"
        item = scenario()["nodes"][0]["cpeMatch"][0]
        result = evaluate_criterion(item, [SIEMENS_HW], installed(generic))
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertIn("correspondencia exacta", result["reason"])

    def test_current_matching_software_and_hardware_required(self):
        all_data = evaluate_configurations(
            [scenario()], [SIEMENS_HW], installed()
        )
        self.assertEqual(all_data["result"], EXCLUDED)
        match = all_data["configurations"][0]
        self.assertEqual(match["children"][0]["children"][0]["result"], EXCLUDED)
        self.assertEqual(match["children"][1]["children"][0]["result"], COMPATIBLE)
        self.assertEqual(evaluate_configurations(
            [scenario()], [SIEMENS_HW], installed(cpe=None)
        )["result"], INDETERMINATE)

    def test_family_hardware_cpe_is_not_excluded_on_name_mismatch_alone(self):
        broad_hw = "cpe:2.3:h:siemens:simatic_s7-1200:-:*:*:*:*:*:*:*"
        result = evaluate_criterion(
            {"criteria": broad_hw, "vulnerable": False},
            [SIEMENS_HW], installed(),
        )
        self.assertEqual(result["result"], INDETERMINATE)

    def test_platform_vulnerable_false_means_required_platform_not_no_aplica(self):
        result = evaluate_criterion(scenario()["nodes"][1]["cpeMatch"][0],
                                    [SIEMENS_HW], installed())
        self.assertEqual(result["result"], COMPATIBLE)
        self.assertEqual(evaluate_criterion(scenario()["nodes"][1]["cpeMatch"][0],
                                            [], installed())["result"], INDETERMINATE)

    def test_or_and_negate_preserve_three_valued_logic(self):
        matching = {"criteria": SIEMENS_MATCH, "vulnerable": True,
                    "versionEndExcluding": "4.5.0"}
        not_matching = {"criteria": SIEMENS_MATCH, "vulnerable": True,
                        "versionEndExcluding": "3.0.0"}
        unknown = {"criteria": SIEMENS_MATCH, "vulnerable": True,
                   "versionEndExcluding": "4.0.0"}
        any_match = {"operator": "OR", "cpeMatch": [matching, not_matching]}
        all_match = {"operator": "AND", "cpeMatch": [matching, not_matching]}
        self.assertEqual(evaluate_configurations([any_match], [SIEMENS_HW],
                                                 installed())["result"], COMPATIBLE)
        self.assertEqual(evaluate_configurations([all_match], [SIEMENS_HW],
                                                 installed())["result"], EXCLUDED)
        self.assertEqual(evaluate_configurations([{"operator": "OR",
            "cpeMatch": [unknown, not_matching]}], [SIEMENS_HW],
            installed())["result"], INDETERMINATE)
        self.assertEqual(evaluate_configurations([{"operator": "OR",
            "negate": True, "cpeMatch": [not_matching]}],
            [SIEMENS_HW], installed())["result"], COMPATIBLE)

    def test_alternative_configurations_require_all_to_exclude_a_cve(self):
        excluded = scenario()
        uncertain = scenario(
            software="cpe:2.3:o:siemens:some_other_firmware:*:*:*:*:*:*:*:*"
        )
        result = evaluate_configurations([excluded, uncertain],
                                         [SIEMENS_HW], installed())
        self.assertEqual(result["configurations"][0]["result"], EXCLUDED)
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertEqual(evaluate_configurations([excluded, excluded],
                                                 [SIEMENS_HW], installed())["result"],
                         EXCLUDED)

    def test_missing_cpe_or_unsupported_version_does_not_discard(self):
        result = evaluate_configurations(
            [scenario()], [SIEMENS_HW], installed(version="4.0-beta")
        )
        self.assertEqual(result["result"], INDETERMINATE)
        self.assertEqual(evaluate_configurations([scenario()], [SIEMENS_HW], [])
                         ["result"], INDETERMINATE)


class NvdVersionIntegrationTests(TestCase):
    """The same installed firmware and NVD data drive context and global filters."""

    def setUp(self):
        fixture = CveDiscoveryPlanTests(
            methodName="test_hardware_only_cpe_is_eligible_without_firmware_cpe"
        )
        fixture.setUp()
        self.sample = fixture
        self.user = fixture.user
        self.hw = fixture.hardware
        self.sw = fixture.firmware
        self.sample.confirm(self.hw.asset, HW_CPE)
        self.installation = fixture.link()
        self.sw_cpe = self.sample.confirm(self.sw.asset, SW_CPE)
        match = {
            "criteria": "cpe:2.3:o:phoenixcontact:il_pn_bk-pac_firmware:*:*:*:*:*:*:*:*",
            "vulnerable": True, "versionEndExcluding": "3.0",
        }
        self.cve = Cve.objects.create(
            cve_id="CVE-2026-76543", fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(),
            configurations=[{"operator": "AND", "nodes": [
                {"operator": "OR", "cpeMatch": [match]},
                {"operator": "OR", "cpeMatch": [
                    {"criteria": HW_CPE, "vulnerable": False},
                ]},
            ]}],
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.path = ("/api/vulnerabilities/cves/" + self.cve.cve_id +
                     "/hardware/" + str(self.hw.pk) + "/assessment/")

    def test_live_firmware_confirmation_yields_technical_compatible(self):
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["technical_result"], COMPATIBLE)
        row = response.data["configurations"][0]
        self.assertEqual(row["technical_result"], COMPATIBLE)
        self.assertEqual(row["tree"]["children"][0]["children"][0]
                         ["technical_installed_version"], "2.0")
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_changing_software_version_invalidates_confirmed_cpe_and_result(self):
        before = self.client.get(self.path).data
        self.assertEqual(before["technical_result"], COMPATIBLE)
        self.sw.version = "4.0"
        self.sw.save(update_fields=["version"])
        after = self.client.get(self.path).data
        self.assertEqual(after["technical_result"], INDETERMINATE)
        self.assertEqual(after["installed_software"][0]["confirmed_cpes"], [])
        self.assertNotEqual(before["inventory_fingerprint"],
                            after["inventory_fingerprint"])
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_reconfirming_after_version_update_can_exclude_the_range(self):
        self.sw.version = "4.0"
        self.sw.save(update_fields=["version"])
        current_name = SW_CPE.replace(":2.0:", ":4.0:")
        self.sample.confirm(self.sw.asset, current_name)
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["technical_result"], EXCLUDED)
        self.assertEqual(response.data["configurations"][0]["technical_result"],
                         EXCLUDED)

    def test_technical_list_status_has_no_effect_on_audited_decision(self):
        self.assertEqual(technical_statuses([self.cve])[self.cve.pk],
                         INDETERMINATE)
        # The CVE currently lacks a discovery finding/assessment relationship;
        # merely fetching it does not automatically link the hardware.
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def _link_candidate_finding(self):
        from vulnerabilities.models import CveDiscoveryRun, AssetCveFinding
        run = CveDiscoveryRun.objects.create(
            requested_by=self.user, selected_hardware_ids=[self.hw.pk],
            status=CveDiscoveryRun.Status.COMPLETED,
        )
        from vulnerabilities.services.cve_discovery import build_cve_discovery_plan

        plan = build_cve_discovery_plan([self.hw.pk])
        self.assertEqual(len(plan["queries"]), 1)
        return AssetCveFinding.objects.create(
            hardware=self.hw, cve=self.cve,
            first_discovery_run=run, last_discovery_run=run,
            sources=plan["queries"][0]["sources"],
            evidence_fingerprint=plan["evidence_fingerprints"][str(self.hw.pk)],
        )

    def test_http_filter_shows_technical_result_but_not_a_human_verdict(self):
        self._link_candidate_finding()
        base = "/api/vulnerabilities/cves/"
        response = self.client.get(base, {"technical": "COMPATIBLE"})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["count"], 1)
        row = response.data["results"][0]
        self.assertEqual(row["technical_result"], COMPATIBLE)
        self.assertEqual(row["evaluation_status"], "PENDING_REVIEW")
        self.assertEqual(row["applicability_status"], "APPLIES")
        self.assertEqual(row["applicability_source"], "SYSTEM")
        self.assertEqual(self.client.get(base, {"technical": "EXCLUDED"}).data["count"], 0)
        self.assertEqual(self.client.get(base, {"technical": "ATTENTION"}).data["count"], 1)
        self.assertEqual(self.client.get(base, {"technical": "invalid"}).status_code, 400)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_http_filter_recalculates_after_version_change_without_worker(self):
        self._link_candidate_finding()
        base = "/api/vulnerabilities/cves/"
        self.sw.version = "4.0"
        self.sw.save(update_fields=["version"])
        pending = self.client.get(base, {"technical": "INDETERMINATE"})
        self.assertEqual(pending.data["count"], 1)
        self.sample.confirm(self.sw.asset, SW_CPE.replace(":2.0:", ":4.0:"))
        excluded = self.client.get(base, {"technical": "EXCLUDED"})
        self.assertEqual(excluded.status_code, 200, excluded.data)
        self.assertEqual(excluded.data["count"], 1)
        self.assertEqual(excluded.data["results"][0]["technical_result"], EXCLUDED)
        self.assertEqual(excluded.data["results"][0]["evaluation_status"], "PENDING_REVIEW")
        # A fully evidenced exclusion is an automatic applicability result,
        # but remains distinct from the append-only *human* decision status.
        self.assertEqual(excluded.data["results"][0]["applicability_status"],
                         "NOT_APPLICABLE")
        self.assertEqual(excluded.data["results"][0]["applicability_source"], "SYSTEM")
        self.assertEqual(self.client.get(base, {"status": "NOT_APPLICABLE"}).data["count"], 1)
        self.assertEqual(self.client.get(base, {"technical": "ATTENTION"}).data["count"], 0)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
