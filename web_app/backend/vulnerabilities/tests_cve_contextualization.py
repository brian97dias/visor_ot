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
            "pending_review": 0, "validated": 1,
        })
        self.assertEqual(row["evaluation_status"], "PENDING_REVIEW")
        self.assertEqual(len(row["related_assets"]), 1)
        found = row["related_assets"][0]["assets"]
        self.assertEqual([item["asset_type"] for item in found],
                         ["HARDWARE", "SOFTWARE"])
        self.assertEqual(found[0]["asset_id"], self.hw.pk)
        self.assertEqual(found[1]["asset_id"], self.sw.pk)
        self.assertEqual(found[1]["version"], "4.5.2")
        self.assertEqual(found[1]["role"], "MATCHED_INSTALLED_SOFTWARE")

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

    def test_plcsim_only_exclusion_does_not_mutate_human_decisions(self):
        self.cve.configurations = [
            nvd_platform_firmware(PLCSIM_HW, PLCSIM_FW, before="5.0")
        ]
        self.cve.save(update_fields=["configurations"])
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["technical_result"], EXCLUDED)
        self.assertEqual(response.data["applicability"]["status"], "PENDING_REVIEW")
        self.assertEqual(response.data["applicability"]["source"], "NONE")
        self.assertEqual(response.data["relevant_configurations"], [])
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

    def test_out_of_range_firmware_does_not_become_auto_no_aplica(self):
        self.sw.version = "4.6.0"
        self.sw.save(update_fields=["version"])
        self.fixture.confirm(self.sw.asset, CPU_FW.replace(":4.5.2:", ":4.6.0:"))
        response = self.client.get(self.url).data
        self.assertEqual(response["technical_result"], EXCLUDED)
        self.assertEqual(response["applicability"]["status"], "PENDING_REVIEW")
        self.assertEqual(response["applicability"]["source"], "NONE")
        catalog = self.client.get("/api/vulnerabilities/cves/", {
            "status": "NOT_APPLICABLE", "technical": "ALL"
        })
        self.assertEqual(catalog.data["count"], 0)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
