"""Independent CVE/hardware catalogue rows and filters; no NVD network."""
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from vulnerabilities.models import (
    AssetCveAssessment, AssetCveFinding, Cve, CveDiscoveryRun,
)
from vulnerabilities.services.cve_general_assessment import _context, _digest
from vulnerabilities.tests_cve_discovery_plan import CveDiscoveryPlanTests, HW_CPE
from vulnerabilities.tests_cve_general_assessment import nvd_and


class CveHardwareRowTests(TestCase):
    URL = "/api/vulnerabilities/cves/"

    def setUp(self):
        fixture = CveDiscoveryPlanTests(
            methodName="test_hardware_only_cpe_is_eligible_without_firmware_cpe"
        )
        fixture.setUp()
        self.fixture = fixture
        self.user = fixture.user
        self.mez = fixture.hardware
        self.tra = fixture.make_hardware("PLC-TRA-01")
        self.mez.asset.name = "PLC-MEZ-01"
        self.mez.asset.save(update_fields=["name"])
        self.mez_cpe = fixture.confirm(self.mez.asset, HW_CPE)
        self.tra_cpe = fixture.confirm(self.tra.asset, HW_CPE)
        self.cve = Cve.objects.create(
            cve_id="CVE-2021-42029",
            fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(),
            description="Software de ingeniería evaluado",
            configurations=[nvd_and()],
        )
        run = CveDiscoveryRun.objects.create(
            requested_by=self.user,
            status=CveDiscoveryRun.Status.COMPLETED,
            selected_hardware_ids=[self.mez.pk, self.tra.pk],
        )
        for hw, cpe in ((self.mez, self.mez_cpe), (self.tra, self.tra_cpe)):
            AssetCveFinding.objects.create(
                hardware=hw, cve=self.cve,
                first_discovery_run=run, last_discovery_run=run,
                sources=[{
                    "origin": "HARDWARE",
                    "hardware_id": hw.pk, "asset_id": hw.pk,
                    "asset_cpe_id": cpe.pk, "cpe_name": HW_CPE,
                }],
            )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

        # Analyst decision for MEZ only, supported by the exact fingerprints
        # of that hardware. TRA must NEVER inherit that decision.
        _, _, _, _, fp = _context(self.cve.cve_id, self.mez.pk)
        AssetCveAssessment.objects.create(
            hardware=self.mez, cve=self.cve,
            configuration_index=0,
            configuration_snapshot=self.cve.configurations[0],
            configuration_fingerprint=_digest(self.cve.configurations[0]),
            inventory_fingerprint=fp,
            status=AssetCveAssessment.Status.NOT_APPLICABLE,
            justification="No tenemos TIA Portal instalado en MEZ.",
            decided_by=self.user,
            criteria_evidence={
                "decision_scope": "HARDWARE_CVE",
                "nvd_fingerprint": _digest(self.cve.configurations),
            },
        )

    def test_same_cve_is_two_rows_with_distinct_hardware_and_applicability(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual(len(response.data["results"]), 2)
        rows = {r["hardware_id"]: r for r in response.data["results"]}
        self.assertEqual(set(rows), {self.mez.pk, self.tra.pk})
        self.assertEqual(
            {r["cve_id"] for r in rows.values()}, {self.cve.cve_id}
        )
        self.assertEqual(len({r["row_key"] for r in rows.values()}), 2)
        self.assertEqual(rows[self.mez.pk]["applicability_status"], "NOT_APPLICABLE")
        self.assertEqual(rows[self.mez.pk]["applicability_source"], "ANALYST")
        self.assertEqual(rows[self.tra.pk]["applicability_status"], "PENDING_REVIEW")
        self.assertEqual(rows[self.tra.pk]["applicability_source"], "NONE")
        for pk, item in rows.items():
            self.assertEqual(len(item["related_assets"]), 1)
            self.assertEqual(item["related_assets"][0]["hardware_id"], pk)
            self.assertEqual(item["hardware_count"], 1)
        self.assertEqual(response.data["summary"]["total"], 1)
        self.assertEqual(response.data["evaluation_summary"], {
            "total": 2, "applies": 0, "applies_conditional": 0,
            "not_applicable": 1, "pending_review": 1, "validated": 1,
        })

    def test_status_filters_apply_per_hardware_before_pagination(self):
        pending = self.client.get(self.URL, {"status": "PENDING_REVIEW"})
        negative = self.client.get(self.URL, {"status": "NOT_APPLICABLE"})
        self.assertEqual(pending.data["count"], 1)
        self.assertEqual(pending.data["results"][0]["hardware_id"], self.tra.pk)
        self.assertEqual(negative.data["count"], 1)
        self.assertEqual(negative.data["results"][0]["hardware_id"], self.mez.pk)
        first = self.client.get(self.URL, {"page_size": 1, "page": 1})
        second = self.client.get(self.URL, {"page_size": 1, "page": 2})
        self.assertEqual(first.data["count"], 2)
        self.assertEqual(second.data["count"], 2)
        self.assertNotEqual(
            first.data["results"][0]["row_key"],
            second.data["results"][0]["row_key"],
        )
        self.assertEqual(
            self.client.get(self.URL, {"status": "APPLIES"}).data["count"], 0
        )

    def test_hardware_filter_returns_only_matching_context_not_aggregate(self):
        mez = self.client.get(self.URL, {"q": "PLC-MEZ-01"})
        tra = self.client.get(self.URL, {"q": "PLC-TRA-01"})
        for response, hardware, status in (
            (mez, self.mez, "NOT_APPLICABLE"),
            (tra, self.tra, "PENDING_REVIEW"),
        ):
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(response.data["count"], 1)
            self.assertEqual(response.data["results"][0]["hardware_id"], hardware.pk)
            self.assertEqual(response.data["results"][0]["applicability_status"], status)
        self.assertEqual(self.client.get(
            self.URL, {"q": "CVE-2021-42029"}
        ).data["count"], 2)
        self.assertEqual(self.client.get(
            self.URL, {"q": "ingeniería"}
        ).data["count"], 2)

    def test_detail_assessment_history_does_not_cross_hardware_boundary(self):
        mez = self.client.get(
            self.URL + self.cve.cve_id + f"/hardware/{self.mez.pk}/assessment/"
        )
        tra = self.client.get(
            self.URL + self.cve.cve_id + f"/hardware/{self.tra.pk}/assessment/"
        )
        self.assertEqual(mez.status_code, 200, mez.data)
        self.assertEqual(tra.status_code, 200, tra.data)
        self.assertEqual(mez.data["applicability"]["status"], "NOT_APPLICABLE")
        self.assertEqual(tra.data["applicability"]["status"], "PENDING_REVIEW")

    def test_unassociated_official_cve_stays_visible_without_fake_evaluation(self):
        from vulnerabilities.models import Cve
        other = Cve.objects.create(
            cve_id="CVE-2026-99999", fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(), configurations=[],
        )
        result = self.client.get(self.URL, {"q": other.cve_id})
        self.assertEqual(result.data["count"], 1)
        row = result.data["results"][0]
        self.assertIsNone(row["hardware_id"])
        self.assertEqual(row["applicability_status"], "PENDING_REVIEW")
        self.assertEqual(row["related_assets"], [])
        self.assertEqual(result.data["summary"]["total"], 2)
        self.assertEqual(result.data["evaluation_summary"]["total"], 2)
