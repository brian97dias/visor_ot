"""Global CVE catalogue endpoints: one CVE per row, candidate findings only."""
from unittest.mock import Mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from vulnerabilities.models import (
    AssetCveAssessment, AssetCveFinding, Cve,
)
from vulnerabilities.services.cve_discovery_worker import (
    enqueue_cve_discovery, execute_cve_discovery_run,
)
from vulnerabilities.tests_cve_discovery_api import page, record
from vulnerabilities.tests_cve_discovery_plan import (
    CveDiscoveryPlanTests, HW_CPE,
)


class CveCatalogueHttpTests(TestCase):
    BASE = "/api/vulnerabilities/cves/"

    def setUp(self):
        fixture = CveDiscoveryPlanTests(
            methodName="test_hardware_only_cpe_is_eligible_without_firmware_cpe"
        )
        fixture.setUp()
        self.user = fixture.user
        self.hardware = fixture.hardware
        fixture.confirm(self.hardware.asset, HW_CPE)
        self.fixture = fixture
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.operator = get_user_model().objects.create_user(
            username="cve-catalogue-operator", role="OPERATOR",
        )

    def run_discovery(self, records):
        run, _ = enqueue_cve_discovery([self.hardware.pk], self.user)
        done = execute_cve_discovery_run(
            run, Mock(), fetcher=Mock(
                return_value=page(records, size=500)
            ),
        )
        self.assertEqual(done.status, "COMPLETED", done.error_message)

    def test_empty_catalogue_and_no_automatic_hardware_verdicts(self):
        reply = self.client.get(self.BASE)
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.data["count"], 0)
        self.assertEqual(reply.data["results"], [])
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_unique_cve_count_and_candidate_hardware(self):
        self.run_discovery([record("CVE-2024-65432"), record("CVE-2024-65433")])
        self.assertEqual(Cve.objects.count(), 2)
        reply = self.client.get(self.BASE)
        self.assertEqual(reply.status_code, 200, reply.data)
        self.assertEqual(reply.data["count"], 2)
        self.assertTrue(all(r["hardware_count"] == 1 for r in reply.data["results"]))
        self.assertTrue(all(r["relationship_kind"] == "CANDIDATE"
                            for r in reply.data["results"]))
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_filters_search_severity_and_pagination(self):
        high = record("CVE-2024-65432")
        high["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] = "HIGH"
        medium = record("CVE-2024-65433")
        self.run_discovery([high, medium])
        self.assertEqual(self.client.get(self.BASE, {"severity": "HIGH"}).data["count"], 1)
        self.assertEqual(self.client.get(self.BASE, {"q": "65433"}).data["count"], 1)
        first = self.client.get(self.BASE, {"page_size": 1, "page": 1})
        second = self.client.get(self.BASE, {"page_size": 1, "page": 2})
        self.assertEqual(first.data["count"], 2)
        self.assertNotEqual(first.data["results"][0]["cve_id"],
                            second.data["results"][0]["cve_id"])
        self.assertEqual(self.client.get(self.BASE, {"page": 0}).status_code, 400)
        self.assertEqual(self.client.get(self.BASE, {"page_size": 101}).status_code, 400)

    def test_detail_preserves_original_and_or_without_claiming_applicability(self):
        source = record()
        self.run_discovery([source])
        detail = self.client.get(self.BASE + source["id"] + "/")
        self.assertEqual(detail.status_code, 200, detail.data)
        self.assertEqual(detail.data["cve"]["configurations"], source["configurations"])
        self.assertEqual(detail.data["cve"]["hardware_count"], 1)
        self.assertNotIn("effective_status", detail.data["cve"])
        self.assertEqual(self.client.get(self.BASE + "CVE-2020-99999/").status_code, 404)

    def test_hardware_list_reports_stale_evidence_and_sources(self):
        source = record()
        self.run_discovery([source])
        path = self.BASE + source["id"] + "/hardware/"
        before = self.client.get(path)
        self.assertEqual(before.data["count"], 1)
        row = before.data["results"][0]
        self.assertEqual(row["candidate_status"], "CANDIDATE")
        self.assertEqual(row["evidence_status"], "CURRENT")
        self.assertEqual(row["hardware_id"], self.hardware.pk)
        self.assertEqual(row["sources"][0]["cpe_name"], HW_CPE)
        self.hardware.model = "Other Model"
        self.hardware.save(update_fields=["model"])
        after = self.client.get(path).data["results"][0]
        self.assertEqual(after["evidence_status"], "STALE")
        self.assertEqual(AssetCveFinding.objects.count(), 1)

    def test_operator_read_only_and_anonymous_denied(self):
        self.run_discovery([record()])
        self.client.force_authenticate(self.operator)
        self.assertEqual(self.client.get(self.BASE).status_code, 200)
        self.assertEqual(self.client.get(self.BASE + "CVE-2024-65432/").status_code, 200)
        self.assertEqual(self.client.get(self.BASE + "CVE-2024-65432/hardware/").status_code, 200)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.client.get(self.BASE).status_code, 401)
        self.assertEqual(self.client.get(self.BASE + "CVE-2024-65432/").status_code, 401)

    def test_catalogue_counts_previously_assessed_hardware_without_a_finding(self):
        from django.utils import timezone
        existing = Cve.objects.create(
            cve_id="CVE-2021-33540",
            fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(), descriptions=[
                {"lang": "en", "value": "Original description"},
                {"lang": "es", "value": "Descripción original en español"},
            ],
        )
        from vulnerabilities.models import AssetCveAssessment
        AssetCveAssessment.objects.create(
            hardware=self.hardware, cve=existing,
            configuration_index=11, configuration_snapshot={},
            configuration_fingerprint="a" * 64,
            inventory_fingerprint="b" * 64,
            status=AssetCveAssessment.Status.APPLIES,
            justification="Verificación histórica", decided_by=self.user,
        )
        listing = self.client.get(self.BASE)
        self.assertEqual(listing.status_code, 200, listing.data)
        row = listing.data["results"][0]
        self.assertEqual(row["selected_assets_count"], 1)
        self.assertEqual(row["description"], "Descripción original en español")
        self.assertEqual(row["description_source"], "NVD_ES")
        related = self.client.get(self.BASE + existing.cve_id + "/hardware/")
        self.assertEqual(related.status_code, 200, related.data)
        self.assertEqual(related.data["count"], 1)
        self.assertTrue(related.data["results"][0]["has_assessment"])
        self.assertIsNone(related.data["results"][0]["finding_id"])

    def test_assessed_hardware_with_a_finding_is_counted_once(self):
        from django.utils import timezone
        self.run_discovery([record()])
        from vulnerabilities.models import AssetCveAssessment
        source = Cve.objects.get(cve_id="CVE-2024-65432")
        AssetCveAssessment.objects.create(
            hardware=self.hardware, cve=source,
            configuration_index=0, configuration_snapshot={},
            configuration_fingerprint="a" * 64,
            inventory_fingerprint="b" * 64,
            status=AssetCveAssessment.Status.PENDING_REVIEW,
            justification="Análisis iniciado", decided_by=self.user,
        )
        results = self.client.get(self.BASE)
        self.assertEqual(results.data["results"][0]["selected_assets_count"], 1)
        related = self.client.get(self.BASE + source.cve_id + "/hardware/")
        self.assertEqual(related.data["count"], 1)

    def test_not_yet_fetched_record_is_not_presented_as_official(self):
        Cve.objects.create(cve_id="CVE-2024-65432")
        self.assertEqual(self.client.get(self.BASE).data["count"], 0)
        self.assertEqual(self.client.get(self.BASE + "CVE-2024-65432/").status_code, 404)
