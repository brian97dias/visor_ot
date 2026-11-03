"""Global CVE catalogue endpoints: one CVE per row, candidate findings only."""
from unittest.mock import Mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from vulnerabilities.models import (
    AssetCveAssessment, AssetCveFinding, Cve, CveDiscoveryRun,
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
        self.assertEqual(reply.data["summary"], {
            "total": 0, "applies": 0, "not_applicable": 0,
            "pending_review": 0, "validated": 0, "applies_conditional": 0,
        })
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

    def test_software_only_legacy_finding_is_historical_not_current_candidate(self):
        from django.utils import timezone

        old_cve = Cve.objects.create(
            cve_id="CVE-2025-12346",
            fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(),
            configurations=[],
        )
        run = CveDiscoveryRun.objects.create(
            requested_by=self.user,
            status=CveDiscoveryRun.Status.COMPLETED,
            selected_hardware_ids=[self.hardware.pk],
        )
        finding = AssetCveFinding.objects.create(
            hardware=self.hardware, cve=old_cve,
            first_discovery_run=run, last_discovery_run=run,
            sources=[{
                "origin": "SOFTWARE",
                "hardware_id": self.hardware.pk,
                "asset_id": 25,
                "asset_cpe_id": 99,
                "cpe_name": "cpe:2.3:o:vendor:firmware:4.5.2:*:*:*:*:*:*:*",
            }],
        )
        listed = self.client.get(self.BASE)
        self.assertEqual(listed.status_code, 200, listed.data)
        row = next(row for row in listed.data["results"]
                   if row["cve_id"] == old_cve.cve_id)
        self.assertEqual(row["hardware_count"], 0)
        self.assertEqual(row["related_assets"], [])
        hw = self.client.get(self.BASE + old_cve.cve_id + "/hardware/")
        self.assertEqual(hw.status_code, 200, hw.data)
        self.assertEqual(hw.data["count"], 0)
        finding.refresh_from_db()
        self.assertEqual(finding.sources[0]["origin"], "SOFTWARE")
        self.assertTrue(Cve.objects.filter(pk=old_cve.pk).exists())

        # A prior human decision remains readable but is not an active finding.
        AssetCveAssessment.objects.create(
            hardware=self.hardware, cve=old_cve, configuration_index=0,
            configuration_snapshot={}, configuration_fingerprint="a" * 64,
            inventory_fingerprint="b" * 64,
            status=AssetCveAssessment.Status.PENDING_REVIEW,
            justification="Revisión histórica", decided_by=self.user,
        )
        assessed = self.client.get(self.BASE + old_cve.cve_id + "/hardware/")
        self.assertEqual(assessed.data["count"], 1)
        self.assertIsNone(assessed.data["results"][0]["finding_id"])
        self.assertEqual(assessed.data["results"][0]["candidate_status"],
                         "PREVIOUSLY_ASSESSED")

    def test_search_by_hardware_name_filters_only_related_cves(self):
        from django.utils import timezone
        self.hardware.asset.name = "PLC-TRA-01"
        self.hardware.asset.save(update_fields=["name"])
        self.run_discovery([
            record("CVE-2024-65432"), record("CVE-2024-65433"),
        ])
        Cve.objects.create(
            cve_id="CVE-2025-00001", fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(),
            description="Una vulnerabilidad de otro equipo",
            configurations=[],
        )
        response = self.client.get(self.BASE, {"q": "plc-tra-01"})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual({
            row["cve_id"] for row in response.data["results"]
        }, {"CVE-2024-65432", "CVE-2024-65433"})
        self.assertTrue(all(
            context["assets"][0]["name"] == "PLC-TRA-01"
            for row in response.data["results"]
            for context in row["related_assets"]
        ))
        # Global counters are intentionally independent of the text filter.
        self.assertEqual(response.data["summary"]["total"], 3)
        self.assertEqual(self.client.get(
            self.BASE, {"q": "no-existe-este-activo"}
        ).data["count"], 0)

    def test_name_filter_combines_with_severity_status_and_pagination(self):
        self.hardware.asset.name = "PLC-TRA-01"
        self.hardware.asset.save(update_fields=["name"])
        severe = record("CVE-2024-65432")
        severe["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] = "HIGH"
        self.run_discovery([severe, record("CVE-2024-65433")])
        first = self.client.get(self.BASE, {
            "q": "TRA-01", "page": 1, "page_size": 1,
        })
        second = self.client.get(self.BASE, {
            "q": "TRA-01", "page": 2, "page_size": 1,
        })
        self.assertEqual(first.data["count"], 2)
        self.assertEqual(second.data["count"], 2)
        self.assertNotEqual(
            first.data["results"][0]["cve_id"],
            second.data["results"][0]["cve_id"],
        )
        high = self.client.get(self.BASE, {
            "q": "TRA-01", "severity": "HIGH",
            "status": "PENDING_REVIEW",
        })
        self.assertEqual(high.status_code, 200, high.data)
        self.assertEqual(high.data["count"], 1)
        self.assertEqual(high.data["results"][0]["cve_id"], "CVE-2024-65432")
        # The pre-existing CVE ID search still works through the same field.
        self.assertEqual(self.client.get(
            self.BASE, {"q": "65433"}
        ).data["count"], 1)

    def test_assessed_hardware_without_finding_is_searchable_by_name(self):
        from django.utils import timezone
        self.hardware.asset.name = "PLC-TRA-01"
        self.hardware.asset.save(update_fields=["name"])
        cve = Cve.objects.create(
            cve_id="CVE-2025-73001",
            fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(), configurations=[],
        )
        for index in (0, 1):
            AssetCveAssessment.objects.create(
                hardware=self.hardware, cve=cve,
                configuration_index=index, configuration_snapshot={},
                configuration_fingerprint="a" * 64,
                inventory_fingerprint="b" * 64,
                status=AssetCveAssessment.Status.PENDING_REVIEW,
                justification="Historial evaluado", decided_by=self.user,
            )
        match = self.client.get(self.BASE, {"q": "PLC-TRA"})
        self.assertEqual(match.status_code, 200, match.data)
        self.assertEqual(match.data["count"], 1)
        self.assertEqual(match.data["results"][0]["cve_id"], cve.cve_id)
        self.assertEqual(match.data["results"][0]["hardware_count"], 1)

    def test_software_name_search_only_when_software_is_evaluated_evidence(self):
        from vulnerabilities.tests_cve_general_assessment import nvd_and
        from vulnerabilities.tests_cve_discovery_plan import SW_CPE
        self.fixture.link()
        self.fixture.confirm(self.fixture.firmware.asset, SW_CPE)
        self.run_discovery([record("CVE-2024-65432")])
        matching = Cve.objects.get(cve_id="CVE-2024-65432")
        matching.configurations = [nvd_and()]
        matching.save(update_fields=["configurations"])
        display = self.client.get(self.BASE)
        self.assertTrue(any(
            asset["name"] == "Firmware one"
            for context in display.data["results"][0]["related_assets"]
            for asset in context["assets"]
        ))
        found = self.client.get(self.BASE, {"q": "firmware one"})
        self.assertEqual(found.status_code, 200, found.data)
        self.assertEqual(found.data["count"], 1)
        unrelated = self.fixture.make_software("Unrelated firmware")
        self.fixture.link(software=unrelated)
        rejected = self.client.get(self.BASE, {"q": "unrelated firmware"})
        self.assertEqual(rejected.data["count"], 0)

    def test_name_filter_does_not_resurrect_legacy_software_only_finding(self):
        from django.utils import timezone
        self.hardware.asset.name = "PLC-TRA-01"
        self.hardware.asset.save(update_fields=["name"])
        cve = Cve.objects.create(
            cve_id="CVE-2025-73888",
            fetch_status=Cve.FetchStatus.COMPLETED,
            retrieved_at=timezone.now(), configurations=[],
        )
        run = CveDiscoveryRun.objects.create(
            requested_by=self.user, status=CveDiscoveryRun.Status.COMPLETED,
            selected_hardware_ids=[self.hardware.pk],
        )
        AssetCveFinding.objects.create(
            hardware=self.hardware, cve=cve,
            first_discovery_run=run, last_discovery_run=run,
            sources=[{
                "origin": "SOFTWARE", "hardware_id": self.hardware.pk,
                "asset_id": 999, "asset_cpe_id": 999,
                "cpe_name": "cpe:2.3:o:vendor:old_firmware:1.0:*:*:*:*:*:*:*",
            }],
        )
        result = self.client.get(self.BASE, {"q": "PLC-TRA-01"})
        self.assertEqual(result.data["count"], 0)
        self.assertEqual(result.data["summary"]["total"], 1)

    def test_not_yet_fetched_record_is_not_presented_as_official(self):
        Cve.objects.create(cve_id="CVE-2024-65432")
        self.assertEqual(self.client.get(self.BASE).data["count"], 0)
        self.assertEqual(self.client.get(self.BASE + "CVE-2024-65432/").status_code, 404)
