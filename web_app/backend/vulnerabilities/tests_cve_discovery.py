"""Storage-only regression tests; CVE discovery networking is not enabled."""
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone
from assets.models import Asset, Hardware
from vulnerabilities.models import (
    AssetCpe, AssetCveAssessment, AssetCveFinding, Cve, CveDiscoveryRun,
)


class CveDiscoveryPersistenceTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="cve-discovery-test", role=User.Role.ANALYST,
        )
        self.asset = Asset.objects.create(
            name="Phoenix controller", asset_type=Asset.AssetType.HARDWARE,
            created_by=self.user, updated_by=self.user,
        )
        self.hardware = Hardware.objects.create(
            asset=self.asset, manufacturer="Phoenix Contact",
            model="IL PN BK-PAC", role=Hardware.Role.OTHER,
        )
        self.cve = Cve.objects.create(cve_id="CVE-2021-33540")

    def new_run(self):
        return CveDiscoveryRun.objects.create(
            requested_by=self.user,
            selected_hardware_ids=[self.hardware.pk],
        )

    def test_run_preserves_selection_and_incomplete_checkpoint(self):
        run = self.new_run()
        self.assertEqual(run.status, CveDiscoveryRun.Status.QUEUED)
        run.status = CveDiscoveryRun.Status.INCOMPLETE
        run.started_at = timezone.now()
        run.checkpoint_at = timezone.now()
        run.queries = [{
            "cpe_name": "cpe:2.3:h:phoenixcontact:il_pn_bk-pac:-:*:*:*:*:*:*:*",
            "next_start_index": 2000,
            "expected_total": 3100,
            "pages_fetched": 2,
            "status": "INCOMPLETE",
        }]
        run.save(update_fields=["status", "started_at", "checkpoint_at", "queries"])
        run.refresh_from_db()
        self.assertEqual(run.selected_hardware_ids, [self.hardware.pk])
        self.assertEqual(run.queries[0]["next_start_index"], 2000)
        self.assertEqual(run.queries[0]["expected_total"], 3100)

    def test_deduplicated_hardware_cve_preserves_multiple_cpe_sources(self):
        run = self.new_run()
        sources = [
            {"origin": "HARDWARE", "asset_id": self.asset.pk,
             "cpe_name": "cpe:2.3:h:phoenixcontact:il_pn_bk-pac:-:*:*:*:*:*:*:*"},
            {"origin": "SOFTWARE", "asset_id": 4, "installation_id": 8,
             "cpe_name": "cpe:2.3:o:vendor:firmware:1.0:*:*:*:*:*:*:*"},
        ]
        record = AssetCveFinding.objects.create(
            hardware=self.hardware, cve=self.cve,
            first_discovery_run=run, last_discovery_run=run,
            sources=sources, evidence_fingerprint="a" * 64,
        )
        record.refresh_from_db()
        self.assertEqual(record.sources, sources)
        self.assertEqual(record.first_discovery_run_id, run.pk)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AssetCveFinding.objects.create(
                    hardware=self.hardware, cve=self.cve,
                    first_discovery_run=run, last_discovery_run=run,
                )
        self.assertEqual(AssetCveFinding.objects.count(), 1)

    def test_same_cve_can_belong_to_two_hardware_without_duplicate_cve(self):
        run = self.new_run()
        other_asset = Asset.objects.create(
            name="Second controller", asset_type=Asset.AssetType.HARDWARE,
            created_by=self.user, updated_by=self.user,
        )
        other = Hardware.objects.create(
            asset=other_asset, manufacturer="Phoenix Contact",
            model="IL PN BK-PAC", role=Hardware.Role.OTHER,
        )
        for hardware in (self.hardware, other):
            AssetCveFinding.objects.create(
                hardware=hardware, cve=self.cve,
                first_discovery_run=run, last_discovery_run=run,
            )
        self.assertEqual(AssetCveFinding.objects.count(), 2)
        self.assertEqual(Cve.objects.count(), 1)

    def test_discovery_creates_no_evaluation_or_cpe(self):
        run = self.new_run()
        finding = AssetCveFinding.objects.create(
            hardware=self.hardware, cve=self.cve,
            first_discovery_run=run, last_discovery_run=run,
        )
        self.assertEqual(finding.sources, [])
        self.assertEqual(Cve.objects.get(pk=self.cve.pk).nvd_record, {})
        self.assertEqual(AssetCpe.objects.count(), 0)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)

    def test_json_defaults_are_not_shared_across_instances(self):
        a, b = self.new_run(), self.new_run()
        a.queries.append({"cpe_name": "example"})
        self.assertEqual(b.queries, [])
        f1 = AssetCveFinding(
            hardware=self.hardware, cve=self.cve,
            first_discovery_run=a, last_discovery_run=a,
        )
        f2 = AssetCveFinding(
            hardware=self.hardware, cve=self.cve,
            first_discovery_run=b, last_discovery_run=b,
        )
        f1.sources.append({"origin": "HARDWARE"})
        self.assertEqual(f2.sources, [])
