"""Read-only discovery planner; no network and no automatic CVE verdict."""
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from assets.models import Asset, Hardware, Software, SoftwareInstallation
from vulnerabilities.models import (
    AssetCpe, AssetCveAssessment, Cpe, CpeSearchRun, CveDiscoveryRun,
    AssetCveFinding,
)
from vulnerabilities.services.cve_discovery import (
    MAX_CVE_DISCOVERY_HARDWARE, build_cve_discovery_plan,
)
from vulnerabilities.services.identity import (
    fingerprint, hardware_identity, software_identity,
)


HW_CPE = "cpe:2.3:h:phoenixcontact:il_pn_bk-pac:-:*:*:*:*:*:*:*"
SW_CPE = "cpe:2.3:o:phoenixcontact:il_pn_bk-pac_firmware:2.0:*:*:*:*:*:*:*"
SW_CPE_TWO = "cpe:2.3:a:vendor:tool:1.0:*:*:*:*:*:*:*"


class CveDiscoveryPlanTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="cve-plan-analyst", role=User.Role.ANALYST,
        )
        self.hardware = self.make_hardware("Controller one")
        self.firmware = self.make_software("Firmware one")

    def make_hardware(self, name):
        asset = Asset.objects.create(
            name=name, asset_type=Asset.AssetType.HARDWARE,
            created_by=self.user, updated_by=self.user,
        )
        return Hardware.objects.create(
            asset=asset, manufacturer="Phoenix Contact",
            model="IL PN BK-PAC", role=Hardware.Role.OTHER,
        )

    def make_software(self, name):
        asset = Asset.objects.create(
            name=name, asset_type=Asset.AssetType.SOFTWARE,
            created_by=self.user, updated_by=self.user,
        )
        return Software.objects.create(
            asset=asset, software_type=Software.SoftwareType.FIRMWARE,
            manufacturer="Phoenix Contact",
            product="IL PN BK-PAC Firmware", version="2.0",
        )

    def link(self, hardware=None, software=None):
        return SoftwareInstallation.objects.create(
            hardware=hardware or self.hardware,
            software=software or self.firmware,
            registered_by=self.user,
        )

    def confirm(self, asset, cpe_name, *, status=AssetCpe.Validation.CONFIRMED,
                deprecated=False, old_fingerprint=False):
        source_identity = (
            hardware_identity(asset) if asset.asset_type == Asset.AssetType.HARDWARE
            else software_identity(asset)
        )
        current = fingerprint(source_identity)
        run = CpeSearchRun.objects.create(
            asset=asset, requested_by=self.user,
            status=CpeSearchRun.Status.COMPLETED,
            identity_snapshot=source_identity, identity_fingerprint=current,
        )
        cpe = Cpe.objects.create(
            cpe_name_id=uuid4(), cpe_name=cpe_name, title=cpe_name,
            deprecated=deprecated,
        )
        return AssetCpe.objects.create(
            asset=asset, cpe=cpe, source_run=run,
            validation_status=status, validated_by=self.user,
            validated_at=timezone.now(),
            validated_identity_fingerprint=("x" * 64 if old_fingerprint else current),
        )

    def test_without_hardware_cpe_cannot_search_even_if_software_has_one(self):
        self.link()
        self.confirm(self.firmware.asset, SW_CPE)
        plan = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(plan["eligible_hardware_ids"], [])
        self.assertEqual(plan["queries"], [])
        self.assertEqual(plan["skipped"][0]["reason"],
                         "NO_CURRENT_CONFIRMED_HARDWARE_CPE")

    def test_hardware_only_cpe_is_eligible_without_firmware_cpe(self):
        association = self.confirm(self.hardware.asset, HW_CPE)
        self.link()
        plan = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(plan["eligible_hardware_ids"], [self.hardware.pk])
        self.assertEqual(len(plan["queries"]), 1)
        query = plan["queries"][0]
        self.assertEqual(query["cpe_name"], HW_CPE)
        self.assertEqual(query["sources"][0]["asset_cpe_id"], association.pk)
        self.assertEqual(query["sources"][0]["origin"], "HARDWARE")
        self.assertEqual(query["next_start_index"], 0)
        self.assertEqual(query["status"], "QUEUED")

    def test_installed_software_never_generates_independent_cve_queries(self):
        hardware_cpe = self.confirm(self.hardware.asset, HW_CPE)
        sw_cpe = self.confirm(self.firmware.asset, SW_CPE)
        before = build_cve_discovery_plan([self.hardware.pk])
        installation = self.link()
        after = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual([q["cpe_name"] for q in after["queries"]], [HW_CPE])
        self.assertEqual(after["queries"][0]["sources"][0]["asset_cpe_id"],
                         hardware_cpe.pk)
        self.assertTrue(all(source["origin"] == "HARDWARE"
                            for q in after["queries"] for source in q["sources"]))
        self.assertNotIn(sw_cpe.pk, {
            source["asset_cpe_id"] for q in after["queries"]
            for source in q["sources"]
        })
        self.assertEqual(before["evidence_fingerprints"],
                         after["evidence_fingerprints"])
        self.firmware.version = "3.0"
        self.firmware.save(update_fields=["version"])
        changed_software = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(after["queries"], changed_software["queries"])
        self.assertEqual(after["evidence_fingerprints"],
                         changed_software["evidence_fingerprints"])
        installation.unlinked_at = timezone.now()
        installation.unlinked_by = self.user
        installation.save(update_fields=["unlinked_at", "unlinked_by"])
        unlinked = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(unlinked["queries"], before["queries"])
        self.assertEqual(unlinked["evidence_fingerprints"],
                         before["evidence_fingerprints"])

    def test_archived_and_stale_software_do_not_affect_hardware_queries(self):
        self.confirm(self.hardware.asset, HW_CPE)
        self.link()
        assoc = self.confirm(self.firmware.asset, SW_CPE)
        initial = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(len(initial["queries"]), 1)
        self.firmware.version = "3.0"
        self.firmware.save(update_fields=["version"])
        stale = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual([q["cpe_name"] for q in stale["queries"]], [HW_CPE])
        self.assertEqual(initial["evidence_fingerprints"],
                         stale["evidence_fingerprints"])
        assoc.validated_identity_fingerprint = fingerprint(
            software_identity(self.firmware.asset)
        )
        assoc.save(update_fields=["validated_identity_fingerprint"])
        renewed = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(len(renewed["queries"]), 1)
        self.firmware.asset.inventory_status = Asset.InventoryStatus.ARCHIVED
        self.firmware.asset.save(update_fields=["inventory_status"])
        archived = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(renewed["queries"], archived["queries"])
        self.assertEqual(renewed["evidence_fingerprints"],
                         archived["evidence_fingerprints"])

    def test_stale_hardware_identity_or_revoked_or_deprecated_cpe_skipped(self):
        assoc = self.confirm(self.hardware.asset, HW_CPE)
        original = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(len(original["queries"]), 1)
        self.hardware.model = "Changed model"
        self.hardware.save(update_fields=["model"])
        stale = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(stale["eligible_hardware_ids"], [])
        self.hardware.model = "IL PN BK-PAC"
        self.hardware.save(update_fields=["model"])
        assoc.validation_status = AssetCpe.Validation.REOPENED
        assoc.save(update_fields=["validation_status"])
        reopened = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(reopened["queries"], [])
        assoc.validation_status = AssetCpe.Validation.CONFIRMED
        assoc.save(update_fields=["validation_status"])
        assoc.cpe.deprecated = True
        assoc.cpe.save(update_fields=["deprecated"])
        self.assertEqual(build_cve_discovery_plan([self.hardware.pk])["queries"], [])

    def test_invalid_part_or_unconfirmed_software_association_is_ignored(self):
        self.confirm(self.hardware.asset, HW_CPE)
        self.link()
        pending = self.confirm(
            self.firmware.asset, SW_CPE, status=AssetCpe.Validation.REJECTED
        )
        invalid = self.confirm(self.firmware.asset, HW_CPE)
        plan = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual([q["cpe_name"] for q in plan["queries"]], [HW_CPE])
        pending.validation_status = AssetCpe.Validation.CONFIRMED
        pending.save(update_fields=["validation_status"])
        plan = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual({q["cpe_name"] for q in plan["queries"]}, {HW_CPE})
        self.assertNotIn(invalid.pk, [
            src["asset_cpe_id"] for q in plan["queries"] for src in q["sources"]
        ])

    def test_shared_cpe_is_queried_once_for_two_hardware_and_all_sources_retained(self):
        second = self.make_hardware("Controller two")
        first_assoc = self.confirm(self.hardware.asset, HW_CPE)
        identity = fingerprint(hardware_identity(second.asset))
        run = CpeSearchRun.objects.create(
            asset=second.asset, requested_by=self.user,
            status=CpeSearchRun.Status.COMPLETED,
            identity_snapshot=hardware_identity(second.asset),
            identity_fingerprint=identity,
        )
        AssetCpe.objects.create(
            asset=second.asset, cpe=first_assoc.cpe,
            source_run=run, validation_status=AssetCpe.Validation.CONFIRMED,
            validated_by=self.user, validated_at=timezone.now(),
            validated_identity_fingerprint=identity,
        )
        plan = build_cve_discovery_plan([second.pk, self.hardware.pk, second.pk])
        self.assertEqual(plan["selected_hardware_ids"], [second.pk, self.hardware.pk])
        self.assertEqual(plan["eligible_hardware_ids"], [second.pk, self.hardware.pk])
        self.assertEqual(len(plan["queries"]), 1)
        self.assertEqual({s["hardware_id"] for s in plan["queries"][0]["sources"]},
                         {second.pk, self.hardware.pk})
        self.assertEqual(len(plan["queries"][0]["sources"]), 2)

    def test_unconfirmed_or_archived_hardware_and_unknown_ids_are_reported(self):
        archived = self.make_hardware("Archived")
        archived.asset.inventory_status = Asset.InventoryStatus.ARCHIVED
        archived.asset.save(update_fields=["inventory_status"])
        software_id = self.firmware.asset_id
        plan = build_cve_discovery_plan([
            archived.pk, software_id, 99999, self.hardware.pk
        ])
        self.assertEqual(plan["eligible_hardware_ids"], [])
        self.assertEqual([s["reason"] for s in plan["skipped"]],
                         ["ARCHIVED", "NOT_HARDWARE", "NOT_FOUND",
                          "NO_CURRENT_CONFIRMED_HARDWARE_CPE"])

    def test_invalid_input_and_query_cap(self):
        for value in (None, [], "1", [0], [-1], [True], [1.0]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_cve_discovery_plan(value)
        with self.assertRaises(ValueError):
            build_cve_discovery_plan(list(range(1, MAX_CVE_DISCOVERY_HARDWARE + 2)))

    def test_service_is_read_only_and_fingerprint_stable(self):
        self.confirm(self.hardware.asset, HW_CPE)
        self.link()
        a = build_cve_discovery_plan([self.hardware.pk])
        b = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(a, b)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
        self.assertEqual(CveDiscoveryRun.objects.count(), 0)
        self.assertEqual(AssetCveFinding.objects.count(), 0)
        self.assertEqual(AssetCpe.objects.count(), 1)

    def test_source_provenance_preserves_multiple_installed_assets(self):
        self.confirm(self.hardware.asset, HW_CPE)
        self.link()
        self.confirm(self.firmware.asset, SW_CPE)
        application = Software.objects.create(
            asset=Asset.objects.create(
                name="HMI app", asset_type=Asset.AssetType.SOFTWARE,
                created_by=self.user, updated_by=self.user,
            ),
            software_type=Software.SoftwareType.APPLICATION,
            manufacturer="Vendor", product="Tool", version="1.0",
        )
        self.link(software=application)
        self.confirm(application.asset, SW_CPE_TWO)
        plan = build_cve_discovery_plan([self.hardware.pk])
        self.assertEqual(len(plan["queries"]), 1)
        sources = [s for q in plan["queries"] for s in q["sources"]]
        self.assertEqual({s["origin"] for s in sources}, {"HARDWARE"})
        self.assertEqual(len([s for s in sources if s["origin"] == "SOFTWARE"]), 0)
