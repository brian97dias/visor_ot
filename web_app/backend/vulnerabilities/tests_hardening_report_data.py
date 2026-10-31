"""Phase 2 hardening data: current inventory and per-hardware CVE evidence.

Run:
python manage.py test vulnerabilities.tests_hardening_report_data \\
  --settings=config.settings_test_sqlite
"""
import json
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from assets.models import Asset, Hardware, NetworkInterface, OTSystem, SystemMembership
from vulnerabilities.models import AssetCveAssessment, AssetCveFinding
from vulnerabilities.services.hardening_report_data import collect_hardening_report_data
from vulnerabilities.tests_cve_contextualization import (
    SiemensContextualHttpTests, CPU_HW, CPU_FW, CPU_FW_CRITERION,
    nvd_platform_firmware,
)


class HardeningReportDataTests(TestCase):
    def setUp(self):
        # Reuse exactly the current CPE/NVD and installation scenario that
        # already passes VISOR OT's independent CVE contextualization tests.
        SiemensContextualHttpTests.setUp(self)
        self.hw.asset.criticality = "HIGH"
        self.hw.asset.save(update_fields=["criticality"])
        self.sw.asset.criticality = "MEDIUM"
        self.sw.asset.save(update_fields=["criticality"])
        self.system = OTSystem.objects.create(
            name="Control Siemens", description="Planta experimental",
            criticality="HIGH",
            criticality_justification="Equipo crítico para el control.",
            impact="Parada del controlador.",
            created_by=self.user, updated_by=self.user,
        )
        SystemMembership.objects.create(
            system=self.system, hardware=self.hw,
            registered_by=self.user,
        )
        self.interface = NetworkInterface.objects.create(
            hardware=self.hw, mac="02:00:00:00:12:15",
            declared_ip="192.168.88.61",
        )

    def test_current_inventory_cpe_and_positive_pair_are_json_and_read_only(self):
        before_assessments = AssetCveAssessment.objects.count()
        frozen_time = timezone.now()
        with patch("vulnerabilities.services.nvd_client.fetch_page") as nvd:
            report = collect_hardening_report_data(generated_at=frozen_time)
        nvd.assert_not_called()
        self.assertEqual(AssetCveAssessment.objects.count(), before_assessments)
        json.dumps(report)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["generated_at"], frozen_time.isoformat())
        self.assertEqual(report["summary"]["systems"], 1)
        self.assertEqual(report["summary"]["hardware"], 1)
        self.assertEqual(report["summary"]["software_variants"], 1)
        self.assertEqual(report["summary"]["current_installations"], 1)
        self.assertEqual(report["summary"]["network_interfaces"], 1)
        self.assertEqual(report["summary"]["confirmed_cpes"], 2)
        self.assertEqual(report["summary"]["applicable_hardware_cve_pairs"], 1)
        self.assertEqual(report["summary"]["distinct_applicable_cves"], 1)
        self.assertEqual(report["summary"]["conditional_hardware_cve_pairs"], 0)
        self.assertEqual(report["communications"], [])
        system = report["systems"][0]
        self.assertEqual(system["hardware_ids"], [self.hw.pk])
        self.assertEqual(system["criticality_justification"],
                         "Equipo crítico para el control.")
        hardware = report["hardware"][0]
        self.assertEqual(hardware["system_ids"], [self.system.pk])
        self.assertEqual(hardware["interfaces"][0]["declared_ip"], "192.168.88.61")
        self.assertEqual(hardware["confirmed_cpes"][0]["cpe_name"], CPU_HW)
        self.assertEqual(
            hardware["software_installations"][0]["id"], self.installation.pk
        )
        self.assertEqual(report["software"][0]["confirmed_cpes"][0]["cpe_name"], CPU_FW)
        finding = report["applicable_vulnerabilities"][0]
        self.assertEqual(
            (finding["cve_id"], finding["hardware_id"]),
            (self.cve.cve_id, self.hw.pk),
        )
        self.assertEqual(finding["applicability_status"], "APPLIES")
        self.assertEqual(finding["applicability_source"], "SYSTEM")
        self.assertEqual(finding["hardware_criticality"], "HIGH")
        self.assertEqual(finding["evaluated_software"][0]["version"], "4.5.2")
        self.assertEqual(finding["justifications"], [])
        self.assertIsNotNone(finding["automatic_nvd_evidence"])

    def test_one_cve_is_reported_only_for_hardware_with_verified_positive(self):
        second_asset = Asset.objects.create(
            name="Segundo PLC", asset_type="HARDWARE", criticality="LOW",
            created_by=self.user, updated_by=self.user,
        )
        second = Hardware.objects.create(
            asset=second_asset, manufacturer="Siemens",
            model="SIMATIC S7-1200 CPU 1215C", role="PLC",
        )
        SystemMembership.objects.create(
            system=self.system, hardware=second, registered_by=self.user,
        )
        # This is a real, currently confirmed platform CPE, but the second
        # CPU has no verified vulnerable firmware installation.
        assoc = self.fixture.confirm(second_asset, CPU_HW)
        source = dict(self.finding.sources[0])
        source.update({
            "hardware_id": second.pk, "asset_id": second.pk,
            "asset_cpe_id": assoc.pk,
        })
        AssetCveFinding.objects.create(
            hardware=second, cve=self.cve,
            first_discovery_run=self.run, last_discovery_run=self.run,
            sources=[source], evidence_fingerprint="candidate-only",
        )
        report = collect_hardening_report_data()
        self.assertEqual(report["summary"]["hardware"], 2)
        self.assertEqual(report["summary"]["applicable_hardware_cve_pairs"], 1)
        self.assertEqual(
            [(row["cve_id"], row["hardware_id"]) for row
             in report["applicable_vulnerabilities"]],
            [(self.cve.cve_id, self.hw.pk)],
        )

    def test_verified_version_exclusion_does_not_create_report_finding(self):
        self.cve.configurations = [
            nvd_platform_firmware(CPU_HW, CPU_FW_CRITERION, before="4.5.2")
        ]
        self.cve.save(update_fields=["configurations"])
        report = collect_hardening_report_data()
        self.assertEqual(report["applicable_vulnerabilities"], [])
        self.assertEqual(report["conditional_vulnerabilities"], [])
        self.assertEqual(report["summary"]["applicable_hardware_cve_pairs"], 0)
        self.assertEqual(report["summary"]["hardware"], 1)

    def test_manual_conditional_is_in_appendix_only_with_justification(self):
        current = self.client.get(self.url)
        self.assertEqual(current.status_code, 200, current.data)
        selected = current.data["configurations"][8]
        reply = self.client.post(self.url, {
            "configuration_index": 8,
            "configuration_fingerprint": selected["fingerprint"],
            "inventory_fingerprint": current.data["inventory_fingerprint"],
            "verdict": "CONDITIONAL",
            "technical_override_acknowledged": True,
            "software_installation_id": None,
            "justification": "Pendiente verificar condición operacional en terreno.",
        }, format="json")
        self.assertEqual(reply.status_code, 201, reply.data)
        report = collect_hardening_report_data()
        self.assertEqual(report["applicable_vulnerabilities"], [])
        self.assertEqual(len(report["conditional_vulnerabilities"]), 1)
        conditional = report["conditional_vulnerabilities"][0]
        self.assertEqual(conditional["applicability_status"], "APPLIES_CONDITIONAL")
        self.assertEqual(conditional["applicability_source"], "ANALYST")
        self.assertEqual(conditional["automatic_nvd_evidence"], None)
        self.assertEqual(len(conditional["justifications"]), 1)
        self.assertEqual(conditional["justifications"][0]["justification"],
                         "Pendiente verificar condición operacional en terreno.")
        self.assertEqual(report["summary"]["conditional_hardware_cve_pairs"], 1)

    def test_identity_change_invalidates_cpe_and_positive_proof(self):
        self.hw.model = "Modelo corregido"
        self.hw.save(update_fields=["model"])
        report = collect_hardening_report_data()
        self.assertEqual(report["applicable_vulnerabilities"], [])
        self.assertEqual(report["hardware"][0]["confirmed_cpes"], [])
        # This does not delete stale history or revive old CPE confirmations.
        self.assertEqual(report["summary"]["confirmed_cpes"], 1)

    def test_archived_or_unlinked_inventory_is_not_current_evidence(self):
        self.installation.unlinked_at = timezone.now()
        self.installation.unlinked_by = self.user
        self.installation.save(update_fields=["unlinked_at", "unlinked_by"])
        self.interface.hardware = None
        self.interface.save(update_fields=["hardware"])
        report = collect_hardening_report_data()
        self.assertEqual(report["hardware"][0]["software_installations"], [])
        self.assertEqual(report["hardware"][0]["interfaces"], [])
        self.assertEqual(report["applicable_vulnerabilities"], [])
        self.assertEqual(report["summary"]["current_installations"], 0)

    def test_incomplete_active_inventory_is_rejected_without_changes(self):
        self.system.criticality = "UNDEFINED"
        self.system.save(update_fields=["criticality"])
        with self.assertRaises(ValidationError):
            collect_hardening_report_data()
        with self.assertRaises(CommandError):
            call_command("preview_hardening_data", stdout=StringIO())
        self.system.refresh_from_db()
        self.assertEqual(self.system.criticality, "UNDEFINED")

    def test_preview_command_outputs_json_without_creating_audit_rows(self):
        output = StringIO()
        with patch("vulnerabilities.services.nvd_client.fetch_page") as nvd:
            call_command("preview_hardening_data", stdout=output)
        nvd.assert_not_called()
        data = json.loads(output.getvalue())
        self.assertEqual(data["summary"]["applicable_hardware_cve_pairs"], 1)
        self.assertFalse(AssetCveAssessment.objects.exists())
