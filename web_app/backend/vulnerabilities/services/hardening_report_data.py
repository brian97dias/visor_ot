"""Read-only, JSON-serializable source for the future OT hardening PDF.

Phase 2 does not generate a PDF, contact NVD, create CVE assessments or
infer vulnerability from a candidate CPE. Applicability is scoped to each
current Hardware-CVE pair using the *existing* catalogue evaluator.
"""
from collections import defaultdict

from django.utils import timezone
from rest_framework.exceptions import ValidationError

from assets.inventory_integrity import inventory_integrity_issues
from assets.models import (
    Asset, NetworkInterface, OTSystem, SoftwareInstallation, SystemMembership,
)
from vulnerabilities.models import AssetCpe, AssetCveAssessment, Cve
from .cve_general_assessment import _context, _digest
from .cve_applicability import assessment_evidence_is_current
from .cve_technical_status import related_assets_for_cves
from .identity import fingerprint, hardware_identity, software_identity


def _date(value):
    return value.isoformat() if value is not None else None


def _confirmed_cpes(assets):
    """Currently confirmed NVD CPEs only: current fingerprint, nondeprecated."""
    by_asset = {asset.pk: [] for asset in assets}
    identities = {}
    for asset in assets:
        try:
            identity = (hardware_identity(asset) if asset.asset_type == "HARDWARE"
                        else software_identity(asset))
            identities[asset.pk] = fingerprint(identity)
        except (ValueError, AttributeError, TypeError):
            # An unidentifiable asset must not receive a current CPE claim.
            continue
    for association in AssetCpe.objects.filter(
        asset_id__in=identities,
        validation_status=AssetCpe.Validation.CONFIRMED,
        cpe__deprecated=False,
    ).select_related("cpe").order_by("asset_id", "pk"):
        if association.validated_identity_fingerprint != identities[association.asset_id]:
            continue
        part = "h" if association.asset.asset_type == "HARDWARE" else None
        cpe_name = association.cpe.cpe_name
        if not cpe_name.startswith("cpe:2.3:"):
            continue
        if part == "h" and not cpe_name.startswith("cpe:2.3:h:"):
            continue
        if part is None and not cpe_name.startswith(("cpe:2.3:a:", "cpe:2.3:o:")):
            continue
        by_asset[association.asset_id].append({
            "asset_cpe_id": association.pk,
            "cpe_name_id": str(association.cpe.cpe_name_id),
            "cpe_name": cpe_name,
            "title": association.cpe.title,
            "justification": association.justification,
            "validated_at": _date(association.validated_at),
        })
    return by_asset


def _current_justifications(cves):
    """Latest current ANALYST justification per operative hardware/CVE result.

    Revalidate by the same inventory and configuration fingerprints as the
    detail page. A stale recent review never revives a past positive record.
    Automatic evidence does not masquerade as a human justification.
    """
    if not cves:
        return {}
    ids = [cve.pk for cve in cves]
    latest = {}
    for row in AssetCveAssessment.objects.filter(
        cve_id__in=ids,
    ).order_by("cve_id", "hardware_id", "configuration_index",
               "-decided_at", "-pk"):
        key = (row.cve_id, row.hardware_id, row.configuration_index)
        latest.setdefault(key, row)
    by_cve = {cve.pk: cve for cve in cves}
    validated = {}
    contexts = {}
    for (cve_pk, hardware_id, index), row in latest.items():
        if isinstance(row.criteria_evidence, dict) and (
            row.criteria_evidence.get("origin") == "SYSTEM"
        ):
            continue
        cve = by_cve[cve_pk]
        if not isinstance(cve.configurations, list) or index >= len(cve.configurations):
            continue
        key = (cve_pk, hardware_id)
        if key not in contexts:
            try:
                hardware, _, _, _, inventory_fp = _context(cve.cve_id, hardware_id)
                contexts[key] = (hardware, inventory_fp)
            except (ValueError, AttributeError, ValidationError):
                contexts[key] = (None, None)
            except Exception as exc:
                # A removed/not-found hardware is not evidence of currency.
                from django.http import Http404
                if not isinstance(exc, Http404):
                    raise
                contexts[key] = (None, None)
        hardware, inventory_fp = contexts[key]
        if hardware is None or not assessment_evidence_is_current(
            row, cve, hardware, inventory_fp, _digest(cve.configurations[index])
        ):
            continue
        validated.setdefault(key, []).append(row)
    return validated


def _report_findings(cves, hardware_by_id, software_installations):
    """Evaluate current pairs, not globally shared CVE labels."""
    main, conditional = [], []
    latest_manual = _current_justifications(cves)
    related = related_assets_for_cves(cves)
    for cve in cves:
        for context in related.get(cve.pk, []):
            hardware_id = context["hardware_id"]
            if hardware_id not in hardware_by_id:
                continue
            applicability = context.get("scoped_applicability") or {}
            status = applicability.get("status")
            if status not in ("APPLIES", "APPLIES_CONDITIONAL"):
                continue
            source = applicability.get("source")
            if source not in ("SYSTEM", "ANALYST"):
                continue
            # These records are validated against current fingerprints above.
            records = [
                row for row in latest_manual.get((cve.pk, hardware_id), [])
                if row.status == status
            ] if source == "ANALYST" else []
            evidence_software = []
            for asset in context.get("assets", []):
                if asset.get("asset_type") != "SOFTWARE":
                    continue
                installation = software_installations.get(asset.get("installation_id"))
                if installation is not None and installation["hardware_id"] == hardware_id:
                    evidence_software.append({
                        "asset_id": installation["software_asset_id"],
                        "installation_id": installation["id"],
                        "name": installation["software_name"],
                        "software_type": installation["software_type"],
                        "version": installation["version"],
                        "role_nvd": asset.get("role"),
                    })
            item = {
                "cve_id": cve.cve_id,
                "hardware_id": hardware_id,
                "hardware_name": hardware_by_id[hardware_id]["name"],
                "hardware_criticality": hardware_by_id[hardware_id]["criticality"],
                "hardware_role_nvd": context.get("hardware_role"),
                "severity": cve.severity or "UNKNOWN",
                "cvss_base_score": (
                    str(cve.base_score) if cve.base_score is not None else None
                ),
                "description": cve.description,
                "published": _date(cve.published),
                "last_modified": _date(cve.last_modified),
                "nvd_retrieved_at": _date(cve.retrieved_at),
                "nvd_references": cve.references,
                "applicability_status": status,
                "applicability_source": source,
                "justifications": [{
                    "assessment_id": row.pk,
                    "configuration_index": row.configuration_index,
                    "justification": row.justification,
                    "decided_at": _date(row.decided_at),
                } for row in records],
                "evaluated_software": evidence_software,
                "automatic_nvd_evidence": (
                    context.get("automatic_evidence")
                    if source == "SYSTEM" and status == "APPLIES" else None
                ),
            }
            if status == "APPLIES":
                main.append(item)
            else:
                conditional.append(item)
    sort_key = lambda row: (row["cve_id"], row["hardware_id"])
    return sorted(main, key=sort_key), sorted(conditional, key=sort_key)


def collect_hardening_report_data(*, generated_at=None):
    """Return an immutable-in-practice plain dict ready for JSON/PDF rendering.

    Reject incomplete active inventory rather than silently inventing
    criticalities, OT systems or asset identities. No model writes or NVD I/O.
    """
    issues = inventory_integrity_issues()
    if issues:
        raise ValidationError({
            "inventory": "Completa el inventario activo antes de generar el informe.",
            "issues": issues,
        })

    generated_at = generated_at or timezone.now()
    assets = list(Asset.objects.filter(
        inventory_status=Asset.InventoryStatus.ACTIVE,
    ).select_related("hardware", "software").order_by("pk"))
    hardware = [a for a in assets if a.asset_type == Asset.AssetType.HARDWARE]
    software = [a for a in assets if a.asset_type == Asset.AssetType.SOFTWARE]
    hardware_ids = {item.pk for item in hardware}
    software_ids = {item.pk for item in software}
    cpes = _confirmed_cpes(assets)

    systems = list(OTSystem.objects.filter(
        status=OTSystem.Status.ACTIVE,
    ).order_by("pk"))
    membership_by_system = defaultdict(list)
    membership_by_hardware = defaultdict(list)
    for membership in SystemMembership.objects.filter(
        system_id__in=[system.pk for system in systems],
        hardware_id__in=hardware_ids,
        unlinked_at__isnull=True,
    ).order_by("system_id", "hardware_id", "pk"):
        membership_by_system[membership.system_id].append(membership.hardware_id)
        membership_by_hardware[membership.hardware_id].append(membership.system_id)

    interfaces = defaultdict(list)
    for interface in NetworkInterface.objects.filter(
        hardware_id__in=hardware_ids,
    ).order_by("hardware_id", "pk"):
        interfaces[interface.hardware_id].append({
            "id": interface.pk,
            "mac": interface.mac,
            "declared_ip": interface.declared_ip,
            "identified_at": _date(interface.identified_at),
        })

    installs_by_hardware = defaultdict(list)
    install_by_id = {}
    software_hardware = defaultdict(set)
    for installation in SoftwareInstallation.objects.filter(
        hardware_id__in=hardware_ids,
        software_id__in=software_ids,
        unlinked_at__isnull=True,
    ).select_related("software", "software__asset").order_by("hardware_id", "pk"):
        item = {
            "id": installation.pk, "hardware_id": installation.hardware_id,
            "software_asset_id": installation.software_id,
            "software_name": installation.software.asset.name,
            "software_type": installation.software.software_type,
            "manufacturer": installation.software.manufacturer,
            "product": installation.software.product,
            "version": installation.software.version,
            "registered_at": _date(installation.registered_at),
        }
        installs_by_hardware[installation.hardware_id].append(item)
        install_by_id[installation.pk] = item
        software_hardware[installation.software_id].add(installation.hardware_id)

    hardware_rows = [{
        "id": a.pk, "name": a.name, "description": a.description,
        "criticality": a.criticality, "impact": a.impact,
        "manufacturer": a.hardware.manufacturer, "model": a.hardware.model,
        "cpu_model": a.hardware.cpu_model, "role": a.hardware.role,
        "serial_number": a.hardware.serial_number,
        "physical_location": a.hardware.physical_location,
        "system_ids": membership_by_hardware[a.pk],
        "interfaces": interfaces[a.pk],
        "software_installations": installs_by_hardware[a.pk],
        "confirmed_cpes": cpes[a.pk],
    } for a in hardware]

    software_rows = [{
        "id": a.pk, "name": a.name, "description": a.description,
        "criticality": a.criticality, "impact": a.impact,
        "software_type": a.software.software_type,
        "manufacturer": a.software.manufacturer,
        "product": a.software.product, "version": a.software.version,
        "hardware_ids": sorted(software_hardware[a.pk]),
        "confirmed_cpes": cpes[a.pk],
    } for a in software]

    system_rows = [{
        "id": s.pk, "name": s.name, "description": s.description,
        "criticality": s.criticality,
        "criticality_justification": s.criticality_justification,
        "impact": s.impact,
        "hardware_ids": membership_by_system[s.pk],
    } for s in systems]

    # Catalogue's related-assets projection already incorporates current
    # analyst decisions, NVD version limits and verification of CPE identities.
    # Never infer a finding merely from an AssetCveFinding candidate.
    cves = list(Cve.objects.filter(
        fetch_status=Cve.FetchStatus.COMPLETED,
    ).order_by("cve_id"))
    hardware_by_id = {row["id"]: row for row in hardware_rows}
    main, conditional = _report_findings(cves, hardware_by_id, install_by_id)
    return {
        "schema_version": 1,
        "generated_at": _date(generated_at),
        "scope": "ACTIVE_INVENTORY",
        "summary": {
            "systems": len(system_rows),
            "hardware": len(hardware_rows),
            "software_variants": len(software_rows),
            "current_installations": len(install_by_id),
            "network_interfaces": sum(len(rows) for rows in interfaces.values()),
            "confirmed_cpes": sum(len(rows) for rows in cpes.values()),
            "applicable_hardware_cve_pairs": len(main),
            "conditional_hardware_cve_pairs": len(conditional),
            "distinct_applicable_cves": len({row["cve_id"] for row in main}),
            "distinct_conditional_cves": len({row["cve_id"] for row in conditional}),
        },
        "systems": system_rows,
        "hardware": hardware_rows,
        "software": software_rows,
        "applicable_vulnerabilities": main,
        "conditional_vulnerabilities": conditional,
        "communications": [],  # Phase 3: top-3 observed active traffic.
    }
