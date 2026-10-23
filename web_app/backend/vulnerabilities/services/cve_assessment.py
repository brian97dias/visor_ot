"""Assisted, narrowly scoped CVE assessment for Phoenix Contact IL PN BK-PAC.

No NVD calls, automatic CPE matching, fabricated CPEs, or inventory mutation.
Each analyst decision is an immutable row; stale decisions are never presented
as current if the inventory, active installations or NVD config changed.
"""
import hashlib
import json
from uuid import UUID

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound, ValidationError

from assets.models import Asset, Hardware, SoftwareInstallation
from vulnerabilities.models import AssetCpe, AssetCveAssessment, Cve
from .cve_ingestion import (
    EXPERIMENTAL_CVE_ID, HARDWARE_CRITERION, FIRMWARE_CRITERION,
    CveResponseError, find_experimental_configuration,
)
from .identity import fingerprint, hardware_identity, software_identity

EXPERIMENTAL_HARDWARE_ID = 2
EXPECTED_HARDWARE_CPE_UUID = UUID("f9fc7f57-0f76-4dcb-aca0-3b767bc3dafd")
VERDICTS = ("UNKNOWN", "CONFIRMED", "NOT_MATCH")
EVIDENCE_SOURCES = ("INVENTORY", "DOCUMENTATION", "SIMULATION")


def _digest(data):
    blob = json.dumps(data, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _context(hardware_id, *, lock=False):
    """Read current evidence only; software inventory by itself is NOT installation."""
    if hardware_id != EXPERIMENTAL_HARDWARE_ID:
        raise NotFound("La fase experimental evalúa únicamente el hardware #2.")
    hw_query = Hardware.objects.select_related("asset")
    if lock:
        hw_query = hw_query.select_for_update(of=("self",))
    hardware = get_object_or_404(hw_query, pk=hardware_id)
    if hardware.asset.inventory_status != Asset.InventoryStatus.ACTIVE:
        raise ValidationError({"hardware": "El hardware ya no está vigente."})

    cve = get_object_or_404(Cve, cve_id=EXPERIMENTAL_CVE_ID)
    if cve.fetch_status != Cve.FetchStatus.COMPLETED or not cve.retrieved_at:
        raise ValidationError({"cve": "Debe existir un CVE verificado y completado en NVD."})
    try:
        scenario = find_experimental_configuration(cve.configurations)
    except CveResponseError as error:
        raise ValidationError({"cve": str(error)}) from error
    identity = fingerprint(hardware_identity(hardware.asset))
    associations = list(AssetCpe.objects.filter(
        asset_id=hardware_id,
        validation_status=AssetCpe.Validation.CONFIRMED,
        validated_identity_fingerprint=identity,
        cpe__cpe_name_id=EXPECTED_HARDWARE_CPE_UUID,
        cpe__cpe_name=HARDWARE_CRITERION,
    ).select_related("cpe", "source_run"))
    selected_cpe = associations[0] if associations else None

    # The query excludes archived software and unlinked installations.
    installations = list(SoftwareInstallation.objects.filter(
        hardware_id=hardware_id, unlinked_at__isnull=True,
        software__software_type="FIRMWARE",
        software__asset__inventory_status=Asset.InventoryStatus.ACTIVE,
    ).select_related("software", "software__asset").order_by("pk"))
    active = []
    for installation in installations:
        sw = installation.software
        active.append({
            "installation_id": installation.pk,
            "software_asset_id": sw.asset_id,
            "software_name": sw.asset.name,
            "manufacturer": sw.manufacturer,
            "product": sw.product,
            "version": sw.version,
            "software_type": sw.software_type,
            "identity_fingerprint": fingerprint(software_identity(sw.asset)),
            "registered_at": installation.registered_at.isoformat(),
        })

    # Fingerprint includes all relevant affirmative hardware evidence and the
    # complete set of active firmware links, not merely the selected candidate.
    # It deliberately excludes a display-only name change.
    identity_basis = {
        "hardware": identity,
        "confirmed_hardware_cpe": (
            {
                "association_id": selected_cpe.pk,
                "source_run_id": selected_cpe.source_run_id,
                "validated_at": selected_cpe.validated_at.isoformat(),
            } if selected_cpe else None
        ),
        "active_firmware": [
            {"installation_id": x["installation_id"],
             "software_asset_id": x["software_asset_id"],
             "identity_fingerprint": x["identity_fingerprint"]}
            for x in active
        ],
    }
    return {
        "hardware": hardware, "cve": cve, "scenario": scenario,
        "hardware_cpe": selected_cpe,
        "installations": active, "inventory_fingerprint": _digest(identity_basis),
        "configuration_fingerprint": _digest(scenario["configuration"]),
    }


def display_cpe_criterion(criteria):
    """Human-readable label derived from NVD's CPE match string (not a CPE ID)."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[:2] != ["cpe", "2.3"]:
        return criteria
    vendor = "Phoenix Contact" if parts[3] == "phoenixcontact" else parts[3].replace("_", " ").title()
    words = parts[4].replace("_", " ").split()
    product = " ".join(
        word.capitalize() if word.casefold() == "firmware" else word.upper()
        for word in words
    )
    return f"{vendor} {product}"


def _snapshot(context, *, verdict, installation, source, note, complete):
    hw_cpe = context["hardware_cpe"]
    criterion_hw = context["scenario"]["hardware"]
    criterion_fw = context["scenario"]["firmware"]
    hw_verified = hw_cpe is not None
    bounds = {
        key: value for key, value in criterion_fw.items()
        if key in ("versionStartIncluding", "versionStartExcluding",
                   "versionEndIncluding", "versionEndExcluding")
    }
    # Version comparisons have not been implemented in this experimental
    # phase: a positive firmware verdict cannot bypass NVD version bounds.
    fw_positive = bool(installation and verdict == "CONFIRMED" and not bounds)
    fw_negative = bool(installation and verdict == "NOT_MATCH")
    # Negative conclusion requires a witnessed installation, an explicit
    # complete-inventory attestation and NO other unevaluated firmware links.
    justified_negative = (
        hw_verified and fw_negative and complete
        and len(context["installations"]) == 1
    )
    if hw_verified and fw_positive:
        status = AssetCveAssessment.Status.APPLIES
    elif justified_negative:
        status = AssetCveAssessment.Status.NOT_APPLICABLE
    else:
        status = AssetCveAssessment.Status.PENDING_REVIEW

    hardware_evidence = {
        "criteria": criterion_hw["criteria"],
        "match_criteria_id": criterion_hw.get("matchCriteriaId"),
        "nvd_vulnerable": criterion_hw["vulnerable"],
        "state": "SATISFIED" if hw_verified else "UNVERIFIED",
        "source": "CONFIRMED_CPE" if hw_verified else "INVENTORY_ONLY",
        "asset_id": context["hardware"].pk,
        "asset_cpe_id": hw_cpe.pk if hw_cpe else None,
        "cpe_name_id": str(hw_cpe.cpe.cpe_name_id) if hw_cpe else None,
    }
    firmware_evidence = {
        "criteria": criterion_fw["criteria"],
        "match_criteria_id": criterion_fw.get("matchCriteriaId"),
        "nvd_vulnerable": criterion_fw["vulnerable"],
        "display_name": display_cpe_criterion(criterion_fw["criteria"]),
        "state": "SATISFIED" if fw_positive else (
            "NOT_SATISFIED" if justified_negative else "UNVERIFIED"
        ),
        "source": source,
        "analyst_verdict": verdict,
        "selected_installation_id": installation["installation_id"] if installation else None,
        "software_asset_id": installation["software_asset_id"] if installation else None,
        "software_identity": installation if installation else None,
        "active_installation_ids": [r["installation_id"] for r in context["installations"]],
        "inventory_declared_complete": complete,
        "note": note,
        # No official dictionary CPE can be inferred from this cpeMatch pattern.
        "official_cpe_name_id": None,
        "version_constraints": bounds,
        "version_check": "REQUIRES_REVIEW" if bounds else "NOT_REQUIRED",
    }
    return status, {"hardware": hardware_evidence, "firmware": firmware_evidence}


def _latest_record(context):
    return AssetCveAssessment.objects.filter(
        hardware=context["hardware"], cve=context["cve"]
    ).select_related("decided_by").first()


def _serialize_record(record, context):
    if record is None:
        return None
    is_current = (
        record.inventory_fingerprint == context["inventory_fingerprint"]
        and record.configuration_fingerprint == context["configuration_fingerprint"]
    )
    return {
        "id": record.pk,
        "status": record.status,
        "effective_status": record.status if is_current else "PENDING_REVIEW",
        "stale": not is_current,
        "configuration_index": record.configuration_index,
        "configuration_fingerprint": record.configuration_fingerprint,
        "inventory_fingerprint": record.inventory_fingerprint,
        "criteria_evidence": record.criteria_evidence,
        "software_installation_id": record.software_installation_id,
        "justification": record.justification,
        "decided_by": record.decided_by.username if record.decided_by else None,
        "decided_at": record.decided_at,
    }


def assessment_context(hardware_id):
    """Read-only preview: never treats names or missing data as affirmation."""
    context = _context(hardware_id)
    hw_cpe = context["hardware_cpe"]
    last = _latest_record(context)
    status, evidence = _snapshot(
        context, verdict="UNKNOWN", installation=None,
        source="INVENTORY", note="", complete=False,
    )
    # Snapshot status is always PENDING here; historical decision read separately.
    firmware_asset_4 = Asset.objects.filter(
        pk=4, asset_type=Asset.AssetType.SOFTWARE
    ).values("id", "name", "inventory_status").first()
    return {
        "hardware_asset_id": context["hardware"].pk,
        "hardware_name": context["hardware"].asset.name,
        "cve_id": context["cve"].cve_id,
        "description": context["cve"].description,
        "severity": context["cve"].severity,
        "base_score": context["cve"].base_score,
        "configuration_position": context["scenario"]["position"],
        "configuration_index": context["scenario"]["index"],
        "configuration_fingerprint": context["configuration_fingerprint"],
        "inventory_fingerprint": context["inventory_fingerprint"],
        "configuration": context["scenario"]["configuration"],
        "hardware_cpe_confirmed": bool(hw_cpe),
        "criteria_evidence": evidence,
        "active_firmware_installations": context["installations"],
        "software_asset_4": {
            **firmware_asset_4,
            "installed_on_hardware": any(
                row["software_asset_id"] == 4 for row in context["installations"]
            ),
        } if firmware_asset_4 else None,
        "initial_status": status,
        "latest_assessment": _serialize_record(last, context),
        "history": [
            _serialize_record(record, context)
            for record in AssetCveAssessment.objects.filter(
                hardware=context["hardware"], cve=context["cve"]
            ).select_related("decided_by")[:30]
        ],
    }


@transaction.atomic
def record_assessment(hardware_id, actor, *, firmware_verdict="UNKNOWN",
                      software_installation_id=None, evidence_source="INVENTORY",
                      inventory_declared_complete=False, justification="",
                      expected_inventory_fingerprint=None,
                      expected_configuration_fingerprint=None):
    """One append-only decision; no CPE or installation updates ever occur."""
    context = _context(hardware_id, lock=True)
    if (expected_inventory_fingerprint != context["inventory_fingerprint"]
            or expected_configuration_fingerprint != context["configuration_fingerprint"]):
        raise ValidationError({
            "inventory_fingerprint": "La evidencia cambió. Consulta nuevamente antes de decidir."
        })
    if firmware_verdict not in VERDICTS:
        raise ValidationError({"firmware_verdict": "Decisión de firmware inválida."})
    if evidence_source not in EVIDENCE_SOURCES:
        raise ValidationError({"evidence_source": "Origen de evidencia inválido."})
    reason = justification.strip()
    if not reason:
        raise ValidationError({"justification": "Explica la evidencia o ausencia de evidencia."})
    if len(reason) > 1000:
        raise ValidationError({"justification": "Máximo 1000 caracteres."})
    if type(inventory_declared_complete) is not bool:
        raise ValidationError({"inventory_declared_complete": "Debe ser booleano."})

    installations_by_id = {
        entry["installation_id"]: entry for entry in context["installations"]
    }
    selected = installations_by_id.get(software_installation_id)
    if software_installation_id is not None and selected is None:
        raise ValidationError({"software_installation_id": (
            "La instalación no existe, se desvinculó o no es firmware vigente de este hardware."
        )})
    if firmware_verdict != "UNKNOWN" and selected is None:
        raise ValidationError({
            "software_installation_id": "Para verificar el firmware, selecciona una instalación vigente."
        })
    if firmware_verdict == "UNKNOWN" and selected is not None:
        # It is legitimate to mention a candidate as unverified evidence.
        pass
    if firmware_verdict == "NOT_MATCH" and inventory_declared_complete:
        if len(context["installations"]) != 1:
            raise ValidationError({
                "inventory_declared_complete": (
                    "No puedes descartar la configuración: existen otros firmwares "
                    "instalados o no hay evidencia de instalaciones vigentes."
                )
            })
    status, evidence = _snapshot(
        context, verdict=firmware_verdict, installation=selected,
        source=evidence_source, note=reason,
        complete=inventory_declared_complete,
    )
    record = AssetCveAssessment.objects.create(
        hardware=context["hardware"], cve=context["cve"],
        configuration_index=context["scenario"]["index"],
        configuration_snapshot=context["scenario"]["configuration"],
        configuration_fingerprint=context["configuration_fingerprint"],
        status=status, criteria_evidence=evidence,
        software_installation_id=selected["installation_id"] if selected else None,
        inventory_fingerprint=context["inventory_fingerprint"],
        justification=reason, decided_by=actor,
    )
    return _serialize_record(record, context)
