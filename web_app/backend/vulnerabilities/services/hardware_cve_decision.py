"""Audited hardware/CVE human decisions, never synthetic software installs."""
from django.db import transaction
from rest_framework.exceptions import ValidationError

from vulnerabilities.models import (
    AssetCveAssessment, AssetCveFinding, HardwareCveDecision,
)
from .cve_configuration_evaluator import evaluate_configurations
from .cve_applicability import automatic_positive_evidence
from .cve_general_assessment import _context, _digest

PENDING = "PENDING_REVIEW"
FINAL = ("APPLIES", "NOT_APPLICABLE")


def nvd_decision_fingerprint(cve):
    return _digest({
        "configurations": cve.configurations,
        "last_modified": cve.last_modified.isoformat() if cve.last_modified else None,
    })


def serialize_hardware_decision(row, inventory_fp, nvd_fp):
    if row is None:
        return None
    stale = row.inventory_fingerprint != inventory_fp or row.nvd_fingerprint != nvd_fp
    return {
        "id": row.pk, "status": row.status,
        "effective_status": PENDING if stale else row.status,
        "stale": stale, "justification": row.justification,
        "evidence_description": row.evidence_description,
        "evidence_reference": row.evidence_reference,
        "inventory_fingerprint": row.inventory_fingerprint,
        "nvd_fingerprint": row.nvd_fingerprint,
        "decided_by": row.decided_by.username if row.decided_by else None,
        "decided_at": row.decided_at,
    }


def hardware_decision_context(cve, hardware, inventory_fp, *, max_history=30):
    nvd_fp = nvd_decision_fingerprint(cve)
    history = list(HardwareCveDecision.objects.filter(
        cve=cve, hardware=hardware
    ).select_related("decided_by")[:max_history])
    return {
        "nvd_fingerprint": nvd_fp,
        "latest": serialize_hardware_decision(
            history[0], inventory_fp, nvd_fp
        ) if history else None,
        "history": [
            serialize_hardware_decision(row, inventory_fp, nvd_fp)
            for row in history
        ],
    }


@transaction.atomic
def record_hardware_cve_decision(cve_id, hardware_id, actor, *,
                                  verdict, justification, evidence_description,
                                  evidence_reference="", inventory_fingerprint,
                                  nvd_fingerprint, override_confirmed_match=False):
    hardware, cve, confirmed, installed, actual_inventory = _context(
        cve_id, hardware_id, lock=True
    )
    # The decision must belong to an already discovered/reviewed relation.
    has_relation = (
        AssetCveFinding.objects.filter(hardware=hardware, cve=cve).exists()
        or AssetCveAssessment.objects.filter(hardware=hardware, cve=cve).exists()
        or HardwareCveDecision.objects.filter(hardware=hardware, cve=cve).exists()
    )
    if not has_relation:
        raise ValidationError({
            "hardware": "Primero relaciona el CVE con este hardware mediante el descubrimiento."
        })

    current_nvd = nvd_decision_fingerprint(cve)
    if inventory_fingerprint != actual_inventory or nvd_fingerprint != current_nvd:
        raise ValidationError({
            "evidence": "Cambió el inventario o el registro NVD. Actualiza la evaluación antes de guardar."
        })
    if verdict in FINAL:
        if len(justification.strip()) < 20:
            raise ValidationError({"justification": "Justifica la conclusión (mínimo 20 caracteres)."})
        if len(evidence_description.strip()) < 10:
            raise ValidationError({"evidence_description":
                "Documenta evidencia verificable (mínimo 10 caracteres)."})
    if verdict == "NOT_APPLICABLE":
        technical = evaluate_configurations(cve.configurations, list(confirmed), installed)
        if automatic_positive_evidence(technical) and not override_confirmed_match:
            raise ValidationError({"override_confirmed_match":
                "El sistema encontró una coincidencia positiva. Confirma expresamente que tu evidencia externa justifica esta excepción."})

    decision = HardwareCveDecision.objects.create(
        hardware=hardware, cve=cve, status=verdict,
        justification=justification.strip(),
        evidence_description=evidence_description.strip(),
        evidence_reference=evidence_reference.strip(),
        inventory_fingerprint=actual_inventory, nvd_fingerprint=current_nvd,
        decided_by=actor,
    )
    return serialize_hardware_decision(decision, actual_inventory, current_nvd)
