"""General, conservative NVD configuration review.

A discovered CPE is a *candidate*, not proof of applicability. All NVD
configurations are shown without flattening their AND/OR/negate semantics.
Write actions are available only for a narrowly verified platform-AND-firmware
shape; other structures require a later semantic evaluation engine.
The experimental Phoenix Contact endpoint is retained unchanged.
"""
import hashlib
import json

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import ValidationError

from assets.models import Asset, Hardware, SoftwareInstallation
from vulnerabilities.models import AssetCpe, AssetCveAssessment, Cve
from .identity import fingerprint, hardware_identity, software_identity

VERSION_KEYS = (
    "versionStartIncluding", "versionStartExcluding",
    "versionEndIncluding", "versionEndExcluding",
)


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def _render_tree(node, confirmed_cpes, installed):
    """Represent a nested NVD tree faithfully; do not infer software matches."""
    if not isinstance(node, dict):
        return {"kind": "INVALID", "children": [], "verified": False}
    matches = node.get("cpeMatch", [])
    children = [_render_tree(child, confirmed_cpes, installed)
                for child in node.get("nodes", []) if isinstance(child, dict)]
    for item in matches if isinstance(matches, list) else []:
        if not isinstance(item, dict):
            continue
        criteria = item.get("criteria", "")
        parts = criteria.split(":") if isinstance(criteria, str) else []
        part = parts[2] if len(parts) == 13 else ""
        hw = part == "h"
        association = confirmed_cpes.get(criteria) if hw else None
        bounds = {key: item[key] for key in VERSION_KEYS if key in item}
        children.append({
            "kind": "CRITERION", "criteria": criteria,
            "match_criteria_id": item.get("matchCriteriaId"),
            "vulnerable": item.get("vulnerable"),
            "part": part, "bounds": bounds,
            "state": "SATISFIED" if association and not bounds else "UNVERIFIED",
            "confirmed_asset_cpe_id": association.pk if association and not bounds else None,
            "installed_software": installed if part in ("a", "o") else [],
        })
    return {
        "kind": "GROUP", "operator": node.get("operator", "OR"),
        "negate": node.get("negate") is True, "children": children,
    }


def _simple_and_firmware(config, confirmed_cpes):
    """Allow explicit review only for exactly two independent AND criteria.

    One verified non-vulnerable platform CPE + one vulnerable software match.
    No negations, additional nodes or version bounds; we do not pretend to
    support semantic OR resolution or version comparisons yet.
    """
    if not isinstance(config, dict) or config.get("operator") != "AND" or config.get("negate"):
        return None
    nodes = config.get("nodes", [])
    if not isinstance(nodes, list) or len(nodes) != 2:
        return None
    pair = []
    for node in nodes:
        if (not isinstance(node, dict) or node.get("operator") != "OR"
                or node.get("negate") or node.get("nodes")
                or not isinstance(node.get("cpeMatch"), list)
                or len(node["cpeMatch"]) != 1):
            return None
        leaf = node["cpeMatch"][0]
        if (not isinstance(leaf, dict) or any(key in leaf for key in VERSION_KEYS)):
            return None
        pair.append(leaf)
    platform = [x for x in pair if x.get("vulnerable") is False
                and isinstance(x.get("criteria"), str)
                and x["criteria"].startswith("cpe:2.3:h:")]
    target = [x for x in pair if x.get("vulnerable") is True
              and isinstance(x.get("criteria"), str)
              and x["criteria"].startswith(("cpe:2.3:o:", "cpe:2.3:a:"))]
    if len(platform) != 1 or len(target) != 1:
        return None
    if platform[0]["criteria"] not in confirmed_cpes:
        return None
    return {"hardware_criterion": platform[0]["criteria"],
            "software_criterion": target[0]["criteria"]}


def _context(cve_id, hardware_id, *, lock=False):
    queryset = Hardware.objects.select_related("asset")
    if lock:
        queryset = queryset.select_for_update(of=("self",))
    hardware = get_object_or_404(queryset, pk=hardware_id)
    if hardware.asset.inventory_status != Asset.InventoryStatus.ACTIVE:
        raise ValidationError({"hardware": "El hardware no está activo."})
    cve = get_object_or_404(Cve, cve_id=cve_id,
                            fetch_status=Cve.FetchStatus.COMPLETED)
    identity = fingerprint(hardware_identity(hardware.asset))
    confirmed = list(AssetCpe.objects.filter(
        asset_id=hardware_id, validation_status=AssetCpe.Validation.CONFIRMED,
        validated_identity_fingerprint=identity, cpe__deprecated=False,
    ).select_related("cpe").order_by("pk"))
    confirmed_cpes = {assoc.cpe.cpe_name: assoc for assoc in confirmed
                      if assoc.cpe.cpe_name.startswith("cpe:2.3:h:")}
    installations = list(SoftwareInstallation.objects.filter(
        hardware_id=hardware_id, unlinked_at__isnull=True,
        software__asset__inventory_status=Asset.InventoryStatus.ACTIVE,
    ).select_related("software", "software__asset").order_by("pk"))
    installed = [{
        "installation_id": row.pk,
        "software_asset_id": row.software_id,
        "software_name": row.software.asset.name,
        "software_type": row.software.software_type,
        "manufacturer": row.software.manufacturer,
        "product": row.software.product,
        "version": row.software.version,
        "identity": fingerprint(software_identity(row.software.asset)),
    } for row in installations]
    inventory_fp = _digest({
        "hardware": identity,
        "hardware_cpe_associations": [
            (assoc.pk, assoc.cpe.cpe_name, assoc.validated_at.isoformat())
            for assoc in confirmed
        ],
        "installations": [
            (row["installation_id"], row["software_asset_id"], row["identity"])
            for row in installed
        ],
    })
    return hardware, cve, confirmed_cpes, installed, inventory_fp


def _serialize_assessment(item, inventory_fp, config_fp):
    if item is None:
        return None
    stale = item.inventory_fingerprint != inventory_fp or item.configuration_fingerprint != config_fp
    return {
        "id": item.pk, "status": item.status,
        "effective_status": "PENDING_REVIEW" if stale else item.status,
        "stale": stale, "justification": item.justification,
        "software_installation_id": item.software_installation_id,
        "decided_at": item.decided_at,
        "decided_by": item.decided_by.username if item.decided_by else None,
    }


def general_assessment_context(cve_id, hardware_id):
    hw, cve, confirmed, installed, inventory_fp = _context(cve_id, hardware_id)
    configs = []
    for index, config in enumerate(cve.configurations):
        cfg_fp = _digest(config)
        history = list(AssetCveAssessment.objects.filter(
            cve=cve, hardware=hw, configuration_index=index,
        ).select_related("decided_by")[:30])
        current = _serialize_assessment(history[0], inventory_fp, cfg_fp) if history else None
        supported = _simple_and_firmware(config, confirmed)
        configs.append({
            "index": index, "position": index + 1,
            "fingerprint": cfg_fp,
            "tree": _render_tree(config, confirmed, installed),
            "review_supported": bool(supported),
            "review_reason": "" if supported else (
                "La combinación de operadores, negaciones, rangos o CPE "
                "confirmados requiere revisión técnica; no puede confirmarse automáticamente."
            ),
            "hardware_criterion": supported["hardware_criterion"] if supported else None,
            "software_criterion": supported["software_criterion"] if supported else None,
            "latest_assessment": current,
            "history": [_serialize_assessment(row, inventory_fp, cfg_fp) for row in history],
        })
    return {
        "cve_id": cve.cve_id, "hardware_asset_id": hw.pk,
        "hardware_name": hw.asset.name, "inventory_fingerprint": inventory_fp,
        "installed_software": installed,
        "confirmed_hardware_cpes": [
            {"cpe_name": name, "association_id": assoc.pk}
            for name, assoc in confirmed.items()
        ],
        "configurations": configs,
    }


@transaction.atomic
def record_general_assessment(cve_id, hardware_id, actor, *,
                              configuration_index, verdict,
                              software_installation_id=None,
                              inventory_declared_complete=False,
                              justification="", inventory_fingerprint="",
                              configuration_fingerprint=""):
    hw, cve, confirmed, installed, actual_fp = _context(cve_id, hardware_id, lock=True)
    if (type(configuration_index) is not int or configuration_index < 0
            or configuration_index >= len(cve.configurations)):
        raise ValidationError({"configuration_index": "Configuración NVD inválida."})
    config = cve.configurations[configuration_index]
    cfg_fp = _digest(config)
    if inventory_fingerprint != actual_fp or configuration_fingerprint != cfg_fp:
        raise ValidationError({"inventory_fingerprint": "La evidencia cambió; recarga la evaluación."})
    if verdict not in ("CONFIRMED", "NOT_MATCH", "UNKNOWN"):
        raise ValidationError({"verdict": "Decisión no reconocida."})
    reason = justification.strip()
    if not reason or len(reason) > 1000:
        raise ValidationError({"justification": "Justifica tu decisión (máximo 1000 caracteres)."})
    supported = _simple_and_firmware(config, confirmed)
    if not supported and verdict != "UNKNOWN":
        raise ValidationError({"verdict": "La configuración no es verificable mediante este flujo."})
    installed_by_id = {row["installation_id"]: row for row in installed}
    selected = installed_by_id.get(software_installation_id)
    if software_installation_id is not None and selected is None:
        raise ValidationError({"software_installation_id": "La instalación no está vigente."})
    if verdict != "UNKNOWN" and selected is None:
        raise ValidationError({"software_installation_id": "Selecciona software instalado vigente."})
    # A negative verdict only settles an AND branch if the inventory was
    # explicitly attested complete and only this installation was in scope.
    status = "PENDING_REVIEW"
    if supported and verdict == "CONFIRMED" and selected is not None:
        status = "APPLIES"
    elif (supported and verdict == "NOT_MATCH" and selected is not None
          and inventory_declared_complete and len(installed) == 1):
        status = "NOT_APPLICABLE"
    record = AssetCveAssessment.objects.create(
        hardware=hw, cve=cve,
        configuration_index=configuration_index,
        configuration_snapshot=config, configuration_fingerprint=cfg_fp,
        inventory_fingerprint=actual_fp, status=status,
        software_installation_id=selected["installation_id"] if selected else None,
        criteria_evidence={
            "platform": supported["hardware_criterion"] if supported else None,
            "software": supported["software_criterion"] if supported else None,
            "verdict": verdict, "inventory_declared_complete": inventory_declared_complete,
        },
        justification=reason, decided_by=actor,
    )
    return _serialize_assessment(record, actual_fp, cfg_fp)
