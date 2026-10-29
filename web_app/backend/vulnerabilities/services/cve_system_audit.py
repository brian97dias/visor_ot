"""Persist defensible SYSTEM confirmations and scoped negative exclusions.

NVD's original alternatives remain unchanged. A negative audit entry for one
configuration is not a global CVE dismissal. Only a proof covering *all*
alternatives permits global NOT_APPLICABLE. Existing analyst decisions are never
overwritten, and no unknown software absence is treated as evidence.
"""
from django.db import transaction

from vulnerabilities.models import AssetCveAssessment
from .cve_applicability import (
    automatic_positive_evidence, verified_negative_configurations,
)
from .cve_configuration_evaluator import evaluate_configurations
from .cve_general_assessment import _context, _digest, VERSION_KEYS

VERSION_WORDING = {
    "versionStartIncluding": "desde (incluido)",
    "versionStartExcluding": "después de (excluido)",
    "versionEndIncluding": "hasta (incluido)",
    "versionEndExcluding": "antes de (excluido)",
}


def _leaves(node):
    if isinstance(node, dict):
        for item in node.get("cpeMatch", []) or []:
            if isinstance(item, dict):
                yield item
        for child in node.get("nodes", []) or []:
            yield from _leaves(child)


def _automatic_justification(proof, configuration):
    evidence = []
    for row in proof["criteria"]:
        criterion = row["criterion"]
        role = "Componente vulnerable" if row["vulnerable"] else "Plataforma requerida"
        verified = row["confirmed_cpe"]
        piece = f"{role}: criterio NVD {criterion}; CPE confirmado {verified}"
        if row.get("installed_version"):
            piece += f"; versión instalada {row['installed_version']}"
        bounds = []
        for leaf in _leaves(configuration):
            if leaf.get("criteria") == criterion:
                bounds = [f"{VERSION_WORDING[k]} {leaf[k]}"
                          for k in VERSION_KEYS if leaf.get(k)]
                break
        if bounds:
            piece += "; rango NVD " + ", ".join(bounds)
        evidence.append(piece)
    return (
        "El sistema confirmó automáticamente la correspondencia de la "
        f"configuración NVD {proof['configuration_position']}: "
        + ". ".join(evidence)
        + ". Todas las condiciones seleccionadas de NVD coinciden con "
          "los CPE confirmados y las versiones vigentes del inventario."
    )


def _negative_justification(proof):
    lines = []
    for condition in proof["excluded_by"]:
        if condition["reason"] == "FIRMWARE_OR_SOFTWARE_VERSION_EXCLUDED":
            version = condition["installed_version"]
            limits = ", ".join(
                f"{VERSION_WORDING.get(key, key)} {value}"
                for key, value in condition["version_constraints"].items()
            )
            if not limits:
                limits = "versión exacta exigida por el CPE NVD"
            lines.append(
                f"Software instalado #{condition['software_asset_id']}, "
                f"instalación #{condition['software_installation_id']}, "
                f"versión {version}; criterio {condition['criterion']}; "
                f"restricción {limits}; {condition['explanation']}"
            )
        else:
            lines.append(
                f"Plataforma comprobada distinta del criterio "
                f"{condition['criterion']}; CPE confirmados: "
                + ", ".join(condition["confirmed_hardware_cpes"])
                + f"; {condition['explanation']}"
            )
    return (
        "El sistema excluyó automáticamente la configuración NVD "
        f"{proof['configuration_position']} mediante evidencia comprobable: "
        + ". ".join(lines)
        + ". Esta conclusión corresponde a la configuración indicada; "
          "otras alternativas del CVE pueden requerir revisión."
    )


@transaction.atomic
def ensure_system_cve_assessment(cve_id, hardware_id):
    """Return (assessment, created); never override a current manual review.

    Lock hardware so concurrent workers/browser reads cannot duplicate the
    current automated assessment for a configuration and fingerprint.
    """
    hw, cve, confirmed, installed, inventory_fp = _context(
        cve_id, hardware_id, lock=True,
    )
    technical = evaluate_configurations(
        cve.configurations, list(confirmed), installed,
    )
    proof = automatic_positive_evidence(technical)
    if proof is None:
        negatives = verified_negative_configurations(technical)
        first = None
        created_any = False
        for negative in negatives:
            index = negative["configuration_index"]
            config = cve.configurations[index]
            fp = _digest(config)
            latest = AssetCveAssessment.objects.filter(
                hardware=hw, cve=cve, configuration_index=index,
            ).order_by("-decided_at", "-pk").first()
            # Never supersede a current analyst decision (including a reopening)
            # or duplicate a previously logged SYSTEM exclusion.
            if (latest and latest.inventory_fingerprint == inventory_fp
                    and latest.configuration_fingerprint == fp):
                if first is None:
                    first = latest
                continue
            record = AssetCveAssessment.objects.create(
                hardware=hw, cve=cve, configuration_index=index,
                configuration_snapshot=config,
                configuration_fingerprint=fp,
                inventory_fingerprint=inventory_fp,
                software_installation_id=None,
                status=AssetCveAssessment.Status.NOT_APPLICABLE,
                criteria_evidence={
                    "origin": "SYSTEM", "negative_evidence": negative,
                },
                justification=_negative_justification(negative),
                decided_by=None,
            )
            if first is None:
                first = record
            created_any = True
        return first, created_any

    index = proof["configuration_index"]
    configuration = cve.configurations[index]
    config_fp = _digest(configuration)
    latest = AssetCveAssessment.objects.filter(
        hardware=hw, cve=cve, configuration_index=index,
    ).order_by("-decided_at", "-pk").first()
    # A human decision (including a reopening) always remains in control
    # while its evidence stays current; a current SYSTEM row is idempotent.
    if (latest and latest.inventory_fingerprint == inventory_fp
            and latest.configuration_fingerprint == config_fp):
        return latest, False

    installation_id = next(
        (item["software_installation_id"] for item in proof["criteria"]
         if item.get("software_installation_id")),
        None,
    )
    record = AssetCveAssessment.objects.create(
        hardware=hw, cve=cve, configuration_index=index,
        configuration_snapshot=configuration,
        configuration_fingerprint=config_fp,
        inventory_fingerprint=inventory_fp,
        software_installation_id=installation_id,
        status=AssetCveAssessment.Status.APPLIES,
        criteria_evidence={"origin": "SYSTEM", "automatic_evidence": proof},
        justification=_automatic_justification(proof, configuration),
        decided_by=None,
    )
    return record, True
