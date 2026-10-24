"""Persist one reproducible SYSTEM confirmation in the existing NVD history.

This is the same AssetCveAssessment timeline used for analyst decisions:
no second verdict model, no invented software installation, no auto-negatives.
The worker calls this after CVE discovery; the detail may synchronise existing
NVD results through its explicit idempotent POST endpoint.
"""
from django.db import transaction

from vulnerabilities.models import AssetCveAssessment
from .cve_applicability import automatic_positive_evidence
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
        return None, False

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
