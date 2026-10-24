"""Conservative, read-only applicability for a hardware/CVE pair.

A current AND/OR NVD match is automatically applicable only if the complete
positive branch is supported by *confirmed current* product CPEs. Nothing in
this module creates an analyst assessment or auto-declares NOT_APPLICABLE.
"""
from django.utils import timezone

from .cve_configuration_evaluator import COMPATIBLE

PENDING_REVIEW = "PENDING_REVIEW"
APPLIES = "APPLIES"
NOT_APPLICABLE = "NOT_APPLICABLE"
APPLIES_CONDITIONAL = "APPLIES_CONDITIONAL"
SYSTEM = "SYSTEM"
ANALYST = "ANALYST"
NONE = "NONE"


def _positive_proof(node):
    """Return CPE observations proving a positive branch, or None.

    Unsupported structures, negations and inferred absence cannot satisfy
    an automatic positive. For OR, one positively verified child suffices;
    for AND every condition must have a verified path.
    """
    if not isinstance(node, dict) or node.get("result") != COMPATIBLE:
        return None
    if node.get("kind") == "CRITERION":
        if (node.get("identity") != "MATCHED"
                or not node.get("matched_cpe")
                or not isinstance(node.get("vulnerable"), bool)):
            return None
        return [{
            "criterion": node.get("criteria"),
            "confirmed_cpe": node["matched_cpe"],
            "vulnerable": node["vulnerable"],
            "software_asset_id": node.get("software_asset_id"),
            "software_installation_id": node.get("software_installation_id"),
            "installed_version": node.get("installed_version"),
        }]
    if (node.get("kind") != "GROUP"
            or node.get("negate") or node.get("operator") not in ("AND", "OR")):
        return None
    children = node.get("children")
    if not isinstance(children, list) or not children:
        return None
    if node["operator"] == "AND":
        observations = []
        for child in children:
            proof = _positive_proof(child)
            if proof is None:
                return None
            observations.extend(proof)
        return observations
    for child in children:
        proof = _positive_proof(child)
        if proof is not None:
            return proof
    return None


def automatic_positive_evidence(technical):
    """Prefer the first fully proven NVD alternative; indices are zero-based."""
    if not isinstance(technical, dict) or technical.get("result") != COMPATIBLE:
        return None
    for index, alternative in enumerate(technical.get("configurations", [])):
        proof = _positive_proof(alternative)
        if proof is not None and any(row["vulnerable"] for row in proof):
            return {"configuration_index": index,
                    "configuration_position": index + 1,
                    "criteria": proof}
    return None


def resolve_applicability(technical_result, analyst_status, *,
                          automatic_evidence=None):
    """Separate a system conclusion from append-only human decisions.

    A complete human conclusion has precedence. An incomplete/stale manual
    history never converts an unknown or excluded technical result to safe.
    """
    if analyst_status in (APPLIES, NOT_APPLICABLE):
        return {"status": analyst_status, "source": ANALYST}
    if technical_result == COMPATIBLE and automatic_evidence is not None:
        return {"status": APPLIES, "source": SYSTEM}
    if analyst_status == APPLIES_CONDITIONAL:
        return {"status": APPLIES_CONDITIONAL, "source": ANALYST}
    if analyst_status in ("IN_REVIEW", "STALE"):
        return {"status": analyst_status, "source": NONE}
    return {"status": PENDING_REVIEW, "source": NONE}


def scoped_applicability(technical, analyst_status, *,
                         inventory_fingerprint, cve, hardware_id):
    """Expose reproducible CURRENT evidence; retain history only in analyst
    records. The official NVD record and CPE identity data remain unchanged.
    """
    proof = automatic_positive_evidence(technical)
    state = resolve_applicability(technical.get("result"), analyst_status,
                                  automatic_evidence=proof)
    evidence = None
    if state["source"] == SYSTEM:
        from .cve_general_assessment import _digest
        configuration = cve.configurations[proof["configuration_index"]]
        evidence = {
            **proof,
            "hardware_id": hardware_id,
            "inventory_fingerprint": inventory_fingerprint,
            "configuration_fingerprint": _digest(configuration),
            "nvd_last_modified": cve.last_modified,
            "nvd_retrieved_at": cve.retrieved_at,
        }
    return {
        **state,
        "hardening_category": (
            "CONFIRMED" if state["status"] == APPLIES
            else "CONDITIONAL" if state["status"] == APPLIES_CONDITIONAL
            else "NONE"
        ),
        "technical_result": technical.get("result"),
        "automatic_evidence": evidence,
        "evaluated_at": timezone.now(),
    }
