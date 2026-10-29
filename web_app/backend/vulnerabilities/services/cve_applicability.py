"""Conservative, read-only applicability for a hardware/CVE pair.

A complete positive branch may be automatically applicable. Negative proof
requires an explicit verified version exclusion or a narrowly verified distinct
hardware platform for every applicable NVD alternative. This module is read-only.
"""
from django.utils import timezone

from .cve_configuration_evaluator import COMPATIBLE, EXCLUDED

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


def _negative_proof(node):
    """Return demonstrated exclusions, not inferred absence or partial evidence.

    For AND, one proved-false condition invalidates the branch. For OR, *all*
    alternatives must be demonstrably false. Negated/unsupported structures
    remain unknown. We deliberately do not auto-exclude vulnerable hardware
    products merely by observing a different or missing model.
    """
    if not isinstance(node, dict) or node.get("result") != EXCLUDED:
        return None
    if node.get("kind") == "CRITERION":
        part = node.get("part")
        cpe = node.get("criteria")
        if not isinstance(cpe, str):
            return None
        if (part in ("a", "o") and node.get("vulnerable") is True
                and node.get("identity") == "MATCHED"
                and node.get("matched_cpe")
                and node.get("software_asset_id")
                and node.get("software_installation_id")
                and node.get("installed_version")):
            fields = cpe.split(":")
            if len(fields) != 13:
                return None
            bounds = node.get("version_constraints") or {}
            if not bounds and fields[5] in ("*", "-"):
                return None  # No verified version boundary excludes this software.
            return [{
                "reason": "FIRMWARE_OR_SOFTWARE_VERSION_EXCLUDED",
                "criterion": cpe,
                "confirmed_cpe": node["matched_cpe"],
                "software_asset_id": node["software_asset_id"],
                "software_installation_id": node["software_installation_id"],
                "installed_version": node["installed_version"],
                "version_constraints": bounds,
                "explanation": node.get("reason", ""),
            }]
        if (part == "h" and node.get("vulnerable") is False
                and node.get("identity") == "DISTINCT"
                and node.get("distinct_confirmed_cpes")):
            # DISTINCT is emitted solely by the evaluator's explicit
            # independently verified product-line separation rule.
            return [{
                "reason": "DISTINCT_PLATFORM_VERIFIED",
                "criterion": cpe,
                "confirmed_hardware_cpes": node["distinct_confirmed_cpes"],
                "explanation": node.get("reason", ""),
            }]
        return None
    if (node.get("kind") != "GROUP" or node.get("negate")
            or node.get("operator") not in ("AND", "OR")):
        return None
    children = node.get("children")
    if not isinstance(children, list) or not children:
        return None
    if node["operator"] == "AND":
        # Every proof is independently enough to falsify an AND branch.
        for child in children:
            proof = _negative_proof(child)
            if proof:
                return proof
        return None
    excluded = []
    for child in children:
        proof = _negative_proof(child)
        if not proof:
            return None
        excluded.extend(proof)
    return excluded


def verified_negative_configurations(technical):
    """Scoped negative evidence, even when another configuration is unknown."""
    if not isinstance(technical, dict):
        return []
    result = []
    for index, config in enumerate(technical.get("configurations", [])):
        proof = _negative_proof(config)
        if proof:
            result.append({
                "configuration_index": index,
                "configuration_position": index + 1,
                "excluded_by": proof,
            })
    return result


def automatic_negative_evidence(technical):
    """Global NOT_APPLICABLE requires proof for *every* NVD configuration."""
    if not isinstance(technical, dict) or technical.get("result") != EXCLUDED:
        return None
    configs = technical.get("configurations")
    if not isinstance(configs, list) or not configs:
        return None
    negatives = verified_negative_configurations(technical)
    if len(negatives) != len(configs):
        return None
    return {"configurations": negatives}


def resolve_applicability(technical_result, analyst_status, *,
                          automatic_evidence=None, automatic_negative=None):
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
    if technical_result == EXCLUDED and automatic_negative is not None:
        return {"status": NOT_APPLICABLE, "source": SYSTEM}
    return {"status": PENDING_REVIEW, "source": NONE}


def scoped_applicability(technical, analyst_status, *,
                         inventory_fingerprint, cve, hardware_id):
    """Expose reproducible CURRENT evidence; retain history only in analyst
    records. The official NVD record and CPE identity data remain unchanged.
    """
    proof = automatic_positive_evidence(technical)
    negative = automatic_negative_evidence(technical)
    state = resolve_applicability(technical.get("result"), analyst_status,
                                  automatic_evidence=proof,
                                  automatic_negative=negative)
    evidence = None
    if state["source"] == SYSTEM:
        from .cve_general_assessment import _digest
        if state["status"] == APPLIES:
            configuration = cve.configurations[proof["configuration_index"]]
            evidence = {
                **proof, "hardware_id": hardware_id,
                "inventory_fingerprint": inventory_fingerprint,
                "configuration_fingerprint": _digest(configuration),
                "nvd_last_modified": cve.last_modified,
                "nvd_retrieved_at": cve.retrieved_at,
            }
        else:
            evidence = {
                **negative, "hardware_id": hardware_id,
                "inventory_fingerprint": inventory_fingerprint,
                "configuration_fingerprints": [
                    _digest(config) for config in cve.configurations
                ],
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
