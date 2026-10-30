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
        if (part == "a" and node.get("vulnerable") is True
                and node.get("identity") == "PLATFORM_DISTINCT"
                and node.get("distinct_confirmed_cpes")):
            return [{
                "reason": "SOFTWARE_PLATFORM_DISTINCT",
                "criterion": cpe,
                "confirmed_hardware_cpes": node["distinct_confirmed_cpes"],
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
    """Global NOT_APPLICABLE requires complete, reproducible negative proof.

    Contextually FOREIGN branches do not participate in the OR calculation,
    but a scope label alone is never sufficient proof for a global safety
    verdict. Every FOREIGN branch also requires independently verified
    negative evidence. This prevents unsupported vulnerable-hardware CPE
    exclusions from silently producing a false NOT_APPLICABLE.
    """
    if not isinstance(technical, dict) or (
        technical.get("contextual_result", technical.get("result")) != EXCLUDED
    ):
        return None
    configs = technical.get("configurations")
    if not isinstance(configs, list) or not configs:
        return None
    negatives = verified_negative_configurations(technical)
    if len(negatives) != len(configs):
        return None
    scope = technical.get("contextual_selection") or {}
    return {
        "configurations": negatives,
        "foreign_configuration_indexes": scope.get("foreign_indexes", []),
        "evaluated_configuration_indexes": scope.get(
            "evaluated_indexes", list(range(len(configs)))
        ),
        "proof_scope": "HARDWARE_CVE_CONTEXTUAL",
    }



def latest_hardware_cve_decision(cve, hardware, inventory_fingerprint):
    """Latest explicit asset-wide human verdict; never reinterpret a NVD leaf.

    A decision becomes stale if the inventory OR any NVD configuration
    changes. Per-configuration legacy audits remain readable independently.
    """
    from vulnerabilities.models import AssetCveAssessment
    from .cve_general_assessment import _digest
    for row in AssetCveAssessment.objects.filter(
        hardware=hardware, cve=cve,
    ).order_by("-decided_at", "-pk"):
        evidence = row.criteria_evidence if isinstance(row.criteria_evidence, dict) else {}
        if evidence.get("decision_scope") != "HARDWARE_CVE":
            continue
        valid = (
            row.inventory_fingerprint == inventory_fingerprint
            and evidence.get("nvd_fingerprint") == _digest(cve.configurations)
            and 0 <= row.configuration_index < len(cve.configurations)
            and row.configuration_fingerprint ==
                _digest(cve.configurations[row.configuration_index])
        )
        return row, valid
    return None, False


def project_configuration_decisions(technical, human_statuses, *,
                                    stale_human_evidence=False,
                                    global_decision=None):
    """Project ONE hardware/CVE from its NVD alternatives and current audits.

    NVD compatibility remains independent from human audit history. The latest
    current human decision only supersedes its OWN configuration: an UNKNOWN
    reopening does not confirm an NVD exclusion, and a proved NVD positive
    remains a SYSTEM finding even after UNKNOWN. Stale human evidence is
    neither a current positive nor a safe negative.
    """
    # The analyst's latest asset-level decision governs the operative
    # Hardware-CVE relationship, not just one of the NVD OR alternatives.
    # Raw technical evidence is deliberately returned unchanged elsewhere.
    if global_decision in (APPLIES, APPLIES_CONDITIONAL, NOT_APPLICABLE):
        return {"status": global_decision, "source": ANALYST}
    if global_decision == PENDING_REVIEW:
        return {"status": "IN_REVIEW", "source": NONE}
    configs = technical.get("configurations", [])
    excluded = {
        item["configuration_index"]
        for item in verified_negative_configurations(technical)
    }
    scope = technical.get("contextual_selection") or {}
    foreign = set(scope.get("foreign_indexes", []))
    states = []
    for index, config in enumerate(configs):
        human = human_statuses.get(index)
        # Do not discard earlier human decisions from the audit projection.
        # Only a FOREIGN branch with no explicit human verdict is omitted.
        if index in foreign and human is None:
            continue
        if human in (APPLIES, APPLIES_CONDITIONAL, NOT_APPLICABLE):
            states.append((human, ANALYST))
        elif automatic_positive_evidence({
            "result": config["result"], "configurations": [config],
        }) is not None:
            states.append((APPLIES, SYSTEM))
        elif human == PENDING_REVIEW:
            # Explicitly reopened by the analyst; no silent re-exclusion.
            states.append(("IN_REVIEW", NONE))
        elif index in excluded:
            states.append((NOT_APPLICABLE, SYSTEM))
        else:
            states.append((PENDING_REVIEW, NONE))

    # An outdated human review must not be silently shown as a current
    # automatic verdict merely because a CPE still matches the same NVD
    # branch. Other independently current human conclusions may still win.
    if stale_human_evidence and not any(
        state in (APPLIES, APPLIES_CONDITIONAL) and origin == ANALYST
        for state, origin in states
    ):
        return {"status": "STALE", "source": NONE}
    for wanted in (APPLIES, APPLIES_CONDITIONAL):
        if any(state == wanted for state, _ in states):
            origin = (ANALYST if any(
                state == wanted and source == ANALYST for state, source in states
            ) else SYSTEM)
            return {"status": wanted, "source": origin}
    if any(state == "IN_REVIEW" for state, _ in states):
        return {"status": "IN_REVIEW", "source": NONE}
    if ((states and all(state == NOT_APPLICABLE for state, _ in states))
            or (not states and bool(foreign))):
        # A foreign classification by itself is not proof of exclusion.
        # Require verified negative evidence for each ignored configuration;
        # alternatively a scoped human decision for that specific branch.
        foreign_supported = all(
            index in excluded or human_statuses.get(index) == NOT_APPLICABLE
            for index in foreign
        )
        if foreign_supported:
            return {
                "status": NOT_APPLICABLE,
                "source": ANALYST if any(
                    source == ANALYST for _, source in states
                ) else SYSTEM,
            }
    if human_statuses:
        return {"status": "IN_REVIEW", "source": NONE}
    return {"status": PENDING_REVIEW, "source": NONE}


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
    contextual_result = technical.get("contextual_result", technical.get("result"))
    state = resolve_applicability(contextual_result, analyst_status,
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
        "technical_result": contextual_result,
        "nvd_technical_result": technical.get("result"),
        "contextual_selection": technical.get("contextual_selection"),
        "automatic_evidence": evidence,
        "evaluated_at": timezone.now(),
    }
