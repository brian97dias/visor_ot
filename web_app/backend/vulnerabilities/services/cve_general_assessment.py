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
from .cve_configuration_evaluator import evaluate_configurations
from .cve_applicability import scoped_applicability

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


def _annotate_tree(tree, technical):
    """Merge technical observations into the existing visual NVD tree."""
    if not isinstance(tree, dict) or not isinstance(technical, dict):
        return tree
    tree["technical_result"] = technical.get("result", "INDETERMINATE")
    if technical.get("reason"):
        tree["technical_reason"] = technical["reason"]
    for key in ("installed_version", "software_installation_id",
                "software_asset_id", "software_name", "identity", "matched_cpe"):
        if key in technical:
            tree["technical_" + key] = technical[key]
    if tree.get("kind") == "CRITERION":
        chosen = technical.get("software_installation_id")
        tree["installed_software"] = [
            row for row in tree.get("installed_software", [])
            if row["installation_id"] == chosen
        ] if chosen else []
    for visual, evaluated in zip(tree.get("children", []), technical.get("children", [])):
        _annotate_tree(visual, evaluated)
    return tree


def _simple_and_firmware(config, confirmed_cpes, installed=None):
    """Permit scoped analyst review of a simple NVD platform AND software.

    Version-limited software criteria are reviewable only when the conservative
    evaluator verifies an exact confirmed product CPE, the installed version
    and the specific installation. Unbounded legacy manual reviews retain
    their previous behavior for backwards compatibility.
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
        if not isinstance(leaf, dict):
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
    if any(key in platform[0] for key in VERSION_KEYS):
        return None
    supported = {
        "hardware_criterion": platform[0]["criteria"],
        "software_criterion": target[0]["criteria"],
        "required_installation_id": None,
    }
    if any(key in target[0] for key in VERSION_KEYS):
        technical = evaluate_configurations(
            [config], list(confirmed_cpes), installed or []
        )
        if technical["result"] != "COMPATIBLE":
            return None
        # The positive criterion must have selected an actual current
        # software installation, never just a compatible version string.
        def evidence(node):
            if (node.get("kind") == "CRITERION"
                    and node.get("criteria") == target[0]["criteria"]
                    and node.get("identity") == "MATCHED"
                    and node.get("result") == "COMPATIBLE"):
                return node.get("software_installation_id")
            for child in node.get("children", []):
                found = evidence(child)
                if found is not None:
                    return found
            return None

        installation_id = evidence(technical["configurations"][0])
        if installation_id is None:
            return None
        supported["required_installation_id"] = installation_id
    return supported

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
    software_identities = {
        row.software_id: fingerprint(software_identity(row.software.asset))
        for row in installations
    }
    software_associations = list(AssetCpe.objects.filter(
        asset_id__in=software_identities,
        validation_status=AssetCpe.Validation.CONFIRMED,
        cpe__deprecated=False,
    ).select_related("cpe").order_by("asset_id", "pk"))
    confirmed_software = {}
    for association in software_associations:
        if (association.validated_identity_fingerprint
                == software_identities[association.asset_id]
                and association.cpe.cpe_name.startswith(
                    ("cpe:2.3:o:", "cpe:2.3:a:")
                )):
            confirmed_software.setdefault(association.asset_id, []).append(association)
    installed = [{
        "installation_id": row.pk,
        "software_asset_id": row.software_id,
        "software_name": row.software.asset.name,
        "software_type": row.software.software_type,
        "manufacturer": row.software.manufacturer,
        "product": row.software.product,
        "version": row.software.version,
        "identity": software_identities[row.software_id],
        "confirmed_cpes": [
            association.cpe.cpe_name
            for association in confirmed_software.get(row.software_id, [])
        ],
    } for row in installations]
    fingerprint_basis = {
        "hardware": identity,
        "hardware_cpe_associations": [
            (assoc.pk, assoc.cpe.cpe_name, assoc.validated_at.isoformat())
            for assoc in confirmed
        ],
        "installations": [
            (row["installation_id"], row["software_asset_id"], row["identity"])
            for row in installed
        ],
    }
    # Preserve historical generic assessment fingerprints when no confirmed
    # software CPE was used. New software CPE confirmation changes evidence.
    if confirmed_software:
        fingerprint_basis["software_cpe_associations"] = [
            (association.pk, association.cpe.cpe_name,
             association.validated_at.isoformat())
            for associations in confirmed_software.values()
            for association in associations
        ]
    inventory_fp = _digest(fingerprint_basis)
    return hardware, cve, confirmed_cpes, installed, inventory_fp


def _software_snapshot(installation):
    """Immutable display evidence for an installed component at decision time.

    The FK on a negative audit stays NULL: evaluated is not vulnerable.
    """
    if installation is None:
        return None
    return {
        "software_installation_id": installation["installation_id"],
        "software_asset_id": installation["software_asset_id"],
        "software_name": installation["software_name"],
        "software_type": installation["software_type"],
        "installed_version": installation.get("version"),
    }


def _assessment_software_display(item, inventory_fp, config_fp, installed):
    """Return historical snapshots, with a conservative legacy fallback.

    Current inventory names must never be presented as historical versions
    after the inventory or NVD fingerprint has changed.
    """
    evidence = item.criteria_evidence if isinstance(item.criteria_evidence, dict) else {}
    recorded = evidence.get("software_snapshot") or []
    if isinstance(recorded, list) and recorded:
        return recorded
    stale = (item.inventory_fingerprint != inventory_fp or
             item.configuration_fingerprint != config_fp)
    current = {row["installation_id"]: row for row in (installed or [])}
    candidates = []
    if item.software_installation_id:
        candidates.append({"software_installation_id": item.software_installation_id})
    candidates.extend(evidence.get("evaluated_software") or [])
    for proof in (evidence.get("automatic_evidence") or {}).get("criteria", []):
        if proof.get("software_installation_id"):
            candidates.append(proof)
    for proof in (evidence.get("negative_evidence") or {}).get("excluded_by", []):
        if proof.get("software_installation_id"):
            candidates.append(proof)
    for proof in evidence.get("linked_software") or []:
        if proof.get("installation_id"):
            candidates.append({"software_installation_id": proof["installation_id"]})
    displayed = []
    seen = set()
    for proof in candidates:
        installation_id = proof.get("software_installation_id")
        if not installation_id or installation_id in seen:
            continue
        seen.add(installation_id)
        live = current.get(installation_id) if not stale else None
        displayed.append({
            "software_installation_id": installation_id,
            "software_asset_id": proof.get("software_asset_id") or (
                live["software_asset_id"] if live else None),
            "software_name": proof.get("software_name") or (
                live["software_name"] if live else None),
            "software_type": proof.get("software_type") or (
                live["software_type"] if live else None),
            "installed_version": proof.get("installed_version") or (
                live.get("version") if live else None),
        })
    return displayed


def _serialize_assessment(item, inventory_fp, config_fp, installed=None):
    if item is None:
        return None
    stale = item.inventory_fingerprint != inventory_fp or item.configuration_fingerprint != config_fp
    source = ("SYSTEM" if isinstance(item.criteria_evidence, dict)
              and item.criteria_evidence.get("origin") == "SYSTEM"
              else "ANALYST")
    return {
        "id": item.pk, "status": item.status, "source": source,
        "effective_status": "PENDING_REVIEW" if stale else item.status,
        "stale": stale, "justification": item.justification,
        "software_installation_id": item.software_installation_id,
        "software_display": _assessment_software_display(
            item, inventory_fp, config_fp, installed,
        ),
        "decided_at": item.decided_at,
        "decided_by": "VISOR OT" if source == "SYSTEM" else (
            item.decided_by.username if item.decided_by else None
        ),
        "conditional_evidence": (
            item.criteria_evidence
            if item.status == "APPLIES_CONDITIONAL" else None
        ),
        "negative_evidence": (
            item.criteria_evidence.get("negative_evidence")
            if source == "SYSTEM" and item.status == "NOT_APPLICABLE"
            and isinstance(item.criteria_evidence, dict) else None
        ),
        "evaluated_software": (
            item.criteria_evidence.get("evaluated_software", [])
            if item.status == "NOT_APPLICABLE"
            and not stale and isinstance(item.criteria_evidence, dict) else []
        ),
        "technical_override": (
            item.criteria_evidence.get("technical_override")
            if source == "ANALYST"
            and isinstance(item.criteria_evidence, dict) else None
        ),
    }



def _matching_criterion_count(technical_tree):
    if technical_tree.get("kind") == "CRITERION":
        return int(technical_tree.get("identity") == "MATCHED")
    return sum(_matching_criterion_count(child)
               for child in technical_tree.get("children", []))


def _flatten_technical_tree(tree):
    if tree.get("kind") == "CRITERION":
        yield tree
    for child in tree.get("children", []):
        yield from _flatten_technical_tree(child)


def _hardware_scope(criterion_nodes):
    """UI scope for ONE physical hardware, never a replacement for NVD logic.

    A missing platform condition is UNSCOPED, not incompatible. UNKNOWN
    hardware identities require separate inspection; they are not software
    candidates for a hardware that has already been confirmed.
    """
    hardware = [item for item in criterion_nodes if item.get("part") == "h"]
    if not hardware:
        return "UNSCOPED"
    identities = {item.get("technical_identity") for item in hardware}
    if "MATCHED" in identities:
        return "MATCHED"
    if identities == {"DISTINCT"}:
        return "DISTINCT"
    return "UNVERIFIED"


def _relevance_summary(configs, technical_trees):
    """Select only evidence pertaining to this inventory context.

    A historical decision is *not* evidence that another NVD hardware
    platform belongs to the selected asset. Hardware-matched branches stay
    relevant even when their installed firmware version is excluded. A
    software-only branch is relevant here only with a demonstrated software
    identity match; unresolved software-only branches are separately offered
    for review. The entire NVD expression remains evaluated independently.
    """
    relevant = []
    for config, evaluation in zip(configs, technical_trees):
        matches = _matching_criterion_count(evaluation)
        scope = config["hardware_scope"]
        if scope == "MATCHED" or (scope == "UNSCOPED" and matches > 0):
            relevant.append((matches, config))
    priority = {"COMPATIBLE": 0, "INDETERMINATE": 1, "EXCLUDED": 2}
    # A confirmed product identity (including a firmware whose version is
    # EXCLUDED) is a stronger primary candidate than an UNKNOWN firmware
    # attached to the same confirmed hardware. Display relevance is not a
    # vulnerability verdict: the technical AND/OR result remains unchanged.
    relevant.sort(key=lambda row: (
        -row[0],
        priority.get(row[1]["technical_result"], 3),
        row[1]["index"],
    ))
    return [row for _, row in relevant]


def summarize_hardware_cve_review(configurations):
    """One conservative human-review summary per (hardware, CVE).

    Individual append-only decisions remain bound to NVD configuration
    indices. This is only a read-only projection across *all* alternatives,
    including those not displayed in the routine pertinent-evidence view.
    """
    total = len(configurations)
    effective = [
        row.get("latest_assessment") for row in configurations
    ]
    # Automated confirmations belong in the same timeline, but are not
    # falsely reported as HUMAN decisions in the analyst-only summary.
    current = [
        row for row in effective if row and not row.get("stale")
        and row.get("source") != "SYSTEM"
    ]
    stale_count = sum(bool(row and row.get("stale")
                           and row.get("source") != "SYSTEM") for row in effective)
    confirmed = sum(row.get("effective_status") == "APPLIES" for row in current)
    conditional = sum(
        row.get("effective_status") == "APPLIES_CONDITIONAL" for row in current
    )
    excluded = sum(row.get("effective_status") == "NOT_APPLICABLE" for row in current)
    reviewed = len(current)
    if confirmed:
        status = "APPLIES"
    elif conditional:
        status = "APPLIES_CONDITIONAL"
    elif total > 0 and excluded == total and not stale_count:
        status = "NOT_APPLICABLE"
    elif stale_count:
        status = "STALE"
    elif reviewed:
        status = "IN_REVIEW"
    else:
        status = "PENDING_REVIEW"
    return {
        "status": status,
        "total_configurations": total,
        "reviewed_configurations": reviewed,
        "pending_configurations": total - reviewed,
        "confirmed_configurations": confirmed,
        "conditional_configurations": conditional,
        "excluded_configurations": excluded,
        "stale_configurations": stale_count,
    }


def general_assessment_context(cve_id, hardware_id):
    hw, cve, confirmed, installed, inventory_fp = _context(cve_id, hardware_id)
    technical = evaluate_configurations(
        cve.configurations, list(confirmed), installed
    )
    from .cve_applicability import verified_negative_configurations
    verified_negatives = {
        row["configuration_index"]: row
        for row in verified_negative_configurations(technical)
    }
    configs = []
    for index, config in enumerate(cve.configurations):
        cfg_fp = _digest(config)
        observation = technical["configurations"][index]
        history = list(AssetCveAssessment.objects.filter(
            cve=cve, hardware=hw, configuration_index=index,
        ).select_related("decided_by")[:30])
        current = _serialize_assessment(history[0], inventory_fp, cfg_fp, installed) if history else None
        supported = _simple_and_firmware(config, confirmed, installed)
        annotated_tree = _annotate_tree(
            _render_tree(config, confirmed, installed), observation
        )
        # Read-only evidence of installations used to disprove a version
        # requirement. A negative result NEVER creates a positive CVE link.
        observed_installations = {
            row["installation_id"]: row for row in installed
        }
        negative = verified_negatives.get(index)
        evaluated_software = []
        for condition in (negative or {}).get("excluded_by", []):
            if condition.get("reason") != "FIRMWARE_OR_SOFTWARE_VERSION_EXCLUDED":
                continue
            installation = observed_installations.get(
                condition.get("software_installation_id")
            )
            if not installation:
                continue
            evaluated_software.append({
                "software_installation_id": installation["installation_id"],
                "software_asset_id": installation["software_asset_id"],
                "installed_version": installation.get("version"),
                "criterion": condition["criterion"],
                "confirmed_cpe": condition.get("confirmed_cpe"),
                "reason": condition["reason"],
            })

        def leaves(node):
            if node.get("kind") == "CRITERION":
                yield node
            for child in node.get("children", []):
                yield from leaves(child)

        criteria = list(leaves(annotated_tree))
        hardware_scope = _hardware_scope(criteria)
        hardware_matched = any(
            item.get("part") == "h"
            and item.get("technical_identity") == "MATCHED"
            and item.get("technical_matched_cpe") for item in criteria
        )
        vulnerable_software_types = {
            item.get("part") for item in criteria
            if item.get("vulnerable") is True
            and item.get("part") in ("o", "a")
        }
        software_type_present = any(
            ("o" in vulnerable_software_types and sw["software_type"] in ("FIRMWARE", "OS"))
            or ("a" in vulnerable_software_types and sw["software_type"] == "APPLICATION")
            for sw in installed
        )
        manual_platform_review = (
            observation["result"] == "INDETERMINATE"
            and hardware_scope == "UNSCOPED"
            and bool(vulnerable_software_types)
            and software_type_present
        )
        conditional_supported = (
            observation["result"] in ("INDETERMINATE", "EXCLUDED")
            and not _has_nvd_negation(config)
            and bool(vulnerable_software_types)
            and (hardware_matched or manual_platform_review)
        )
        candidate_installations = sorted({
            item.get("technical_software_installation_id")
            for item in criteria
            if item.get("vulnerable") is True and
                item.get("part") in ("a", "o") and
                item.get("technical_identity") == "MATCHED" and
                item.get("technical_result") != "EXCLUDED" and
                item.get("technical_software_installation_id") is not None
        })
        configs.append({
            "index": index, "position": index + 1,
            "fingerprint": cfg_fp,
            "tree": annotated_tree,
            "hardware_scope": hardware_scope,
            "conditional_supported": bool(conditional_supported),
            "manual_platform_review_required": bool(
                conditional_supported and manual_platform_review
            ),
            "technical_override_supported": bool(
                conditional_supported and observation["result"] == "EXCLUDED"
            ),
            "candidate_installation_ids": candidate_installations,
            "technical_result": observation["result"],
            "evaluated_software": evaluated_software,
            "review_supported": bool(supported),
            "review_reason": "" if supported else (
                "La combinación de operadores, negaciones, rangos o CPE "
                "confirmados requiere revisión técnica; no puede confirmarse automáticamente."
            ),
            "hardware_criterion": supported["hardware_criterion"] if supported else None,
            "software_criterion": supported["software_criterion"] if supported else None,
            "review_installation_id": supported["required_installation_id"] if supported else None,
            "latest_assessment": current,
            "history": [_serialize_assessment(row, inventory_fp, cfg_fp, installed) for row in history],
        })
    pertinent = _relevance_summary(configs, technical["configurations"])
    pertinent_indexes = {row["index"] for row in pertinent}
    # Only configurations whose platform is actually matched by the confirmed
    # hardware can offer firmware/software alternatives for THIS controller.
    # A different CPU is never a firmware candidate based on its software TYPE.
    hardware_software = [
        row for row in pertinent
        if row["hardware_scope"] == "MATCHED"
        and any(
            leaf.get("kind") == "CRITERION"
            and leaf.get("vulnerable") is True
            and leaf.get("part") in ("o", "a")
            for leaf in _flatten_technical_tree(row["tree"])
        )
    ]
    # Unscoped applications can remain relevant to an asset, but do not
    # implicitly belong to the firmware of a particular controller.
    candidates = [
        row for row in configs
        if row["technical_result"] == "INDETERMINATE"
        and row["hardware_scope"] == "UNSCOPED"
        and row["index"] not in pertinent_indexes
    ]
    # Ambiguous hardware CPEs remain visible in an audit-only group. They
    # cannot be offered for manual software association by model similarity.
    unverified_platforms = [
        row for row in configs
        if row["technical_result"] == "INDETERMINATE"
        and row["hardware_scope"] == "UNVERIFIED"
        and row["index"] not in pertinent_indexes
    ]
    analyst = summarize_hardware_cve_review(configs)
    applicability = scoped_applicability(
        technical, analyst["status"], inventory_fingerprint=inventory_fp,
        cve=cve, hardware_id=hw.pk,
    )
    # One shared projection is used by both detail and catalogue. NVD's
    # technical result is never rewritten by the analyst's decision.
    from .cve_applicability import project_configuration_decisions
    current_human = {
        row["index"]: row["latest_assessment"]["status"]
        for row in configs
        if row.get("latest_assessment")
        and not row["latest_assessment"]["stale"]
        and row["latest_assessment"]["source"] == "ANALYST"
    }
    has_stale_human = any(
        row.get("latest_assessment")
        and row["latest_assessment"]["stale"]
        and row["latest_assessment"]["source"] == "ANALYST"
        for row in configs
    )
    if current_human or has_stale_human:
        projected = project_configuration_decisions(
            technical, current_human,
            stale_human_evidence=has_stale_human,
        )
        applicability.update({
            **projected,
            "hardening_category": (
                "CONFIRMED" if projected["status"] == "APPLIES"
                else "CONDITIONAL" if projected["status"] == "APPLIES_CONDITIONAL"
                else "NONE"
            ),
            "automatic_evidence": (
                applicability.get("automatic_evidence")
                if projected["source"] == "SYSTEM" else None
            ),
        })
    # Only a POST may append audit rows. GET advertises whether a proved
    # SYSTEM decision lacks a current audit row, even when the global CVE
    # is still pending because other NVD alternatives are unresolved.
    from .cve_applicability import (
        automatic_positive_evidence, automatic_negative_evidence,
        verified_negative_configurations,
    )
    positive = automatic_positive_evidence(technical)
    if positive is not None:
        system_candidates = [positive["configuration_index"]]
    else:
        negatives = verified_negative_configurations(technical)
        if automatic_negative_evidence(technical) is None:
            negatives = [
                row for row in negatives
                if any(proof["reason"] == "FIRMWARE_OR_SOFTWARE_VERSION_EXCLUDED"
                       for proof in row["excluded_by"])
            ]
        system_candidates = [row["configuration_index"] for row in negatives]
    audit_pending = any(
        configs[index]["latest_assessment"] is None
        or configs[index]["latest_assessment"]["stale"]
        for index in system_candidates
    )
    technical_counts = {
        key: sum(row["result"] == key for row in technical["configurations"])
        for key in ("COMPATIBLE", "EXCLUDED", "INDETERMINATE")
    }
    return {
        "cve_id": cve.cve_id, "hardware_asset_id": hw.pk,
        "hardware_name": hw.asset.name, "inventory_fingerprint": inventory_fp,
        "installed_software": installed,
        "technical_result": technical["result"],
        "technical_configuration_counts": technical_counts,
        "applicability": applicability,
        "automatic_audit_pending": audit_pending,
        "assessment_summary": analyst,
        "confirmed_hardware_cpes": [
            {"cpe_name": name, "association_id": assoc.pk}
            for name, assoc in confirmed.items()
        ],
        "configurations": configs,
        "relevant_configurations": pertinent,
        "candidate_configurations": candidates,
        "hardware_software_configurations": hardware_software,
        "unverified_platform_configurations": unverified_platforms,
        "unrelated_configuration_count": len(configs) - len(pertinent),
        "context_unit": "HARDWARE_CVE",
    }



def _has_nvd_negation(node):
    if not isinstance(node, dict):
        return False
    if node.get("negate") is True:
        return True
    return any(_has_nvd_negation(child) for child in node.get("nodes", []) or [])


def _matched_criterion_nodes(tree):
    """Return only demonstrated hardware/software product identities."""
    if tree.get("kind") == "CRITERION":
        if tree.get("technical_identity") == "MATCHED" and tree.get("technical_matched_cpe"):
            yield tree
    for child in tree.get("children", []):
        yield from _matched_criterion_nodes(child)


def _conditional_evidence(cve, hardware, config_index, confirmed, installed,
                          installation_id, *, allow_excluded=False,
                          platform_unverified_acknowledged=False,
                          allow_verified_positive=False):
    """Evidence for a cautious analyst claim: proven hardware context and
    an identified NVD vulnerable component, not an inferred installation.
    """
    from vulnerabilities.models import AssetCveFinding

    if not (
        AssetCveFinding.objects.filter(hardware=hardware, cve=cve).exists()
        or AssetCveAssessment.objects.filter(hardware=hardware, cve=cve).exists()
    ):
        raise ValidationError({"verdict": "El CVE no tiene un hallazgo asociado a este hardware."})
    config = cve.configurations[config_index]
    if _has_nvd_negation(config):
        raise ValidationError({"verdict":
            "La configuración NVD contiene una negación; requiere evaluación especializada."})
    evaluation = evaluate_configurations([config], list(confirmed), installed)
    from .cve_applicability import automatic_positive_evidence
    if automatic_positive_evidence(evaluation) and not allow_verified_positive:
        raise ValidationError({"verdict":
            "Todas las condiciones NVD están verificadas: utiliza Aplica, no Aplica condicionada."})
    if evaluation["result"] == "EXCLUDED" and not allow_excluded:
        raise ValidationError({"verdict":
            "La exclusión NVD requiere una decisión discrepante expresamente reconocida."})
    annotated = _annotate_tree(
        _render_tree(config, confirmed, installed), evaluation["configurations"][0],
    )
    matching = list(_matched_criterion_nodes(annotated))
    hardware_roles = [{
        "criteria": item["criteria"],
        "matched_cpe": item["technical_matched_cpe"],
        "role": "VULNERABLE" if item.get("vulnerable") is True else "PLATFORM",
    } for item in matching if item.get("part") == "h"]
    if not hardware_roles:
        # Unverified OTHER hardware is not a software candidate for this
        # controller. The analyst may only make an unscoped manual link when
        # NVD has no explicit hardware condition at all.
        all_criteria = list(_flatten_technical_tree(annotated))
        if any(item.get("part") == "h" for item in all_criteria):
            raise ValidationError({"verdict":
                "La plataforma de esta configuración no corresponde a un "
                "CPE de hardware confirmado. Verifica primero la identidad "
                "del hardware; no enlaces firmware de otra CPU."})
        if not platform_unverified_acknowledged or installation_id is None:
            raise ValidationError({"platform_unverified_acknowledged":
                "NVD no especifica una plataforma de hardware. "
                "Selecciona una instalación y documenta la decisión condicionada."})

    def vulnerable_leaves(node):
        if node.get("kind") == "CRITERION" and node.get("vulnerable") is True:
            yield node
        for child in node.get("children", []):
            yield from vulnerable_leaves(child)

    vulnerable = list(vulnerable_leaves(annotated))
    if not vulnerable:
        raise ValidationError({"verdict":
            "NVD no identifica un componente vulnerable en la configuración seleccionada."})

    selected_criteria = []
    if installation_id is not None:
        # A manual association is not an NVD/CPE confirmation. Only an active
        # installation on this hardware, of the correct software class, may
        # be linked. The analyst's assertion remains conditional and audited.
        installation = next(
            (row for row in installed if row["installation_id"] == installation_id),
            None,
        )
        if installation is None:
            raise ValidationError({"software_installation_id":
                "La instalación no está vigente en este hardware."})
        permitted_parts = {
            "FIRMWARE": "o", "OS": "o", "APPLICATION": "a",
        }
        matching_parts = [
            item for item in vulnerable
            if item.get("part") == permitted_parts.get(installation["software_type"])
            and (allow_excluded or item.get("technical_result") != "EXCLUDED")
        ]
        if not matching_parts:
            raise ValidationError({"software_installation_id":
                "La instalación seleccionada no corresponde al tipo de componente "
                "vulnerable indicado por NVD."})
        proven = next((
            item for item in matching_parts
            if item.get("technical_identity") == "MATCHED"
            and item.get("technical_software_installation_id") == installation_id
            and item.get("technical_matched_cpe")
        ), None)
        selected_criteria = [{
            # A manual check only links the CVE and the installed asset. It
            # does NOT designate a proven individual NVD alternative.
            "criteria": proven["criteria"] if proven else None,
            "candidate_nvd_criteria": (
                [] if proven else [item["criteria"] for item in matching_parts]
            ),
            "matched_cpe": proven.get("technical_matched_cpe") if proven else None,
            "installation_id": installation_id,
            "software_asset_id": installation["software_asset_id"],
            "link_source": (
                "ANALYST_OVERRIDE" if allow_excluded
                else "CONFIRMED_CPE" if proven else "ANALYST_DISCRETION"
            ),
            "identity_verified": bool(proven),
            "version_verified": bool(
                not allow_excluded and proven
                and proven.get("technical_result") == "COMPATIBLE"
            ),
        }]
    return {
        "origin": "ANALYST", "hardware_roles": hardware_roles,
        "platform_unverified": (
            {
                "acknowledged": True,
                "confirmed_hardware_cpes": list(confirmed),
                "reason": "No hay coincidencia CPE de hardware en la configuración NVD.",
            } if not hardware_roles else None
        ),
        "vulnerable_criteria": [{
            "criteria": item["criteria"], "part": item.get("part"),
            "identity_verified": item.get("technical_identity") == "MATCHED",
            "matched_cpe": item.get("technical_matched_cpe"),
            "bounds": item.get("bounds", {}),
        } for item in vulnerable],
        "linked_software": selected_criteria,
        "pending_condition": evaluation["result"] != "COMPATIBLE",
        "pending_criteria": [{
            "criteria": item["criteria"], "reason": item.get("technical_reason"),
            "result": item.get("technical_result", "INDETERMINATE"),
        } for item in vulnerable if item.get("technical_result") != "COMPATIBLE"],
        "configuration_result": evaluation["result"],
    }


@transaction.atomic
def record_general_assessment(cve_id, hardware_id, actor, *,
                              configuration_index, verdict,
                              software_installation_id=None,
                              inventory_declared_complete=False,
                              technical_override_acknowledged=False,
                              platform_unverified_acknowledged=False,
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
    if verdict not in ("CONFIRMED", "NOT_MATCH", "UNKNOWN", "CONDITIONAL"):
        raise ValidationError({"verdict": "Decisión no reconocida."})
    reason = justification.strip()
    if not reason or len(reason) > 1000:
        raise ValidationError({"justification": "Justifica tu decisión (máximo 1000 caracteres)."})
    technical = evaluate_configurations([config], list(confirmed), installed)
    result = technical["result"]
    excluded = result == "EXCLUDED"
    conflicting_negative = verdict == "NOT_MATCH" and result == "COMPATIBLE"
    conflicting_positive = verdict == "CONDITIONAL" and result == "COMPATIBLE"
    override = excluded and verdict in ("CONFIRMED", "CONDITIONAL")
    if (override or conflicting_negative or conflicting_positive) and not technical_override_acknowledged:
        raise ValidationError({"technical_override_acknowledged":
            "Esta decisión es distinta del resultado técnico NVD. "
            "Registra una revisión justificada para continuar."})

    # Reaffirming a CURRENT persisted decision changes no state and may not
    # manufacture a new analyst audit record. A mere UI opening never writes.
    latest = AssetCveAssessment.objects.filter(
        hardware=hw, cve=cve, configuration_index=configuration_index,
    ).order_by("-decided_at", "-pk").first()
    target = {
        "CONFIRMED": "APPLIES", "CONDITIONAL": "APPLIES_CONDITIONAL",
        "NOT_MATCH": "NOT_APPLICABLE" if inventory_declared_complete else "PENDING_REVIEW",
        "UNKNOWN": "PENDING_REVIEW",
    }[verdict]
    if (latest and latest.inventory_fingerprint == actual_fp
            and latest.configuration_fingerprint == cfg_fp
            and latest.status == target):
        raise ValidationError({"verdict":
            "La evaluación ya tiene este estado vigente. No se registran reconfirmaciones."})

    supported = _simple_and_firmware(config, confirmed, installed)
    if not supported and verdict == "CONFIRMED" and not override:
        raise ValidationError({"verdict":
            "La configuración no permite una confirmación positiva sin evidencia comprobada."})
    if verdict == "NOT_MATCH":
        if _has_nvd_negation(config):
            raise ValidationError({"verdict":
                "Esta configuración contiene negaciones NVD y requiere revisión especializada."})
        if inventory_declared_complete and len(reason) < 20:
            raise ValidationError({"justification":
                "Documenta la evidencia negativa y el alcance revisado (mínimo 20 caracteres)."})
        # Manual non-correspondence is scoped to this NVD configuration, never
        # inferred solely from a missing software entry and never an automatic
        # global dismissal. Require a verified platform or unscoped criterion.
        # An unknown, explicitly different hardware platform cannot be
        # dismissed manually in the software-only evaluation for this asset.
        observed = evaluate_configurations([config], list(confirmed), installed)
        tree = _annotate_tree(
            _render_tree(config, confirmed, installed),
            observed["configurations"][0],
        )
        hardware_criteria = [
            item for item in _flatten_technical_tree(tree)
            if item.get("part") == "h"
        ]
        if hardware_criteria and not any(
                item.get("technical_identity") == "MATCHED"
                for item in hardware_criteria):
            raise ValidationError({"verdict":
                "No se ha confirmado la plataforma de hardware NVD para este activo."})
    installed_by_id = {row["installation_id"]: row for row in installed}
    selected = installed_by_id.get(software_installation_id)
    if software_installation_id is not None and selected is None:
        raise ValidationError({"software_installation_id": "La instalación no está vigente."})
    if selected is not None and supported and verdict == "CONFIRMED":
        part = supported["software_criterion"].split(":")[2]
        permitted = ("FIRMWARE", "OS") if part == "o" else ("APPLICATION",)
        if selected["software_type"] not in permitted:
            raise ValidationError({"software_installation_id":
                "El tipo de software instalado no corresponde al criterio NVD."})
    if verdict == "CONFIRMED" and selected is None:
        raise ValidationError({"software_installation_id":
            "Selecciona una instalación de software vigente."})
    if (supported and supported["required_installation_id"] is not None
            and verdict == "CONFIRMED"
            and software_installation_id != supported["required_installation_id"]):
        raise ValidationError({"software_installation_id":
            "Selecciona la instalación concreta verificada contra NVD."})
    conditional_evidence = None
    if verdict == "CONDITIONAL" or override:
        if len(reason) < 20:
            raise ValidationError({"justification":
                "Justifica la decisión y las condiciones pendientes (mínimo 20 caracteres)."})
        if override and verdict == "CONFIRMED" and selected is None:
            raise ValidationError({"software_installation_id":
                "La confirmación discrepante requiere una instalación vigente vinculada."})
        conditional_evidence = _conditional_evidence(
            cve, hw, configuration_index, confirmed, installed,
            software_installation_id, allow_excluded=override,
            platform_unverified_acknowledged=platform_unverified_acknowledged,
            allow_verified_positive=conflicting_positive,
        )
        if override or conflicting_positive:
            conditional_evidence["technical_override"] = {
                "acknowledged": True,
                "technical_result": result,
                "analyst_verdict": verdict,
                "reason": technical["configurations"][0].get("reason", ""),
                "configuration_fingerprint": cfg_fp,
            }
    # A negative verdict only settles an AND branch if the inventory was
    # explicitly attested complete and only this installation was in scope.
    status = "PENDING_REVIEW"
    if verdict == "CONDITIONAL":
        status = "APPLIES_CONDITIONAL"
    elif (supported or override) and verdict == "CONFIRMED" and selected is not None:
        status = "APPLIES"
    elif verdict == "NOT_MATCH" and inventory_declared_complete:
        status = "NOT_APPLICABLE"
    if verdict == "NOT_MATCH":
        # The negative assessment has an evaluated installation, NOT a
        # vulnerable software association. Keep its FK null by design.
        conditional_evidence = {
            "origin": "ANALYST", "verdict": "NOT_MATCH",
            "inventory_declared_complete": inventory_declared_complete,
            "evaluated_software": [{
                "software_installation_id": selected["installation_id"],
                "software_asset_id": selected["software_asset_id"],
                "installed_version": selected.get("version"),
            }] if selected else [],
            "negative_scope": "NVD_CONFIGURATION",
            "technical_result": result,
            "technical_override": {
                "acknowledged": True, "technical_result": result,
                "analyst_verdict": verdict,
            } if conflicting_negative else None,
        }
    if conditional_evidence is None:
        conditional_evidence = {
            "platform": supported["hardware_criterion"] if supported else None,
            "software": supported["software_criterion"] if supported else None,
            "verdict": verdict,
            "inventory_declared_complete": inventory_declared_complete,
        }
    # Snapshot the actual inventory values before a later firmware update or
    # unlink; this display evidence never changes the NVD technical result.
    snapshot = _software_snapshot(selected)
    if snapshot:
        conditional_evidence["software_snapshot"] = [snapshot]
    record = AssetCveAssessment.objects.create(
        hardware=hw, cve=cve,
        configuration_index=configuration_index,
        configuration_snapshot=config, configuration_fingerprint=cfg_fp,
        inventory_fingerprint=actual_fp, status=status,
        software_installation_id=(
            selected["installation_id"] if selected and
            status in ("APPLIES", "APPLIES_CONDITIONAL") else None
        ),
        criteria_evidence=conditional_evidence,
        justification=reason, decided_by=actor,
    )
    return _serialize_assessment(record, actual_fp, cfg_fp, installed)
