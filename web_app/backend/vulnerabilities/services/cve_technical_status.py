"""Read-only summary of NVD technical compatibility across related hardware.

This does NOT change the analyst's evaluation_status and never asserts
applicability solely from a CVE discovered by CPE.
"""
from collections import defaultdict

from django.http import Http404
from rest_framework.exceptions import NotFound, ValidationError

from vulnerabilities.models import AssetCveAssessment, AssetCveFinding
from .cve_discovery import hardware_discovery_pairs
from .cve_general_assessment import _context, _digest
from .cve_applicability import (
    automatic_positive_evidence, automatic_negative_evidence,
    verified_negative_configurations,
)
from .cve_configuration_evaluator import (
    COMPATIBLE, EXCLUDED, INDETERMINATE, evaluate_configurations,
)

TECHNICAL_FILTERS = ("ATTENTION", COMPATIBLE, EXCLUDED, INDETERMINATE)


def technical_statuses(cves):
    items = list(cves)
    if not items:
        return {}
    ids = [row.pk for row in items]
    related = defaultdict(set)
    for cve_id, hw_id in hardware_discovery_pairs(ids):
        related[cve_id].add(hw_id)
    for cve_id, hw_id in AssetCveAssessment.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
        related[cve_id].add(hw_id)
    result = {}
    for cve in items:
        technical = []
        for hw_id in sorted(related[cve.pk]):
            try:
                _, _, hardware_cpes, installed, _ = _context(cve.cve_id, hw_id)
                technical.append(evaluate_configurations(
                    cve.configurations, list(hardware_cpes), installed
                )["result"])
            except (Http404, NotFound, ValidationError, ValueError, AttributeError):
                technical.append(INDETERMINATE)
        if not technical:
            result[cve.pk] = INDETERMINATE
        elif COMPATIBLE in technical:
            result[cve.pk] = COMPATIBLE
        elif all(value == EXCLUDED for value in technical):
            result[cve.pk] = EXCLUDED
        else:
            result[cve.pk] = INDETERMINATE
    return result


def _matched_software(evaluation):
    """Only link installed software when the NVD criterion matched its CPE."""
    if evaluation.get("kind") == "CRITERION":
        if evaluation.get("identity") == "MATCHED" and evaluation.get("software_asset_id"):
            return {evaluation["software_asset_id"]}
        return set()
    result = set()
    for child in evaluation.get("children", []):
        result.update(_matched_software(child))
    return result


def _hardware_role(analysis, preferred_index=None):
    """Select role only from a confirmed NVD hardware identity.
    A role is scoped to one NVD configuration, not to all CVEs.
    """
    configs = analysis.get("configurations", [])
    order = ([preferred_index] if isinstance(preferred_index, int)
             and 0 <= preferred_index < len(configs) else [])
    order += [i for i in range(len(configs)) if i not in order]

    def roles(node):
        if node.get("kind") == "CRITERION":
            if (node.get("identity") == "MATCHED"
                    and node.get("matched_cpe")
                    and str(node.get("criteria", "")).startswith("cpe:2.3:h:")):
                yield "VULNERABLE" if node.get("vulnerable") is True else "PLATFORM"
        for child in node.get("children", []):
            yield from roles(child)

    for index in order:
        found = set(roles(configs[index]))
        if len(found) == 1:
            return next(iter(found))
    return "HARDWARE_CONTEXT"


def _current_linked_installation(cve, hardware, inventory_fp):
    """Latest current analyst evaluation; never link unrelated installed apps."""
    decisions = AssetCveAssessment.objects.filter(
        cve=cve, hardware=hardware
    ).order_by("-decided_at", "-pk")
    for row in decisions:
        if (row.inventory_fingerprint != inventory_fp or
                row.configuration_index >= len(cve.configurations) or
                row.configuration_fingerprint !=
                _digest(cve.configurations[row.configuration_index])):
            # Never resurrect an earlier link after a newer stale assessment.
            return None, None, None
        if (isinstance(row.criteria_evidence, dict)
                and row.criteria_evidence.get("origin") == "SYSTEM"):
            continue
        linked = (row.software_installation_id
                  if row.status in ("APPLIES", "APPLIES_CONDITIONAL") else None)
        return linked, row.configuration_index, row.status
    return None, None, None


def _scoped_status_with_current_audits(cve, hardware, inventory_fp, analysed):
    """Reuse detail's scoped analyst/technical projection for the catalogue."""
    from .cve_applicability import (
        project_configuration_decisions, latest_hardware_cve_decision,
    )
    global_record, global_current = latest_hardware_cve_decision(
        cve, hardware, inventory_fp,
    )
    if global_record is not None:
        return project_configuration_decisions(
            analysed, {}, stale_human_evidence=not global_current,
            global_decision=global_record.status if global_current else None,
        )

    newest = {}
    for row in AssetCveAssessment.objects.filter(
        hardware=hardware, cve=cve,
    ).order_by("-decided_at", "-pk"):
        newest.setdefault(row.configuration_index, row)

    current, stale = {}, False
    for index, row in newest.items():
        system = (isinstance(row.criteria_evidence, dict)
                  and row.criteria_evidence.get("origin") == "SYSTEM")
        is_current = (
            0 <= index < len(cve.configurations)
            and row.inventory_fingerprint == inventory_fp
            and row.configuration_fingerprint == _digest(cve.configurations[index])
        )
        if system:
            continue
        if is_current:
            current[index] = row.status
        else:
            stale = True
    return project_configuration_decisions(
        analysed, current, stale_human_evidence=stale,
    )


def related_assets_for_cves(cves):
    """Concrete inventoried assets evidenced in each hardware/CVE context.

    Hardware is the contextual unit. Software is included only when a
    criterion's CPE matches its CURRENT confirmed CPE and active installation.
    An unrelated installed program is never labelled as a matching CVE asset.
    """
    items = list(cves)
    result = {cve.pk: [] for cve in items}
    if not items:
        return result
    ids = [cve.pk for cve in items]
    related = defaultdict(set)
    for cve_pk, hw_pk in hardware_discovery_pairs(ids):
        related[cve_pk].add(hw_pk)
    for cve_pk, hw_pk in AssetCveAssessment.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
        related[cve_pk].add(hw_pk)

    for cve in items:
        for hw_id in sorted(related[cve.pk]):
            try:
                hardware, _, hw_cpes, installed, inventory_fp = _context(cve.cve_id, hw_id)
                analysed = evaluate_configurations(
                    cve.configurations, list(hw_cpes), installed
                )
                proof = automatic_positive_evidence(analysed)
                negative = automatic_negative_evidence(analysed)
                scoped_status = _scoped_status_with_current_audits(
                    cve, hardware, inventory_fp, analysed,
                )
                from .cve_applicability import latest_hardware_cve_decision
                global_record, global_current = latest_hardware_cve_decision(
                    cve, hardware, inventory_fp,
                )
                chosen_installation, chosen_configuration, human_status = _current_linked_installation(
                    cve, hardware, inventory_fp,
                )
                if global_record is not None:
                    chosen_configuration = global_record.configuration_index
                    human_status = global_record.status if global_current else "STALE"
                    chosen_installation = (
                        global_record.software_installation_id
                        if global_current and global_record.status == "APPLIES"
                        else None
                    )
                proof_installations = {
                    row.get("software_installation_id")
                    for row in (proof or {}).get("criteria", [])
                    if row.get("vulnerable") and row.get("software_installation_id")
                }
                # A hardware-wide human decision changes the active
                # Hardware-CVE relation and ALL associated software findings.
                # A historic SYSTEM positive is still in the NVD evidence,
                # but is not an operative vulnerable-software association.
                if global_record is not None:
                    proof_installations = set()
                elif (chosen_configuration == (proof or {}).get("configuration_index")
                        and human_status in ("NOT_APPLICABLE", "APPLIES_CONDITIONAL",
                                             "PENDING_REVIEW")):
                    proof_installations = set()
                linked = proof_installations | (
                    {chosen_installation} if chosen_installation else set()
                )
                role = _hardware_role(
                    analysed, chosen_configuration if chosen_configuration is not None
                    else (proof or {}).get("configuration_index"),
                )
                assets = [{
                    "asset_id": hardware.pk, "asset_type": "HARDWARE",
                    "name": hardware.asset.name, "version": None,
                    "role": role,
                }]
                for sw in installed:
                    if sw["installation_id"] in linked:
                        assets.append({
                            "asset_id": sw["software_asset_id"],
                            "asset_type": "SOFTWARE",
                            "name": sw["software_name"],
                            "version": sw["version"],
                            "role": "VULNERABLE",
                            "software_type": sw["software_type"],
                            "installation_id": sw["installation_id"],
                        })
                # Installation IDs are distinct; one software asset should
                # appear only once in the catalogue cell.
                seen = set()
                unique = []
                for row in assets:
                    if row["asset_id"] not in seen:
                        unique.append(row)
                        seen.add(row["asset_id"])
                result[cve.pk].append({
                    "hardware_id": hw_id,
                    "technical_result": analysed["result"],
                    "automatic_evidence": proof,
                    "automatic_negative_evidence": negative,
                    "scoped_applicability": scoped_status,
                    "hardware_role": role,
                    "assets": unique,
                })
            except (Http404, NotFound, ValidationError, ValueError, AttributeError):
                # Existing candidate relation is retained for audit but
                # cannot be presented as a verified current match.
                result[cve.pk].append({
                    "hardware_id": hw_id,
                    "technical_result": INDETERMINATE,
                    "automatic_evidence": None,
                    "automatic_negative_evidence": None,
                    "scoped_applicability": {
                        "status": "PENDING_REVIEW", "source": "NONE",
                    },
                    "hardware_role": "HARDWARE_CONTEXT",
                    "assets": [],
                })
    return result
