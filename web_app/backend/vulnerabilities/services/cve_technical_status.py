"""Read-only summary of NVD technical compatibility across related hardware.

This does NOT change the analyst's evaluation_status and never asserts
applicability solely from a CVE discovered by CPE.
"""
from collections import defaultdict

from django.http import Http404
from rest_framework.exceptions import NotFound, ValidationError

from vulnerabilities.models import AssetCveAssessment, AssetCveFinding
from .cve_general_assessment import _context
from .cve_applicability import automatic_positive_evidence
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
    for cve_id, hw_id in AssetCveFinding.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
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
    for cve_pk, hw_pk in AssetCveFinding.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
        related[cve_pk].add(hw_pk)
    for cve_pk, hw_pk in AssetCveAssessment.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
        related[cve_pk].add(hw_pk)

    for cve in items:
        for hw_id in sorted(related[cve.pk]):
            try:
                hardware, _, hw_cpes, installed, _ = _context(cve.cve_id, hw_id)
                analysed = evaluate_configurations(
                    cve.configurations, list(hw_cpes), installed
                )
                proof = automatic_positive_evidence(analysed)
                matched_sw = set()
                for config in analysed["configurations"]:
                    matched_sw.update(_matched_software(config))
                assets = [{
                    "asset_id": hardware.pk, "asset_type": "HARDWARE",
                    "name": hardware.asset.name, "version": None,
                    "role": "HARDWARE_CONTEXT",
                }]
                for sw in installed:
                    if sw["software_asset_id"] in matched_sw:
                        assets.append({
                            "asset_id": sw["software_asset_id"],
                            "asset_type": "SOFTWARE",
                            "name": sw["software_name"],
                            "version": sw["version"],
                            "role": "MATCHED_INSTALLED_SOFTWARE",
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
                    "assets": unique,
                })
            except (Http404, NotFound, ValidationError, ValueError, AttributeError):
                # Existing candidate relation is retained for audit but
                # cannot be presented as a verified current match.
                result[cve.pk].append({
                    "hardware_id": hw_id,
                    "technical_result": INDETERMINATE,
                    "automatic_evidence": None,
                    "assets": [],
                })
    return result
