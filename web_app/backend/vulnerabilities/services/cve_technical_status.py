"""Read-only summary of NVD technical compatibility across related hardware.

This does NOT change the analyst's evaluation_status and never asserts
applicability solely from a CVE discovered by CPE.
"""
from collections import defaultdict

from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound, ValidationError

from vulnerabilities.models import AssetCveAssessment, AssetCveFinding
from .cve_general_assessment import _context
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
            except (NotFound, ValidationError, ValueError, AttributeError):
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
