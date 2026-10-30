"""Conservative row-level CVE evaluation status for the global catalogue.

The CVE is global; analyst assessments belong to (hardware, configuration).
A single current positive is reported as APPLIES *in at least one scope*, not
as an automatic verdict on all selected hardware. NOT_APPLICABLE requires
current negative decisions for every NVD configuration on every linked hardware.
Only the latest append-only decision per (hardware, configuration) is effective.
"""
from collections import defaultdict

from rest_framework.exceptions import NotFound, ValidationError

from vulnerabilities.models import AssetCveAssessment, AssetCveFinding
from .cve_discovery import hardware_discovery_pairs
from .cve_general_assessment import _context as general_context, _digest
from .cve_assessment import _context as experimental_context
from .cve_ingestion import CveResponseError

PENDING_REVIEW = "PENDING_REVIEW"
IN_REVIEW = "IN_REVIEW"
APPLIES = "APPLIES"
APPLIES_CONDITIONAL = "APPLIES_CONDITIONAL"
NOT_APPLICABLE = "NOT_APPLICABLE"
STALE = "STALE"
CATALOGUE_STATES = (
    PENDING_REVIEW, IN_REVIEW, APPLIES, APPLIES_CONDITIONAL, NOT_APPLICABLE, STALE
)


def _is_current(record, cve, cache):
    """Use the same decision validity as detail and related-assets projection."""
    if not isinstance(cve.configurations, list):
        return False
    index = record.configuration_index
    if index < 0 or index >= len(cve.configurations):
        return False
    key = (cve.pk, record.hardware_id)
    if key not in cache:
        try:
            hardware, _, _, _, inventory_fp = general_context(
                cve.cve_id, record.hardware_id
            )
            cache[key] = (hardware, inventory_fp)
        except (NotFound, ValidationError, CveResponseError, ValueError, AttributeError):
            cache[key] = (None, None)
    hardware, inventory_fp = cache[key]
    if hardware is None:
        return False
    from .cve_applicability import assessment_evidence_is_current
    return assessment_evidence_is_current(
        record, cve, hardware, inventory_fp, _digest(cve.configurations[index])
    )


def catalogue_statuses(cves):
    """Batch-read candidate hardware and latest audited reviews for CVE rows.

    Does not write, modify decisions or contact NVD. Empty/unreviewed
    CVEs are PENDING_REVIEW even if their NVD fetch is COMPLETED.
    """
    cves = list(cves)
    if not cves:
        return {}
    ids = [cve.pk for cve in cves]
    hardware_by_cve = defaultdict(set)
    for cve_pk, hw_pk in hardware_discovery_pairs(ids):
        hardware_by_cve[cve_pk].add(hw_pk)
    latest = defaultdict(dict)
    seen = set()
    audits = AssetCveAssessment.objects.filter(
        cve_id__in=ids,
    ).order_by(
        "cve_id", "hardware_id", "configuration_index", "-decided_at", "-pk"
    )
    for record in audits:
        hardware_by_cve[record.cve_id].add(record.hardware_id)
        if (isinstance(record.criteria_evidence, dict)
                and record.criteria_evidence.get("origin") == "SYSTEM"):
            # The phase-1 technical proof already supplies SYSTEM status.
            # Do not present the very same automated row as ANALYST.
            continue
        key = (record.cve_id, record.hardware_id, record.configuration_index)
        if key in seen:
            continue
        seen.add(key)
        latest[record.cve_id][(record.hardware_id, record.configuration_index)] = record

    cache = {}
    statuses = {}
    for cve in cves:
        hardware_ids = hardware_by_cve[cve.pk]
        records = latest[cve.pk]
        configurations = cve.configurations
        config_count = len(configurations) if isinstance(configurations, list) else 0
        if not records:
            statuses[cve.pk] = PENDING_REVIEW
            continue
        current = {}
        any_stale = False
        for key, record in records.items():
            if _is_current(record, cve, cache):
                current[key] = record.status
            else:
                any_stale = True

        if APPLIES in current.values():
            # A demonstrated positive outranks conditional and other alternatives.
            statuses[cve.pk] = APPLIES
        elif APPLIES_CONDITIONAL in current.values():
            statuses[cve.pk] = APPLIES_CONDITIONAL
        elif (
            hardware_ids and config_count > 0 and not any_stale
            and all(
                current.get((hw_id, index)) == NOT_APPLICABLE
                for hw_id in hardware_ids for index in range(config_count)
            )
        ):
            statuses[cve.pk] = NOT_APPLICABLE
        elif any_stale:
            statuses[cve.pk] = STALE
        elif current:
            statuses[cve.pk] = IN_REVIEW
        else:
            statuses[cve.pk] = PENDING_REVIEW
    return statuses
