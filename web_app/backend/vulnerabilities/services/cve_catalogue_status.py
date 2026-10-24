"""Conservative row-level CVE evaluation status for the global catalogue.

The CVE is global; analyst assessments belong to (hardware, configuration).
A single current positive is reported as APPLIES *in at least one scope*, not
as an automatic verdict on all selected hardware. NOT_APPLICABLE requires
current negative decisions for every NVD configuration on every linked hardware.
Only the latest append-only decision per (hardware, configuration) is effective.
"""
from collections import defaultdict

from django.http import Http404

from rest_framework.exceptions import NotFound, ValidationError

from vulnerabilities.models import (
    AssetCveAssessment, AssetCveFinding, HardwareCveDecision,
)
from .hardware_cve_decision import nvd_decision_fingerprint
from .cve_general_assessment import _context as general_context, _digest
from .cve_assessment import _context as experimental_context
from .cve_ingestion import CveResponseError

PENDING_REVIEW = "PENDING_REVIEW"
IN_REVIEW = "IN_REVIEW"
APPLIES = "APPLIES"
NOT_APPLICABLE = "NOT_APPLICABLE"
STALE = "STALE"
CATALOGUE_STATES = (PENDING_REVIEW, IN_REVIEW, APPLIES, NOT_APPLICABLE, STALE)


def _is_current(record, cve, cache):
    """Recheck both current inventory identity and the exact NVD configuration."""
    configs = cve.configurations
    if not isinstance(configs, list) or record.configuration_index >= len(configs):
        return False
    if record.configuration_index < 0:
        return False

    is_legacy = (
        cve.cve_id == "CVE-2021-33540"
        and record.hardware_id == 2
        and isinstance(record.criteria_evidence, dict)
        and {"hardware", "firmware"}.issubset(record.criteria_evidence)
    )
    key = (cve.pk, record.hardware_id, is_legacy)
    if key not in cache:
        try:
            if is_legacy:
                context = experimental_context(record.hardware_id)
                cache[key] = (
                    context["inventory_fingerprint"],
                    {context["scenario"]["index"]:
                     context["configuration_fingerprint"]},
                )
            else:
                _, _, _, _, inventory_fingerprint = general_context(
                    cve.cve_id, record.hardware_id
                )
                cache[key] = (
                    inventory_fingerprint,
                    {index: _digest(config) for index, config in enumerate(configs)},
                )
        except (Http404, NotFound, ValidationError, CveResponseError, ValueError, AttributeError):
            cache[key] = (None, {})
    inventory_fingerprint, config_fingerprints = cache[key]
    return bool(
        inventory_fingerprint
        and record.inventory_fingerprint == inventory_fingerprint
        and record.configuration_fingerprint == config_fingerprints.get(
            record.configuration_index
        )
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
    for cve_pk, hw_pk in AssetCveFinding.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
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
        key = (record.cve_id, record.hardware_id, record.configuration_index)
        if key in seen:
            continue
        seen.add(key)
        latest[record.cve_id][(record.hardware_id, record.configuration_index)] = record

    # New append-only whole-hardware decisions take precedence over previous
    # per-configuration reviews for the *same* hardware. The older records
    # remain untouched and can still be inspected in the legacy history.
    newest_hardware = defaultdict(dict)
    for record in HardwareCveDecision.objects.filter(
        cve_id__in=ids
    ).order_by("cve_id", "hardware_id", "-decided_at", "-pk"):
        if record.hardware_id not in newest_hardware[record.cve_id]:
            newest_hardware[record.cve_id][record.hardware_id] = record
        hardware_by_cve[record.cve_id].add(record.hardware_id)

    cache = {}
    statuses = {}
    for cve in cves:
        hardware_ids = hardware_by_cve[cve.pk]
        configurations = cve.configurations
        config_count = len(configurations) if isinstance(configurations, list) else 0
        newest = newest_hardware[cve.pk]
        records = {
            key: record for key, record in latest[cve.pk].items()
            if key[0] not in newest
        }
        current = {}
        any_stale = False
        for key, record in records.items():
            if _is_current(record, cve, cache):
                current[key] = record.status
            else:
                any_stale = True
        whole = {}
        fp = nvd_decision_fingerprint(cve)
        for hw_id, decision in newest.items():
            key = (cve.pk, hw_id, False)
            if key not in cache:
                try:
                    _, _, _, _, identity_fp = general_context(cve.cve_id, hw_id)
                    cache[key] = (identity_fp, {})
                except (Http404, NotFound, ValidationError,
                        CveResponseError, ValueError, AttributeError):
                    cache[key] = (None, {})
            current_fp = cache[key][0]
            if (current_fp and decision.inventory_fingerprint == current_fp
                    and decision.nvd_fingerprint == fp):
                whole[hw_id] = decision.status
            else:
                any_stale = True

        if APPLIES in current.values() or APPLIES in whole.values():
            statuses[cve.pk] = APPLIES
        elif (hardware_ids and not any_stale and
              all(
                  (whole.get(hw_id) == NOT_APPLICABLE) if hw_id in newest
                  else (config_count > 0 and all(
                      current.get((hw_id, index)) == NOT_APPLICABLE
                      for index in range(config_count)
                  ))
                  for hw_id in hardware_ids
              )):
            statuses[cve.pk] = NOT_APPLICABLE
        elif any_stale:
            statuses[cve.pk] = STALE
        elif current or whole:
            statuses[cve.pk] = IN_REVIEW
        else:
            statuses[cve.pk] = PENDING_REVIEW
    return statuses
