"""Read-only, UUID-based counts for the latest valid completed NVD search."""
from vulnerabilities.models import AssetCpe, CpeSearchRun
from .candidate_matching import candidates_for_identity


def is_outdated_association(association, identity_fingerprint):
    """Historical REOPENED does not claim a current technical match."""
    return (
        association.validation_status != AssetCpe.Validation.REOPENED
        and association.validated_identity_fingerprint != identity_fingerprint
    )


def count_external_reviewed_cpes(associations, identity_fingerprint, automatic_ids):
    """Count current, audited external-UUID decisions outside automatic discovery.

    A CPE present in BOTH sources contributes only once to overall totals.
    The full manually reviewed count remains independently visible as provenance.
    Older or reopened decisions are not current confirmations/rejections.
    """
    external = {}
    for association in associations:
        if (association.source_run.trigger != "EXTERNAL_CPE"
                or association.validated_identity_fingerprint != identity_fingerprint):
            continue
        external[str(association.cpe.cpe_name_id).lower()] = association.validation_status

    statuses = (AssetCpe.Validation.CONFIRMED, AssetCpe.Validation.REJECTED)
    extras = {
        uid: status for uid, status in external.items()
        if uid not in automatic_ids and status in statuses
    }
    return {
        "confirmed": sum(status == AssetCpe.Validation.CONFIRMED for status in extras.values()),
        "rejected": sum(status == AssetCpe.Validation.REJECTED for status in extras.values()),
        "manual_confirmed": sum(
            status == AssetCpe.Validation.CONFIRMED for status in external.values()),
        "manual_rejected": sum(
            status == AssetCpe.Validation.REJECTED for status in external.values()),
        "manual_reopened": sum(
            status == AssetCpe.Validation.REOPENED for status in external.values()),
    }


def count_current_cpes(run, associations, identity_fingerprint):
    """Never count an old or missing NVD result as currently discovered.

    Each UUID in the latest *completed* search is counted exactly once. A
    historical PENDING is still unresolved; REOPENED is unresolved by design.
    Outside-of-run associations remain in audit but are not included in counts.
    """
    available = bool(
        run and run.status == CpeSearchRun.Status.COMPLETED
        and run.identity_fingerprint == identity_fingerprint
    )
    uuids = set()
    exploratory_ids = set()
    # The search run already stores the asset type and CPE part in its
    # immutable identity snapshot. Preserve hardware legacy behavior.
    candidates = candidates_for_identity(run.candidates, run.identity_snapshot) if available else []
    if available:
        exploratory_ids = {
            str(item.get("cpe_name_id", "")).lower()
            for item in candidates
            if item.get("cpe_name_id") and item.get("match_level") == "EXPLORATORY"
        }
        uuids = {
            str(item.get("cpe_name_id", "")).lower()
            for item in candidates
            if item.get("cpe_name_id")
        }

    by_uuid = {
        str(a.cpe.cpe_name_id).lower(): a
        for a in associations
        if str(a.cpe.cpe_name_id).lower() in uuids
        and a.validated_identity_fingerprint == identity_fingerprint
    }
    confirmed = sum(
        a.validation_status == AssetCpe.Validation.CONFIRMED
        for a in by_uuid.values()
    )
    rejected = sum(
        a.validation_status == AssetCpe.Validation.REJECTED
        for a in by_uuid.values()
    )
    legacy_pending = sum(
        a.validation_status == AssetCpe.Validation.PENDING
        for a in by_uuid.values()
    )
    return {
        "available": available,
        "candidate_ids": uuids,
        "total": len(uuids),
        "exploratory_count": len(exploratory_ids),
        "confirmed": confirmed,
        "rejected": rejected,
        "legacy_pending": legacy_pending,
        "unreviewed": sum(
            uid not in exploratory_ids and (
                uid not in by_uuid
                or by_uuid[uid].validation_status not in (
                    AssetCpe.Validation.CONFIRMED, AssetCpe.Validation.REJECTED
                )
            ) for uid in uuids
        ),
    }
