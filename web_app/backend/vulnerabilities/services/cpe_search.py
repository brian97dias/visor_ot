"""Queue and execute NVD CPE discovery without mixing candidates and validations."""
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from assets.models import Asset
from vulnerabilities.models import CpeSearchRun

from .identity import hardware_identity, fingerprint, build_queries, build_level_queries
from .candidate_matching import normalize_candidate, merge_candidates, hardware_candidates, is_pertinent
from .nvd_client import fetch_page, PAGE_SIZE, MAX_PAGES_PER_STRATEGY, MAX_TOTAL_CANDIDATES
from .worker_lock import worker_lock_held

# Shared across all discovery levels: never reset budgets on fallback.
MAX_TOTAL_PAGE_FETCHES = 8


def create_run(asset_id, user, scope, *, return_reused=False):
    with transaction.atomic():
        # Lock only Asset: the reverse OneToOne "hardware" is nullable for
        # software assets, and PostgreSQL rejects FOR UPDATE on its OUTER JOIN.
        # Access to asset.hardware below performs a separate query inside
        # this transaction, after the Asset row has been locked.
        asset = Asset.objects.select_for_update().get(pk=asset_id)
        identity = hardware_identity(asset)
        try:
            build_queries(identity, scope)
        except ValueError as error:
            raise ValidationError({"identity": str(error)}) from error
        digest = fingerprint(identity)
        existing = CpeSearchRun.objects.filter(
            asset=asset, identity_fingerprint=digest,
            scope=scope, status__in=(CpeSearchRun.Status.QUEUED, CpeSearchRun.Status.RUNNING)
        ).first()
        if existing is not None:
            return (existing, True) if return_reused else existing
        run = CpeSearchRun.objects.create(
            asset=asset, requested_by=user, scope=scope, identity_snapshot=identity,
            identity_fingerprint=digest,
        )
        return (run, False) if return_reused else run


def _persist(run, fields):
    for key, value in fields.items():
        setattr(run, key, value)
    run.save(update_fields=list(fields))


def execute_run(run, pacer, fetcher=fetch_page):
    """Progressive hardware discovery. Only the locked worker calls NVD.

    SPECIFIC starts with the original precise plan and falls back to FAMILY.
    BROAD starts with FAMILY. This phase never searches manufacturer-wide.
    Failed or partial queries do not establish absence of a relevant CPE.
    """
    if run.status != CpeSearchRun.Status.QUEUED:
        return run
    _persist(run, {
        "status": CpeSearchRun.Status.RUNNING,
        "started_at": timezone.now(), "error_message": "",
        "queries": [], "candidates": [], "result_truncated": False,
    })
    queries = []
    dedup = {}
    fetched_pages = 0
    truncated = False
    seen_queries = set()
    levels = ("SPECIFIC", "FAMILY") if run.scope == "SPECIFIC" else ("FAMILY",)

    try:
        for level in levels:
            level_queries = []
            level_seen = set()
            for query in build_level_queries(run.identity_snapshot, level):
                key = (query["strategy"], query["parameter"])
                if key not in seen_queries:
                    level_queries.append(query)
                    seen_queries.add(key)
            if not level_queries:
                # No new queries can broaden this identity; do not repeat HTTP.
                if queries:
                    queries[-1]["next_level_reason"] = "NO_NEW_PARAMETERS"
                break

            level_uuids = set()
            level_partial = False
            for query in level_queries:
                details = {
                    **query, "level": level, "pages": 0, "total_results": None,
                    "retrieved": 0, "hardware_results": 0, "pertinent_results": 0,
                    "related_results": 0, "status": "RUNNING",
                }
                queries.append(details)
                _persist(run, {"queries": queries})
                if (fetched_pages >= MAX_TOTAL_PAGE_FETCHES or
                        len(dedup) >= MAX_TOTAL_CANDIDATES):
                    details["status"] = "SKIPPED"
                    details["stop_reason"] = "GLOBAL_BUDGET_EXHAUSTED"
                    truncated = level_partial = True
                    _persist(run, {"queries": queries})
                    break

                for page in range(MAX_PAGES_PER_STRATEGY):
                    if fetched_pages >= MAX_TOTAL_PAGE_FETCHES:
                        details["stop_reason"] = "GLOBAL_PAGE_LIMIT"
                        truncated = level_partial = True
                        break
                    # Count a page fetch even if the HTTP call fails; the pacer
                    # itself protects retries, and the FAILED status is retained.
                    fetched_pages += 1
                    data = fetcher(query["strategy"], query["parameter"], page * PAGE_SIZE, pacer)
                    products = data["products"]
                    total = int(data.get("totalResults", 0))
                    details["pages"] += 1
                    details["total_results"] = total
                    details["retrieved"] += len(products)
                    for row in products:
                        item = normalize_candidate(row, run.identity_snapshot, query["strategy"])
                        if item is None:
                            continue
                        details["hardware_results"] += 1
                        if is_pertinent(item, run.identity_snapshot):
                            details["pertinent_results"] += 1
                        elif item["match_level"] == "RELATED":
                            details["related_results"] += 1
                        level_uuids.add(item["cpe_name_id"])
                        if item["cpe_name_id"] in dedup:
                            old = dedup[item["cpe_name_id"]]
                            old["methods"] = sorted(set(old["methods"] + item["methods"]))
                            old["discovery_levels"] = sorted(set(
                                old.get("discovery_levels", []) + [level]
                            ))
                        elif len(dedup) < MAX_TOTAL_CANDIDATES:
                            item["discovery_levels"] = [level]
                            dedup[item["cpe_name_id"]] = item
                        else:
                            truncated = level_partial = True
                            details["stop_reason"] = "CANDIDATE_LIMIT"
                    _persist(run, {
                        "queries": queries,
                        "candidates": merge_candidates(list(dedup.values())),
                        "result_truncated": truncated,
                    })
                    if truncated:
                        break
                    if page * PAGE_SIZE + len(products) >= total or not products:
                        break
                    if len(dedup) >= MAX_TOTAL_CANDIDATES:
                        truncated = level_partial = True
                        details["stop_reason"] = "CANDIDATE_LIMIT"
                        break
                else:
                    if details["retrieved"] < (details["total_results"] or 0):
                        truncated = level_partial = True
                        details["stop_reason"] = "PER_STRATEGY_PAGE_LIMIT"
                details["status"] = "PARTIAL" if level_partial else "COMPLETED"
                _persist(run, {"queries": queries, "result_truncated": truncated})
                if level_partial:
                    break

            strong = sum(is_pertinent(dedup[uuid], run.identity_snapshot)
                         for uuid in level_uuids if uuid in dedup)
            # A progress reason travels with each query; historical queries
            # without this metadata remain valid and readable.
            reason = ("PARTIAL_RESULTS" if level_partial else
                      "SUFFICIENT_PERTINENT_CANDIDATES" if strong else
                      "NO_PERTINENT_CANDIDATES")
            for details in queries:
                if details.get("level") == level:
                    details["level_result"] = reason
                    details["level_unique_hardware_candidates"] = len(level_uuids)
                    details["level_pertinent_candidates"] = strong
                    if not strong and not level_partial and level == "SPECIFIC":
                        details["next_level_reason"] = "NO_PERTINENT_CANDIDATES"
            _persist(run, {"queries": queries})
            if level_partial or strong:
                break

        _persist(run, {
            "status": CpeSearchRun.Status.COMPLETED,
            "finished_at": timezone.now(),
            "candidates": merge_candidates(list(dedup.values())),
            "result_truncated": truncated, "queries": queries,
        })
    except Exception as error:
        if queries:
            queries[-1]["status"] = "FAILED"
            queries[-1]["stop_reason"] = "REQUEST_FAILED"
        _persist(run, {
            "status": CpeSearchRun.Status.FAILED,
            "error_message": str(error)[:1000],
            "finished_at": timezone.now(),
            "queries": queries,
            "candidates": merge_candidates(list(dedup.values())),
            "result_truncated": truncated,
        })
    return run


def serialize_run(run):
    try:
        current = fingerprint(hardware_identity(run.asset))
        is_current = run.identity_fingerprint == current
    except (ValueError, AttributeError):
        is_current = False
    candidates = hardware_candidates(run.candidates)
    return {
        "id": run.pk,
        "asset_id": run.asset_id,
        "status": run.status,
        # Reports the worker advisory lock, not a guarantee of successful NVD access.
        "worker_active": worker_lock_held() if run.status in (
            CpeSearchRun.Status.QUEUED, CpeSearchRun.Status.RUNNING
        ) else None,
        "scope": run.scope,
        "trigger": run.trigger,
        "identity_snapshot": run.identity_snapshot,
        "identity_is_current": is_current,
        "queries": run.queries,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "result_truncated": run.result_truncated,
        "error_message": run.error_message,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
    }
