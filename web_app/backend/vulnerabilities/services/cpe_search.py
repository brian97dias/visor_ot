"""Queue and execute NVD CPE discovery without mixing candidates and validations."""
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from assets.models import Asset
from vulnerabilities.models import CpeSearchRun

from .identity import hardware_identity, fingerprint, build_queries, build_level_queries
from .candidate_matching import (
    normalize_candidate, merge_candidates, hardware_candidates,
    is_pertinent, is_manufacturer_related,
)
from .nvd_client import fetch_page, PAGE_SIZE, MAX_PAGES_PER_STRATEGY, MAX_TOTAL_CANDIDATES
from .worker_lock import worker_lock_held
from .advanced_query import validate_advanced_query
from .nvd_references import combine_references

# Shared across all discovery levels: never reset budgets on fallback.
MAX_TOTAL_PAGE_FETCHES = 8
# A manufacturer may have thousands of records; avoid scanning the full catalog.
# This per-level limit never overrides the smaller remaining global budget.
MAX_MANUFACTURER_PAGES = 2
# Shared by ALL vendor spellings and product-prefix probes in the third level.
MAX_MANUFACTURER_LEVEL_PAGES = 4


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
            scope=scope, trigger="MANUAL",
            status__in=(CpeSearchRun.Status.QUEUED, CpeSearchRun.Status.RUNNING)
        ).first()
        if existing is not None:
            return (existing, True) if return_reused else existing
        run = CpeSearchRun.objects.create(
            asset=asset, requested_by=user, scope=scope, identity_snapshot=identity,
            identity_fingerprint=digest,
        )
        return (run, False) if return_reused else run



def create_advanced_run(asset_id, user, payload):
    """Queue a validated manual plan; reuses only an identical active manual job."""
    with transaction.atomic():
        asset = Asset.objects.select_for_update().get(pk=asset_id)
        if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
            raise ValidationError({"asset": "Solo se buscan CPE de hardware activo."})
        identity = hardware_identity(asset)
        try:
            build_queries(identity, "SPECIFIC")
            plan = validate_advanced_query(identity, payload)
        except ValueError as exc:
            raise ValidationError({"advanced": str(exc)}) from exc
        digest = fingerprint(identity)
        for existing in CpeSearchRun.objects.filter(
            asset=asset, identity_fingerprint=digest, trigger="ADVANCED",
            status__in=(CpeSearchRun.Status.QUEUED, CpeSearchRun.Status.RUNNING),
        ):
            if existing.queries:
                prior = existing.queries[0]
                if all(prior.get(k) == v for k, v in plan.items()):
                    return existing, True
        run = CpeSearchRun.objects.create(
            asset=asset, requested_by=user, scope=CpeSearchRun.Scope.SPECIFIC,
            trigger="ADVANCED", identity_snapshot=identity,
            identity_fingerprint=digest,
            queries=[{**plan, "level": "ADVANCED", "status": "PLANNED"}],
        )
        return run, False


def _persist(run, fields):
    for key, value in fields.items():
        setattr(run, key, value)
    run.save(update_fields=list(fields))


def execute_advanced_run(run, pacer, fetcher=fetch_page):
    """Execute a single manual strategy with stored offset and page budget.

    Uses the same worker lock and public NVD pacer as automatic discovery.
    Filtering always uses the *inventoried* identity, never the user's claim.
    """
    if run.status != CpeSearchRun.Status.QUEUED:
        return run
    raw_plan = run.queries[0] if run.queries else {}
    try:
        plan = validate_advanced_query(run.identity_snapshot, {
            key: raw_plan[key] for key in
            ("strategy", "parameter", "start_index", "max_pages")
            if key in raw_plan
        })
    except ValueError as exc:
        _persist(run, {"status": CpeSearchRun.Status.FAILED,
                       "error_message": str(exc),
                       "finished_at": timezone.now()})
        return run
    details = {
        **plan, "level": "ADVANCED", "status": "RUNNING",
        "pages": 0, "total_results": None, "retrieved": 0,
        "hardware_results": 0, "filtered_hardware_results": 0,
        "related_results": 0, "pertinent_results": 0,
    }
    dedup = {}
    truncated = bool(plan["start_index"])
    _persist(run, {
        "status": CpeSearchRun.Status.RUNNING, "started_at": timezone.now(),
        "queries": [details], "candidates": [],
        "result_truncated": truncated, "error_message": "",
    })
    try:
        for index in range(plan["max_pages"]):
            start = plan["start_index"] + index * PAGE_SIZE
            data = fetcher(plan["strategy"], plan["parameter"], start, pacer)
            products = data["products"]
            total = int(data.get("totalResults", 0))
            details["pages"] += 1
            details["total_results"] = total
            details["retrieved"] += len(products)
            for row in products:
                item = normalize_candidate(row, run.identity_snapshot, plan["strategy"])
                if item is None:
                    continue
                details["hardware_results"] += 1
                if not is_manufacturer_related(item, run.identity_snapshot):
                    details["filtered_hardware_results"] += 1
                    continue
                if is_pertinent(item, run.identity_snapshot):
                    details["pertinent_results"] += 1
                elif item["match_level"] == "RELATED":
                    details["related_results"] += 1
                if item["cpe_name_id"] in dedup:
                    old = dedup[item["cpe_name_id"]]
                    old["methods"] = sorted(set(old["methods"] + item["methods"]))
                    old["nvd_references"] = combine_references(
                        old.get("nvd_references", []), item.get("nvd_references", [])
                    )
                elif len(dedup) < MAX_TOTAL_CANDIDATES:
                    item["discovery_levels"] = ["ADVANCED"]
                    dedup[item["cpe_name_id"]] = item
                else:
                    truncated = True
                    details["stop_reason"] = "CANDIDATE_LIMIT"
                    break
            _persist(run, {
                "queries": [details], "candidates": merge_candidates(list(dedup.values())),
                "result_truncated": truncated,
            })
            if details.get("stop_reason"):
                break
            if start + len(products) >= total or not products:
                break
        else:
            if plan["start_index"] + details["retrieved"] < (details["total_results"] or 0):
                truncated = True
                details["stop_reason"] = "ADVANCED_PAGE_LIMIT"

        if plan["start_index"] and not details.get("stop_reason"):
            details["stop_reason"] = "ADVANCED_OFFSET"
        details["level_result"] = (
            "PARTIAL_RESULTS" if truncated else
            "SUFFICIENT_PERTINENT_CANDIDATES" if details["pertinent_results"] else
            "NO_PERTINENT_CANDIDATES"
        )
        details["level_unique_hardware_candidates"] = len(dedup)
        details["level_pertinent_candidates"] = sum(
            is_pertinent(item, run.identity_snapshot) for item in dedup.values()
        )
        details["status"] = "PARTIAL" if truncated else "COMPLETED"
        _persist(run, {
            "status": CpeSearchRun.Status.COMPLETED, "finished_at": timezone.now(),
            "queries": [details], "candidates": merge_candidates(list(dedup.values())),
            "result_truncated": truncated,
        })
    except Exception as exc:
        details["status"] = "FAILED"
        details["stop_reason"] = "REQUEST_FAILED"
        _persist(run, {
            "status": CpeSearchRun.Status.FAILED,
            "error_message": str(exc)[:1000], "finished_at": timezone.now(),
            "queries": [details], "candidates": merge_candidates(list(dedup.values())),
            "result_truncated": truncated,
        })
    return run


def execute_run(run, pacer, fetcher=fetch_page):
    """Progressive hardware discovery. Only the locked worker calls NVD.

    SPECIFIC progresses through precise, family, and manufacturer levels.
    BROAD starts with family then may use manufacturer.
    The manufacturer query is restricted to hardware and locally filtered for
    product/family relevance. Failed or partial queries never prove absence.
    """
    if run.status != CpeSearchRun.Status.QUEUED:
        return run
    if getattr(run, "trigger", None) == "ADVANCED":
        return execute_advanced_run(run, pacer, fetcher)
    _persist(run, {
        "status": CpeSearchRun.Status.RUNNING,
        "started_at": timezone.now(), "error_message": "",
        "queries": [], "candidates": [], "result_truncated": False,
    })
    queries = []
    dedup = {}
    fetched_pages = 0
    manufacturer_pages = 0
    truncated = False
    seen_queries = set()
    levels = (
        ("SPECIFIC", "FAMILY", "MANUFACTURER")
        if run.scope == "SPECIFIC" else ("FAMILY", "MANUFACTURER")
    )

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
                # The family spelling may equal the specific spelling. Do not
                # repeat either request, but still try manufacturer discovery.
                if queries:
                    queries[-1]["next_level_reason"] = "NO_NEW_PARAMETERS"
                    _persist(run, {"queries": queries})
                continue

            level_uuids = set()
            level_partial = False
            for query in level_queries:
                details = {
                    **query, "level": level, "pages": 0, "total_results": None,
                    "retrieved": 0, "hardware_results": 0, "pertinent_results": 0,
                    "related_results": 0, "filtered_hardware_results": 0,
                    "status": "RUNNING",
                }
                queries.append(details)
                _persist(run, {"queries": queries})
                if (fetched_pages >= MAX_TOTAL_PAGE_FETCHES or
                        len(dedup) >= MAX_TOTAL_CANDIDATES or
                        (level == "MANUFACTURER" and
                         manufacturer_pages >= MAX_MANUFACTURER_LEVEL_PAGES)):
                    details["status"] = "SKIPPED"
                    details["stop_reason"] = (
                        "MANUFACTURER_LEVEL_LIMIT" if (
                            level == "MANUFACTURER"
                            and manufacturer_pages >= MAX_MANUFACTURER_LEVEL_PAGES
                            and fetched_pages < MAX_TOTAL_PAGE_FETCHES
                            and len(dedup) < MAX_TOTAL_CANDIDATES
                        ) else "GLOBAL_BUDGET_EXHAUSTED"
                    )
                    truncated = level_partial = True
                    _persist(run, {"queries": queries})
                    break

                max_pages = (
                    min(MAX_MANUFACTURER_PAGES, MAX_PAGES_PER_STRATEGY)
                    if level == "MANUFACTURER" else MAX_PAGES_PER_STRATEGY
                )
                for page in range(max_pages):
                    if fetched_pages >= MAX_TOTAL_PAGE_FETCHES:
                        details["stop_reason"] = "GLOBAL_PAGE_LIMIT"
                        truncated = level_partial = True
                        break
                    if (level == "MANUFACTURER"
                            and manufacturer_pages >= MAX_MANUFACTURER_LEVEL_PAGES):
                        details["stop_reason"] = "MANUFACTURER_LEVEL_LIMIT"
                        truncated = level_partial = True
                        break
                    # Count a page fetch even if the HTTP call fails; the pacer
                    # itself protects retries, and the FAILED status is retained.
                    fetched_pages += 1
                    if level == "MANUFACTURER":
                        manufacturer_pages += 1
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
                        if level == "MANUFACTURER" and not is_manufacturer_related(
                            item, run.identity_snapshot
                        ):
                            # Count rejected records for audit, without storing
                            # unrelated products as asset CPE candidates.
                            details["filtered_hardware_results"] += 1
                            continue
                        if is_pertinent(item, run.identity_snapshot):
                            details["pertinent_results"] += 1
                        elif item["match_level"] == "RELATED":
                            details["related_results"] += 1
                        level_uuids.add(item["cpe_name_id"])
                        if item["cpe_name_id"] in dedup:
                            old = dedup[item["cpe_name_id"]]
                            old["methods"] = sorted(set(old["methods"] + item["methods"]))
                            old["nvd_references"] = combine_references(
                                old.get("nvd_references", []), item.get("nvd_references", [])
                            )
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
                        details["stop_reason"] = (
                            "MANUFACTURER_PAGE_LIMIT" if level == "MANUFACTURER"
                            else "PER_STRATEGY_PAGE_LIMIT"
                        )
                details["status"] = "PARTIAL" if level_partial else "COMPLETED"
                _persist(run, {"queries": queries, "result_truncated": truncated})
                if level_partial:
                    break
                if level == "MANUFACTURER" and any(
                    is_pertinent(dedup[uuid], run.identity_snapshot)
                    for uuid in level_uuids if uuid in dedup
                ):
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
                    if not strong and not level_partial and level != "MANUFACTURER":
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
