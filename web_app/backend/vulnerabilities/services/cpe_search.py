"""Queue and execute NVD CPE discovery without mixing candidates and validations."""
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from assets.models import Asset
from vulnerabilities.models import CpeSearchRun, CpeQuerySnapshot, CpeQueryProduct

from .identity import (
    hardware_identity, software_identity, fingerprint, build_queries,
    build_level_queries, build_cpe_match_plan, build_software_cpe_match_plan,
    build_alternative_keyword_plan,
)
from .candidate_matching import (
    normalize_candidate, merge_candidates, hardware_candidates, candidates_for_identity,
    is_pertinent, is_manufacturer_related, classify_alternative_vendor,
)
from .nvd_client import fetch_page, PAGE_SIZE, MAX_PAGES_PER_STRATEGY, MAX_TOTAL_CANDIDATES
from .worker_lock import worker_lock_held
from .advanced_query import validate_advanced_query
from .nvd_references import combine_references
from .cpe_catalogue import enqueue_catalogue_query

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
        if (asset.asset_type == Asset.AssetType.SOFTWARE
                and asset.inventory_status != Asset.InventoryStatus.ACTIVE):
            raise ValidationError({"asset": "Solo se buscan CPE de software vigente."})
        identity = (software_identity(asset) if asset.asset_type == Asset.AssetType.SOFTWARE
                    else hardware_identity(asset))
        try:
            if identity["asset_type"] == "SOFTWARE":
                build_software_cpe_match_plan(identity)
            else:
                build_cpe_match_plan(identity)
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


def execute_legacy_run(run, pacer, fetcher=fetch_page):
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



# New automatic engine: bounded preview requests, full manufacturer catalogue
# traversal delegated to the existing resumable snapshot worker. The old
# executor above remains available for verifying historical regressions.
AUTO_MAX_PAGES_PER_QUERY = 3
AUTO_TOTAL_PREVIEW_PAGES = 40
MAX_EXPLORATORY_CANDIDATES = 5


def _exploratory_rank(item):
    return (bool(item.get("deprecated")), item.get("exploratory_distance", 100000),
            str(item.get("cpe_name") or ""))



def _record_candidate(row, run, level, dedup, details, *, alternative=False,
                      version_scope=None):
    """Record one NVD product as an explainable suggestion, never validation."""
    item = normalize_candidate(
        row, run.identity_snapshot,
        "keywordSearch" if alternative else "cpeMatchString",
    )
    if item is None:
        return
    # NVD wildcard version prefixes are not exact branch filters:
    # 12.1* may also return 12.10. Recheck each row locally.
    if version_scope == "BRANCH_PREFIX" and item["match_level"] not in (
        "SOFTWARE_EXACT", "SOFTWARE_BRANCH",
    ):
        return
    if run.identity_snapshot.get("asset_type") == "SOFTWARE":
        details["software_results"] = details.get("software_results", 0) + 1
    else:
        details["hardware_results"] += 1
    brand_discrepancy = (
        classify_alternative_vendor(item, run.identity_snapshot)
        if alternative else None
    )
    if brand_discrepancy:
        item["match_level"] = "EXPLORATORY"
        item["match_reason"] = brand_discrepancy
        # Keep evidence with an exact alternate-vendor model above weak
        # manufacturer-prefix-only firmware hints in the shared top-five.
        item["exploratory_distance"] = (
            2000000 if run.identity_snapshot.get("asset_type") == "SOFTWARE"
            else 0
        )
    elif not is_manufacturer_related(item, run.identity_snapshot):
        details["filtered_hardware_results"] += 1
        return
    if is_pertinent(item, run.identity_snapshot):
        details["pertinent_results"] += 1
    elif item["match_level"] == "RELATED":
        details["related_results"] += 1
    elif item["match_level"] == "EXPLORATORY":
        details["exploratory_results"] = details.get("exploratory_results", 0) + 1
    key = item["cpe_name_id"]
    if key in dedup:
        old = dedup[key]
        old["methods"] = sorted(set(old.get("methods", []) + item["methods"]))
        old["nvd_references"] = combine_references(
            old.get("nvd_references", []), item.get("nvd_references", [])
        )
        old["discovery_levels"] = sorted(set(
            old.get("discovery_levels", []) + [level]
        ))
    elif item["match_level"] == "EXPLORATORY":
        # Keep only five optional suggestions. Never consume technical-match
        # slots or mark a complete retrieval as partial due to this cap.
        weak = [v for v in dedup.values() if v.get("match_level") == "EXPLORATORY"]
        if len(weak) < MAX_EXPLORATORY_CANDIDATES:
            item["discovery_levels"] = [level]
            dedup[key] = item
        else:
            worst = max(weak, key=_exploratory_rank)
            if _exploratory_rank(item) < _exploratory_rank(worst):
                del dedup[worst["cpe_name_id"]]
                item["discovery_levels"] = [level]
                dedup[key] = item
    elif run.identity_snapshot.get("asset_type") == "SOFTWARE":
        # Save representative evidence rather than thousands of IOS versions.
        # The NVD catalogue itself remains fully checkpointed and reusable.
        same_level = [v for v in dedup.values()
                      if v.get("match_level") == item["match_level"]]
        if len(same_level) < 5:
            item["discovery_levels"] = [level]
            dedup[key] = item
    elif sum(v.get("match_level") != "EXPLORATORY" for v in dedup.values()) < MAX_TOTAL_CANDIDATES:
        item["discovery_levels"] = [level]
        dedup[key] = item
    else:
        details["candidate_limit_reached"] = True


def _snapshot_products(snapshot):
    """Read original NVD evidence in batches, never preload the catalogue."""
    return (CpeQueryProduct.objects.filter(snapshot=snapshot)
            .order_by("pk").values_list("nvd_record", flat=True)
            .iterator(chunk_size=500))


def execute_run(run, pacer, fetcher=fetch_page):
    """Automatic structured discovery plus optional brand/provider investigation.

    Each completed query is checkpointed in CpeSearchRun. At the manufacturer
    level, enqueue/reuse a CpeQuerySnapshot and leave this run QUEUED until
    the worker finishes the complete catalogue retrieval. On restart, skip
    completed queries and resume from the recorded waiting snapshot.
    """
    if run.status != CpeSearchRun.Status.QUEUED:
        return run
    if getattr(run, "trigger", None) == "ADVANCED":
        return execute_advanced_run(run, pacer, fetcher)
    if getattr(run, "trigger", "MANUAL") != "MANUAL":
        return run
    queries = list(run.queries or [])
    dedup = {c["cpe_name_id"]: c for c in (run.candidates or [])
             if isinstance(c, dict) and isinstance(c.get("cpe_name_id"), str)}
    try:
        software = run.identity_snapshot.get("asset_type") == "SOFTWARE"
        if software:
            planned = build_software_cpe_match_plan(run.identity_snapshot)
        else:
            planned = build_cpe_match_plan(run.identity_snapshot)
        # The same last-resort keyword investigation now handles software.
        # Existing structured matches always take precedence.
        planned += build_alternative_keyword_plan(run.identity_snapshot)
        if run.scope == CpeSearchRun.Scope.BROAD:
            planned = [q for q in planned if q["level"] != "SPECIFIC"]
    except ValueError as exc:
        _persist(run, {
            "status": CpeSearchRun.Status.FAILED, "finished_at": timezone.now(),
            "error_message": str(exc), "result_truncated": True,
        })
        return run
    if not queries:
        _persist(run, {
            "status": CpeSearchRun.Status.RUNNING,
            "started_at": timezone.now(),
            "error_message": "", "queries": [], "candidates": [],
            "result_truncated": False,
        })
    else:
        _persist(run, {"status": CpeSearchRun.Status.RUNNING,
                       "error_message": ""})
    preview_pages = sum(q.get("pages", 0) for q in queries
                        if not q.get("snapshot_id"))
    active_details = None
    try:
        for step in planned:
            # Optional keyword investigation is strictly the LAST resort.
            # Neither failures nor partial preceding searches prove absence.
            if step["level"] == "ALTERNATIVE" and (dedup or run.result_truncated):
                break
            if software and step.get("version_scope") == "MANUFACTURER_CATALOGUE" and dedup:
                break
            # Only replay a previously WAITING query; completed queries
            # already have durable evidence and must not be requested again.
            previous = next((q for q in queries if
                             q.get("parameter") == step["parameter"] and
                             q.get("level") == step["level"]), None)
            if previous and previous.get("status") == "COMPLETED":
                continue
            if previous and previous.get("status") not in ("WAITING_CATALOGUE",):
                raise ValueError("Estado inconsistente del plan CPE. Requiere nueva búsqueda.")
            details = previous or {
                **step, "status": "RUNNING", "pages": 0,
                "retrieved": 0, "total_results": None,
                "hardware_results": 0, "filtered_hardware_results": 0,
                "pertinent_results": 0, "related_results": 0,
            }
            active_details = details
            if previous is None:
                queries.append(details)
            if (step["level"] in ("MANUFACTURER", "ALTERNATIVE")
                    or (software and step.get("version_scope") in (
                        "BRANCH_PREFIX", "PRODUCT_CATALOGUE", "RELATED_SERIES",
                    ))):
                if previous:
                    snapshot = CpeQuerySnapshot.objects.select_related("cache").get(
                        pk=details["snapshot_id"]
                    )
                    if (snapshot.cache.strategy != step["strategy"] or
                            snapshot.cache.parameter != step["parameter"]):
                        raise ValueError("La recuperación NVD no pertenece a esta consulta.")
                else:
                    snapshot, reused = enqueue_catalogue_query(
                        step["strategy"], step["parameter"]
                    )
                    details["snapshot_id"] = snapshot.pk
                    details["cache_reused"] = reused
                details["retrieved"] = snapshot.retrieved_count
                details["total_results"] = snapshot.expected_total
                details["pages"] = snapshot.pages_fetched
                if snapshot.status != CpeQuerySnapshot.Status.COMPLETED:
                    if snapshot.status == CpeQuerySnapshot.Status.FAILED:
                        details["status"] = "FAILED"
                        details["stop_reason"] = snapshot.error_code or "CATALOGUE_FAILED"
                        raise ValueError(
                            "No se completó la recuperación del catálogo NVD: "
                            + (snapshot.error_message or details["stop_reason"])
                        )
                    details["status"] = "WAITING_CATALOGUE"
                    details["level_result"] = "WAITING_CATALOGUE"
                    _persist(run, {
                        "status": CpeSearchRun.Status.QUEUED, "queries": queries,
                        "candidates": merge_candidates(list(dedup.values())),
                    })
                    return run
                details["status"] = "RUNNING"
                # A complete snapshot may be reused by many different assets.
                for row in _snapshot_products(snapshot):
                    _record_candidate(
                        row, run, step["level"], dedup, details,
                        alternative=step["level"] == "ALTERNATIVE",
                        version_scope=step.get("version_scope"),
                    )
                details["status"] = "COMPLETED"
                details["catalogue_complete"] = True
                details["level_result"] = (
                    "EXPLORATORY_BRAND_MATCHES"
                    if step["level"] == "ALTERNATIVE" and details.get("exploratory_results")
                    else "SUFFICIENT_PERTINENT_CANDIDATES"
                    if details["pertinent_results"] else "NO_PERTINENT_CANDIDATES"
                )
                if details.get("candidate_limit_reached"):
                    details["level_result"] = "PARTIAL_RESULTS"
                    details["stop_reason"] = "CANDIDATE_LIMIT"
                    run.result_truncated = True
                _persist(run, {"queries": queries,
                               "candidates": merge_candidates(list(dedup.values())),
                               "result_truncated": run.result_truncated})
                if (details["pertinent_results"] or details.get("candidate_limit_reached")
                        or (step["level"] == "ALTERNATIVE" and dedup)
                        or (software and step.get("version_scope") == "BRANCH_PREFIX"
                            and any(v.get("match_level") in ("SOFTWARE_BRANCH", "SOFTWARE_EXACT")
                                    for v in dedup.values()))
                        or (software and step.get("version_scope") == "PRODUCT_CATALOGUE"
                            and any(v.get("match_level") in (
                                "SOFTWARE_BRANCH", "SOFTWARE_PRODUCT", "SOFTWARE_EXACT"
                            ) for v in dedup.values()))):
                    break
                continue

            # Bounded preview of specific/product-prefix queries. Truncated
            # previews are explicitly PARTIAL and do NOT imply no matching CPE.
            total = None
            offset = 0
            for page_index in range(AUTO_MAX_PAGES_PER_QUERY):
                if preview_pages >= AUTO_TOTAL_PREVIEW_PAGES:
                    details["stop_reason"] = "GLOBAL_PREVIEW_BUDGET"
                    break
                data = fetcher("cpeMatchString", step["parameter"], offset, pacer)
                preview_pages += 1
                products = data.get("products")
                count = data.get("totalResults")
                if not isinstance(products, list) or type(count) is not int or count < 0:
                    raise ValueError("NVD devolvió una página inválida.")
                if len(products) > PAGE_SIZE or offset + len(products) > count:
                    raise ValueError("NVD devolvió una página inconsistente.")
                details["pages"] += 1
                details["total_results"] = count
                details["retrieved"] += len(products)
                total = count
                for row in products:
                    _record_candidate(
                        row, run, step["level"], dedup, details,
                        version_scope=step.get("version_scope"),
                    )
                _persist(run, {"queries": queries,
                               "candidates": merge_candidates(list(dedup.values())),
                               "result_truncated": run.result_truncated})
                offset += len(products)
                if offset >= count:
                    break
                if not products:
                    details["stop_reason"] = "EMPTY_PAGE"
                    break
            if total is None or offset < total or details.get("candidate_limit_reached"):
                details["status"] = "PARTIAL"
                details["stop_reason"] = details.get("stop_reason") or (
                    "CANDIDATE_LIMIT" if details.get("candidate_limit_reached")
                    else "PREVIEW_PAGE_LIMIT"
                )
                details["level_result"] = "PARTIAL_RESULTS"
                _persist(run, {"queries": queries,
                               "result_truncated": True})
                break
            details["status"] = "COMPLETED"
            details["level_result"] = (
                "SUFFICIENT_PERTINENT_CANDIDATES"
                if details["pertinent_results"] else "NO_PERTINENT_CANDIDATES"
            )
            if not details["pertinent_results"]:
                details["next_level_reason"] = "NO_PERTINENT_CANDIDATES"
            _persist(run, {"queries": queries})
            if details["pertinent_results"] and not (
                    software and step.get("version_scope") == "RECORDED_VERSION"
                    and any(q.get("version_scope") == "BRANCH_PREFIX" for q in planned)
            ):
                break

        _persist(run, {
            "status": CpeSearchRun.Status.COMPLETED,
            "finished_at": timezone.now(),
            "candidates": merge_candidates(list(dedup.values())),
            "queries": queries,
            "result_truncated": run.result_truncated,
        })
    except Exception as exc:
        if active_details is not None:
            active_details["status"] = "FAILED"
            active_details["stop_reason"] = active_details.get("stop_reason") or "REQUEST_FAILED"
        _persist(run, {
            "status": CpeSearchRun.Status.FAILED,
            "finished_at": timezone.now(), "error_message": str(exc)[:1000],
            "result_truncated": True,
            "queries": queries, "candidates": merge_candidates(list(dedup.values())),
        })
    return run


def serialize_run(run):
    try:
        identity = (software_identity(run.asset)
                    if run.asset.asset_type == Asset.AssetType.SOFTWARE
                    else hardware_identity(run.asset))
        is_current = run.identity_fingerprint == fingerprint(identity)
    except (ValueError, AttributeError):
        identity = run.identity_snapshot
        is_current = False
    candidates = candidates_for_identity(run.candidates, identity)
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
