"""Queue and execute NVD CPE discovery without mixing candidates and validations."""
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from assets.models import Asset
from vulnerabilities.models import CpeSearchRun

from .identity import hardware_identity, fingerprint, build_queries
from .candidate_matching import normalize_candidate, merge_candidates
from .nvd_client import fetch_page, PAGE_SIZE, MAX_PAGES_PER_STRATEGY, MAX_TOTAL_CANDIDATES
from .worker_lock import worker_lock_held


def create_run(asset_id, user, scope):
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
            return existing
        return CpeSearchRun.objects.create(
            asset=asset, requested_by=user, scope=scope, identity_snapshot=identity,
            identity_fingerprint=digest,
        )


def _persist(run, fields):
    for key, value in fields.items():
        setattr(run, key, value)
    run.save(update_fields=list(fields))


def execute_run(run, pacer, fetcher=fetch_page):
    """Executed only by the separately locked worker (or mocked tests)."""
    if run.status != CpeSearchRun.Status.QUEUED:
        return run
    _persist(run, {
        "status": CpeSearchRun.Status.RUNNING,
        "started_at": timezone.now(),
        "error_message": "",
        "queries": [],
        "candidates": [],
        "result_truncated": False,
    })
    queries = []
    dedup = {}
    truncated = False
    try:
        plan = build_queries(run.identity_snapshot, run.scope)
        for query in plan:
            details = {
                **query, "pages": 0, "total_results": None, "retrieved": 0, "status": "RUNNING",
            }
            queries.append(details)
            _persist(run, {"queries": queries})
            for page in range(MAX_PAGES_PER_STRATEGY):
                data = fetcher(query["strategy"], query["parameter"], page * PAGE_SIZE, pacer)
                details["pages"] += 1
                total = int(data.get("totalResults", 0))
                details["total_results"] = total
                products = data["products"]
                details["retrieved"] += len(products)
                for row in products:
                    item = normalize_candidate(row, run.identity_snapshot, query["strategy"])
                    if item is None:
                        continue
                    if item["cpe_name_id"] in dedup:
                        old = dedup[item["cpe_name_id"]]
                        old["methods"] = sorted(set(old["methods"] + item["methods"]))
                    elif len(dedup) < MAX_TOTAL_CANDIDATES:
                        dedup[item["cpe_name_id"]] = item
                    else:
                        truncated = True
                _persist(run, {"queries": queries, "candidates": merge_candidates(list(dedup.values()))})
                start = page * PAGE_SIZE
                if start + len(products) >= total or not products:
                    break
                if len(dedup) >= MAX_TOTAL_CANDIDATES:
                    truncated = True
                    break
            else:
                if details["retrieved"] < (details["total_results"] or 0):
                    truncated = True
            details["status"] = "COMPLETED"
            _persist(run, {"queries": queries})
            # Continue to the next strategy even after the candidate cap:
            # an official CPE already kept may also be found by both methods.
            # The page cap above prevents unbounded additional requests.
        _persist(run, {
            "status": CpeSearchRun.Status.COMPLETED,
            "finished_at": timezone.now(),
            "candidates": merge_candidates(list(dedup.values())),
            "result_truncated": truncated,
            "queries": queries,
        })
    except Exception as error:
        if queries:
            queries[-1]["status"] = "FAILED"
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
        "candidates": run.candidates,
        "candidate_count": len(run.candidates),
        "result_truncated": run.result_truncated,
        "error_message": run.error_message,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
    }
