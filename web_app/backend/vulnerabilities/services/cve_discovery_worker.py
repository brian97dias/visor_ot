"""Checkpointed CVE discovery under the singleton PostgreSQL NVD worker.

Each accepted NVD page commits its official CVE records, deduplicated
hardware findings and pagination checkpoint in ONE transaction. Neither
this service nor the HTTP layer declares vulnerability applicability.
"""
from collections import defaultdict
from copy import deepcopy

from django.db import transaction
from django.utils import timezone

from assets.models import Hardware
from vulnerabilities.models import AssetCveFinding, CveDiscoveryRun
from .cve_discovery import build_cve_discovery_plan
from .cve_system_audit import ensure_system_cve_assessment
from .cve_ingestion import CveResponseError, validated_cve_record, store_official_cve_record
from .nvd_client import NvdError
from .nvd_cve_client import (
    CVE_RESULTS_PAGE_SIZE, CVE_RESULTS_MAX_PAGE_SIZE,
    fetch_cves_by_cpe, validated_cve_page,
)


class CveDiscoveryError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _queries_for_plan(plan, page_size):
    queries = deepcopy(plan["queries"])
    for query in queries:
        hardware_ids = {source["hardware_id"] for source in query["sources"]}
        query["hardware_fingerprints"] = {
            str(pk): plan["evidence_fingerprints"][str(pk)]
            for pk in sorted(hardware_ids)
        }
        query["page_size"] = page_size
        query["seen_cve_ids"] = []
    return queries


def _assert_current(run):
    """Never run a checkpoint made for different inventory/confirmed CPEs."""
    current = build_cve_discovery_plan(run.selected_hardware_ids)
    live = _queries_for_plan(current, CVE_RESULTS_PAGE_SIZE)
    expected = [
        (q["cpe_name"], q["sources"], q["hardware_fingerprints"])
        for q in run.queries
    ]
    actual = [
        (q["cpe_name"], q["sources"], q["hardware_fingerprints"])
        for q in live
    ]
    if expected != actual:
        raise CveDiscoveryError(
            "STALE_EVIDENCE",
            "El inventario o sus CPE confirmados cambiaron. "
            "Inicia una nueva búsqueda CVE.",
        )


def enqueue_cve_discovery(hardware_ids, actor, *, page_size=CVE_RESULTS_PAGE_SIZE):
    """Create/reuse an active discovery job; no HTTP, no CPE changes.

    PostgreSQL row locks on selected hardware serialize concurrent requests
    that overlap on an asset. This is a callable service; the REST endpoint
    will be implemented in increment 1.5.
    """
    if (type(page_size) is not int
            or not 1 <= page_size <= CVE_RESULTS_MAX_PAGE_SIZE):
        raise ValueError("El tamaño de página CVE debe estar entre 1 y 2000.")
    with transaction.atomic():
        plan = build_cve_discovery_plan(hardware_ids)
        # Stable lock ordering. Do not lock a nullable related asset JOIN.
        list(Hardware.objects.select_for_update().filter(
            pk__in=plan["selected_hardware_ids"]
        ).order_by("pk").values_list("pk", flat=True))
        plan = build_cve_discovery_plan(plan["selected_hardware_ids"])
        if not plan["queries"]:
            raise ValueError(
                "Ningún hardware seleccionado tiene un CPE confirmado vigente."
            )
        queries = _queries_for_plan(plan, page_size)
        candidates = CveDiscoveryRun.objects.select_for_update().filter(
            status__in=(
                CveDiscoveryRun.Status.QUEUED,
                CveDiscoveryRun.Status.RUNNING,
                CveDiscoveryRun.Status.INCOMPLETE,
            ),
            selected_hardware_ids=plan["selected_hardware_ids"],
        ).order_by("-created_at", "-pk")
        for previous in candidates:
            if len(previous.queries) != len(queries):
                continue
            if all(
                old["cpe_name"] == new["cpe_name"]
                and old["sources"] == new["sources"]
                and old.get("hardware_fingerprints") == new["hardware_fingerprints"]
                and old.get("page_size") == page_size
                for old, new in zip(previous.queries, queries)
            ):
                return previous, True
        return CveDiscoveryRun.objects.create(
            requested_by=actor,
            selected_hardware_ids=plan["selected_hardware_ids"],
            queries=queries,
        ), False


def recover_interrupted_cve_discoveries():
    """Only after the existing PostgreSQL advisory lock was acquired."""
    return CveDiscoveryRun.objects.filter(
        status=CveDiscoveryRun.Status.RUNNING,
    ).update(
        status=CveDiscoveryRun.Status.INCOMPLETE,
        error_code="WORKER_INTERRUPTED",
        error_message="Se continuará desde la última página confirmada.",
    )


def _source_key(source):
    return (
        source["origin"], source["asset_id"], source["asset_cpe_id"],
        source.get("installation_id"),
    )


def _store_cve_discovery_page(run_id, query_index, page):
    """Commit a whole page and its offset atomically, or roll it all back."""
    # Validate everything before touching storage: malformed page != zero CVEs.
    checked = [validated_cve_record(row) for row in page["records"]]
    identifiers = [identifier for identifier, _ in checked]
    if len(identifiers) != len(set(identifiers)):
        raise CveDiscoveryError(
            "DUPLICATE_PAGE", "NVD repitió un CVE dentro de la página."
        )
    with transaction.atomic():
        run = CveDiscoveryRun.objects.select_for_update().get(pk=run_id)
        if run.status != CveDiscoveryRun.Status.RUNNING:
            raise CveDiscoveryError("INVALID_STATE", "Búsqueda CVE no ejecutable.")
        _assert_current(run)
        queries = run.queries
        entry = queries[query_index]
        if entry["status"] == "COMPLETED":
            raise CveDiscoveryError("INVALID_STATE", "El CPE ya fue consultado.")
        if entry["next_start_index"] != page["start_index"]:
            raise CveDiscoveryError("CHECKPOINT_CHANGED", "El checkpoint CVE cambió.")
        if (entry["expected_total"] is not None
                and entry["expected_total"] != page["total_results"]):
            raise CveDiscoveryError(
                "NVD_TOTAL_CHANGED", "NVD cambió el total entre páginas."
            )
        seen = set(entry.get("seen_cve_ids", []))
        if not seen.isdisjoint(identifiers):
            raise CveDiscoveryError(
                "DUPLICATE_PAGE", "NVD repitió un CVE entre páginas."
            )

        by_hardware = defaultdict(list)
        for source in entry["sources"]:
            by_hardware[source["hardware_id"]].append(source)
        now = timezone.now()
        for record in page["records"]:
            cve, _ = store_official_cve_record(record)
            for hardware_id, sources in by_hardware.items():
                finding, created = (
                    AssetCveFinding.objects.select_for_update().get_or_create(
                        hardware_id=hardware_id, cve=cve,
                        defaults={
                            "first_discovery_run": run,
                            "last_discovery_run": run,
                            "sources": sources,
                            "evidence_fingerprint": (
                                entry["hardware_fingerprints"][str(hardware_id)]
                            ),
                        },
                    )
                )
                if created:
                    ensure_system_cve_assessment(cve.cve_id, hardware_id)
                    continue
                previous = (
                    finding.sources
                    if finding.last_discovery_run_id == run.pk else []
                )
                combined = {_source_key(item): item for item in previous}
                for source in sources:
                    combined[_source_key(source)] = source
                finding.sources = list(combined.values())
                finding.last_discovery_run = run
                finding.last_discovered_at = now
                finding.evidence_fingerprint = (
                    entry["hardware_fingerprints"][str(hardware_id)]
                )
                finding.save(update_fields=[
                    "sources", "last_discovery_run", "last_discovered_at",
                    "evidence_fingerprint",
                ])
                ensure_system_cve_assessment(cve.cve_id, hardware_id)

        entry["expected_total"] = page["total_results"]
        entry["next_start_index"] = page["next_start_index"]
        entry["retrieved_count"] += len(identifiers)
        entry["pages_fetched"] += 1
        entry["seen_cve_ids"].extend(identifiers)
        if page["complete"]:
            if len(entry["seen_cve_ids"]) != page["total_results"]:
                raise CveDiscoveryError(
                    "INCOMPLETE_RESULTS", "NVD no devolvió el conjunto completo."
                )
            entry["status"] = "COMPLETED"
        else:
            entry["status"] = "RUNNING"
        entry["error_message"] = ""
        run.queries = queries
        run.checkpoint_at = now
        run.save(update_fields=["queries", "checkpoint_at"])
    return run


def _fail_run(run_id, error):
    run = CveDiscoveryRun.objects.get(pk=run_id)
    if isinstance(error, CveDiscoveryError):
        code = error.code
    elif isinstance(error, CveResponseError):
        code = "INVALID_CVE"
    else:
        code = "FETCH_FAILED"
    run.status = CveDiscoveryRun.Status.FAILED
    run.error_code = code
    run.error_message = (str(error) or type(error).__name__)[:1000]
    run.finished_at = timezone.now()
    run.save(update_fields=[
        "status", "error_code", "error_message", "finished_at",
    ])
    return run


def execute_cve_discovery_run(run, pacer, *, fetcher=fetch_cves_by_cpe,
                              after_page=None):
    """Process a complete query plan using the singleton NVD pacer.

    Known data/network problems stop as FAILED, preserving earlier checkpoints.
    A process crash leaves RUNNING for recovery on the next worker startup.
    """
    if run.status not in (
        CveDiscoveryRun.Status.QUEUED, CveDiscoveryRun.Status.INCOMPLETE,
    ):
        return run
    try:
        _assert_current(run)
        run.status = CveDiscoveryRun.Status.RUNNING
        run.started_at = run.started_at or timezone.now()
        run.finished_at = None
        run.error_code = ""
        run.error_message = ""
        run.save(update_fields=[
            "status", "started_at", "finished_at", "error_code", "error_message",
        ])
        for query_index in range(len(run.queries)):
            run.refresh_from_db()
            if run.queries[query_index]["status"] == "COMPLETED":
                continue
            while True:
                _assert_current(run)
                entry = run.queries[query_index]
                offset = entry["next_start_index"]
                payload = fetcher(
                    entry["cpe_name"], offset, pacer,
                    results_per_page=entry["page_size"],
                )
                page = validated_cve_page(payload, offset)
                run = _store_cve_discovery_page(run.pk, query_index, page)
                if after_page is not None:
                    after_page(run)
                if page["complete"]:
                    break
        run.refresh_from_db()
        if not all(q["status"] == "COMPLETED" for q in run.queries):
            raise CveDiscoveryError(
                "INCOMPLETE_RESULTS", "Quedan consultas CVE sin completar."
            )
        run.status = CveDiscoveryRun.Status.COMPLETED
        run.finished_at = timezone.now()
        run.save(update_fields=["status", "finished_at"])
    except (NvdError, CveResponseError, CveDiscoveryError, ValueError) as error:
        run = _fail_run(run.pk, error)
    return run
