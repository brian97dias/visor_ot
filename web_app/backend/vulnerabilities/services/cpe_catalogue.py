"""Reusable, page-checkpointed NVD CPE catalogue recovery (phase 1).

The shared catalogue is independent of any Asset and of human CPE decisions.
Only run this executor under the existing PostgreSQL NVD worker advisory lock.
"""
import hashlib
import json
import re
from datetime import timedelta, timezone as datetime_timezone
from uuid import UUID

from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from vulnerabilities.models import (
    Cpe, CpeQueryCache, CpeQueryProduct, CpeQuerySnapshot,
)
from .nvd_client import NvdError, fetch_page
from .nvd_references import safe_references

CACHE_TTL = timedelta(days=7)
CATALOGUE_PAGE_SIZE = 500
MAX_CATALOGUE_PAGE_SIZE = 1000
# Three deferred attempts after the initial network failure.
# Exponential backoff: 30, 60 and 120 seconds; survives restarts.
MAX_AUTOMATIC_RETRIES = 3
AUTOMATIC_RETRY_BASE_SECONDS = 30


def _retryable_network_failure(exc):
    """Do not retry malformed pages, invalid identity or HTTP 4xx.

    fetch_page already retries each HTTP request twice; this is a separate
    bounded worker-level recovery budget for transient failures only.
    """
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    if not isinstance(exc, NvdError):
        return False
    message = str(exc)
    return (
        message.startswith("No fue posible consultar NVD:")
        or message.startswith("NVD no respondió tras los reintentos")
        or any(message.startswith(f"NVD devolvió HTTP {code}.")
               for code in (429, 500, 502, 503, 504))
    )


def snapshot_retry_scheduled(snapshot):
    return (
        snapshot.status == CpeQuerySnapshot.Status.FAILED
        and snapshot.error_code == "FETCH_FAILED"
        and snapshot.retry_after is not None
        and 0 < snapshot.automatic_retry_count <= MAX_AUTOMATIC_RETRIES
    )


_CPE_PREFIX = re.compile(
    r"^cpe:2\.3:[hao]:[a-z0-9_.-]{2,100}"
    r"(?::[a-z0-9_.\-*]{1,120})?"
    r"(?::[a-z0-9_.\-*\\()+]{1,120})?$"
)
_KEYWORD = re.compile(r"^[\w\s./-]{3,120}$", re.UNICODE)


class CatalogueResponseError(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def canonical_query(strategy, parameter):
    """Normalize query identity; never include offset or transient page size."""
    if strategy not in ("keywordSearch", "cpeMatchString"):
        raise ValueError("Estrategia no admitida.")
    if not isinstance(parameter, str) or any(
        ord(char) < 32 or ord(char) == 127 for char in parameter
    ):
        raise ValueError("La consulta contiene caracteres inválidos.")
    if strategy == "keywordSearch":
        parameter = " ".join(parameter.strip().split())
        if not _KEYWORD.fullmatch(parameter):
            raise ValueError("La búsqueda textual debe tener de 3 a 120 caracteres válidos.")
    else:
        parameter = parameter.strip().lower()
        if not _CPE_PREFIX.fullmatch(parameter):
            raise ValueError("La búsqueda CPE requiere una parte (h/o/a) y un fabricante válidos.")
    return strategy, parameter


def canonical_key(strategy, parameter):
    return hashlib.sha256(json.dumps(
        ["NVD_CPE_2.0", strategy, parameter],
        separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def enqueue_catalogue_query(strategy, parameter, *, force=False, page_size=CATALOGUE_PAGE_SIZE,
                            now=None):
    """Enqueue once per query. A fresh COMPLETE snapshot is a reusable cache hit.

    force creates a fresh version but does not start duplicate simultaneous work.
    """
    strategy, parameter = canonical_query(strategy, parameter)
    if type(page_size) is not int or not 1 <= page_size <= MAX_CATALOGUE_PAGE_SIZE:
        raise ValueError("page_size debe ser un entero entre 1 y 1000.")
    now = now or timezone.now()
    with transaction.atomic():
        cache, _ = CpeQueryCache.objects.get_or_create(
            query_key=canonical_key(strategy, parameter),
            defaults={"strategy": strategy, "parameter": parameter},
        )
        cache = CpeQueryCache.objects.select_for_update().get(pk=cache.pk)
        # A request never replaces an active retrieval, even with force=True.
        # A transiently failed snapshot with a retry deadline is still
        # active. Reuse it across assets instead of starting competing
        # downloads for the same NVD query while backoff is pending.
        active = cache.snapshots.filter(
            Q(status__in=(
                CpeQuerySnapshot.Status.QUEUED,
                CpeQuerySnapshot.Status.RUNNING,
                CpeQuerySnapshot.Status.INCOMPLETE,
            )) | Q(
                status=CpeQuerySnapshot.Status.FAILED,
                error_code="FETCH_FAILED",
                retry_after__isnull=False,
                automatic_retry_count__gte=1,
            )
        ).order_by("-pk").first()
        if active:
            return active, True
        if not force:
            latest_completed = cache.snapshots.filter(
                status=CpeQuerySnapshot.Status.COMPLETED,
                finished_at__gte=now - CACHE_TTL,
            ).order_by("-finished_at", "-pk").first()
            if latest_completed:
                return latest_completed, True
        return CpeQuerySnapshot.objects.create(
            cache=cache, page_size=page_size,
        ), False


def recover_interrupted_catalogue_snapshots():
    """Call only after obtaining the singleton PostgreSQL advisory lock."""
    return CpeQuerySnapshot.objects.filter(
        status=CpeQuerySnapshot.Status.RUNNING
    ).update(
        status=CpeQuerySnapshot.Status.INCOMPLETE,
        error_code="WORKER_INTERRUPTED",
        error_message="Worker interrumpido; se continuará desde la última página confirmada.",
    )


def retry_failed_snapshot(snapshot_id):
    """Retry transient failure from last checkpoint, without erasing evidence.

    Dataset drift cannot safely resume on the same snapshot; refresh the query.
    """
    with transaction.atomic():
        snapshot = CpeQuerySnapshot.objects.select_for_update().get(pk=snapshot_id)
        if (snapshot.status != CpeQuerySnapshot.Status.FAILED or
                snapshot.error_code not in ("FETCH_FAILED", "WORKER_INTERRUPTED")):
            raise ValueError("Esta recuperación no puede reanudarse; inicia una nueva versión.")
        snapshot.status = CpeQuerySnapshot.Status.INCOMPLETE
        snapshot.error_code = ""
        snapshot.error_message = ""
        snapshot.finished_at = None
        snapshot.retry_after = None
        snapshot.save(update_fields=[
            "status", "error_code", "error_message", "finished_at", "retry_after",
        ])
        return snapshot


def _datetime(value):
    parsed = parse_datetime(value) if isinstance(value, str) else None
    if parsed and timezone.is_naive(parsed):
        return parsed.replace(tzinfo=datetime_timezone.utc)
    return parsed


def _validated_record(row):
    if not isinstance(row, dict) or not isinstance(row.get("cpe"), dict):
        raise CatalogueResponseError("INVALID_PRODUCT", "Producto NVD sin diccionario CPE.")
    data = row["cpe"]
    try:
        cpe_id = UUID(str(data["cpeNameId"]))
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        raise CatalogueResponseError("INVALID_PRODUCT", "Producto NVD sin UUID válido.") from error
    name = data.get("cpeName")
    if (not isinstance(name, str) or not name.startswith("cpe:2.3:")
            or len(name) > 500 or len(name.split(":")) < 6):
        raise CatalogueResponseError("INVALID_PRODUCT", "CPE Name inválido en NVD.")
    titles = data.get("titles")
    titles = titles if isinstance(titles, list) else []
    title = next((t.get("title") for t in titles if isinstance(t, dict)
                  and t.get("lang") == "en" and isinstance(t.get("title"), str)
                  and t.get("title")), None)
    title = title or next((t.get("title") for t in titles if isinstance(t, dict)
                           and isinstance(t.get("title"), str) and t.get("title")), name)
    return cpe_id, {
        "cpe_name": name,
        "title": title[:400],
        "deprecated": bool(data.get("deprecated", False)),
        "nvd_created_at": _datetime(data.get("created")),
        "nvd_modified_at": _datetime(data.get("lastModified")),
        "nvd_references": safe_references(data.get("refs")),
    }


def _store_page(snapshot_id, *, start, products, total, timestamp=""):
    """One atomic unit: product updates + evidence + nextStartIndex checkpoint."""
    # Validate ALL records first: a malformed record must never certify a page.
    validated = [_validated_record(row) for row in products]
    identifiers = [identifier for identifier, _ in validated]
    if len(set(identifiers)) != len(identifiers):
        raise CatalogueResponseError("DUPLICATE_PAGE", "NVD repitió un UUID dentro de la página.")
    with transaction.atomic():
        snapshot = CpeQuerySnapshot.objects.select_for_update().get(pk=snapshot_id)
        if snapshot.status != CpeQuerySnapshot.Status.RUNNING:
            raise CatalogueResponseError("INVALID_STATE", "La recuperación ya no está en ejecución.")
        if snapshot.next_start_index != start:
            raise CatalogueResponseError("CHECKPOINT_CHANGED", "El índice de recuperación cambió.")
        if snapshot.expected_total is not None and total != snapshot.expected_total:
            raise CatalogueResponseError(
                "NVD_TOTAL_CHANGED",
                "El número total de NVD cambió entre páginas. Inicia una nueva recuperación.",
            )
        if start + len(products) > total:
            raise CatalogueResponseError(
                "INVALID_PAGE", "NVD devolvió más productos de los indicados en totalResults.",
            )
        if not products and start < total:
            raise CatalogueResponseError(
                "EMPTY_PAGE", "NVD devolvió una página vacía antes de agotar sus productos.",
            )
        # Never touch references_source_run: it refers to analyst-run provenance.
        for row, (cpe_id, values) in zip(products, validated):
            defaults = {**values}
            cpe, created = Cpe.objects.get_or_create(
                cpe_name_id=cpe_id, defaults=defaults,
            )
            if not created:
                modified = values["nvd_modified_at"]
                if (cpe.nvd_modified_at is None or (
                    modified is not None and modified >= cpe.nvd_modified_at
                )):
                    updates = ["cpe_name", "title", "deprecated", "fetched_at"]
                    for field in ("cpe_name", "title", "deprecated"):
                        setattr(cpe, field, values[field])
                    for field in ("nvd_created_at", "nvd_modified_at"):
                        if values[field] is not None:
                            setattr(cpe, field, values[field])
                            updates.append(field)
                    # Previously collected source-run references remain untouched;
                    # evidence for this retrieval is the snapshot's original JSON.
                    cpe.save(update_fields=updates)
            CpeQueryProduct.objects.get_or_create(
                snapshot=snapshot, cpe=cpe, defaults={"nvd_record": row},
            )
        snapshot.expected_total = total
        snapshot.next_start_index = start + len(products)
        snapshot.retrieved_count += len(products)
        snapshot.pages_fetched += 1
        snapshot.unique_products_count = snapshot.products.count()
        snapshot.checkpoint_at = timezone.now()
        if isinstance(timestamp, str):
            snapshot.nvd_timestamp = timestamp[:60]
        snapshot.save(update_fields=[
            "expected_total", "next_start_index", "retrieved_count",
            "pages_fetched", "unique_products_count", "checkpoint_at",
            "nvd_timestamp",
        ])
    return snapshot


def execute_catalogue_snapshot(snapshot, pacer, *, fetcher=fetch_page, after_page=None):
    """Process to completion using bounded memory; resume at confirmed offset.

    Network requests occur outside transactions. System-level interruptions
    (KeyboardInterrupt/process death) deliberately leave RUNNING for recovery.
    """
    if snapshot.status not in (
        CpeQuerySnapshot.Status.QUEUED, CpeQuerySnapshot.Status.INCOMPLETE,
    ):
        return snapshot
    snapshot.status = CpeQuerySnapshot.Status.RUNNING
    snapshot.started_at = snapshot.started_at or timezone.now()
    snapshot.error_code = ""
    snapshot.error_message = ""
    snapshot.finished_at = None
    snapshot.save(update_fields=[
        "status", "started_at", "error_code", "error_message", "finished_at",
    ])
    try:
        while True:
            start = snapshot.next_start_index
            if snapshot.expected_total is not None and start == snapshot.expected_total:
                break
            # The fetcher is injected by tests; the production one uses
            # the same singleton NVD pacer as legacy search jobs.
            payload = fetcher(
                snapshot.cache.strategy, snapshot.cache.parameter, start,
                pacer, results_per_page=snapshot.page_size,
            )
            if not isinstance(payload, dict) or not isinstance(payload.get("products"), list):
                raise CatalogueResponseError("INVALID_PAGE", "Respuesta NVD sin lista de productos.")
            total = payload.get("totalResults")
            if type(total) is not int or total < 0:
                raise CatalogueResponseError("INVALID_PAGE", "NVD no informó totalResults válido.")
            if (len(payload["products"]) > snapshot.page_size or
                    (payload.get("startIndex", start) != start)):
                raise CatalogueResponseError("INVALID_PAGE", "NVD devolvió una paginación inconsistente.")
            snapshot = _store_page(
                snapshot.pk, start=start, products=payload["products"],
                total=total, timestamp=payload.get("timestamp", ""),
            )
            if after_page is not None:
                after_page(snapshot)
        # A complete traversal cannot contain missing UUIDs or page overlaps.
        with transaction.atomic():
            snapshot = CpeQuerySnapshot.objects.select_for_update().get(pk=snapshot.pk)
            if snapshot.unique_products_count != snapshot.expected_total:
                raise CatalogueResponseError(
                    "INCOMPLETE_SET", "El conjunto tiene duplicados entre páginas o registros faltantes.",
                )
            snapshot.status = CpeQuerySnapshot.Status.COMPLETED
            snapshot.finished_at = timezone.now()
            snapshot.save(update_fields=["status", "finished_at"])
    except Exception as exc:
        # Never certify a missing product after an error. Completed pages
        # remain committed, and the retry budget survives worker restarts.
        snapshot = CpeQuerySnapshot.objects.get(pk=snapshot.pk)
        snapshot.status = CpeQuerySnapshot.Status.FAILED
        snapshot.error_code = (
            exc.code if isinstance(exc, CatalogueResponseError)
            else "FETCH_FAILED"
        )
        snapshot.error_message = str(exc)[:1000]
        snapshot.finished_at = timezone.now()
        snapshot.retry_after = None
        if (_retryable_network_failure(exc)
                and snapshot.automatic_retry_count < MAX_AUTOMATIC_RETRIES):
            delay = AUTOMATIC_RETRY_BASE_SECONDS * (
                2 ** snapshot.automatic_retry_count
            )
            snapshot.automatic_retry_count += 1
            snapshot.retry_after = timezone.now() + timedelta(seconds=delay)
        snapshot.save(update_fields=[
            "status", "error_code", "error_message", "finished_at",
            "retry_after", "automatic_retry_count",
        ])
    return snapshot
