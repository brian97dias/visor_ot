"""Phase 1: persist the original NVD CVE record, no asset applicability logic."""
from datetime import timezone as utc_timezone
from decimal import Decimal, InvalidOperation

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from vulnerabilities.models import Cve
from .nvd_client import NvdError
from .nvd_cve_client import EXPERIMENTAL_CVE_ID, fetch_cve

FIRMWARE_CRITERION = (
    "cpe:2.3:o:phoenixcontact:il_pn_bk-pac_firmware:*:*:*:*:*:*:*:*"
)
HARDWARE_CRITERION = (
    "cpe:2.3:h:phoenixcontact:il_pn_bk-pac:-:*:*:*:*:*:*:*"
)


class CveResponseError(ValueError):
    """Malformed, wrong or incomplete NVD response; never certify its data."""


def _criteria_of(nodes):
    """Iterate native cpeMatch entries without flattening the stored tree."""
    for node in nodes:
        if not isinstance(node, dict):
            continue
        yield from (entry for entry in node.get("cpeMatch", [])
                    if isinstance(entry, dict))
        children = node.get("nodes", [])
        if isinstance(children, list):
            yield from _criteria_of(children)


def find_experimental_configuration(configurations):
    """Find the AND scenario by actual criteria, NOT a mutable NVD array index.

    An NVD 'configuration 12' label is an ordinal display position. Return the
    observed ordinal for the stored snapshot; never infer current numbering.
    """
    if not isinstance(configurations, list):
        raise CveResponseError("NVD no devolvió configuraciones válidas.")
    matches = []
    for position, config in enumerate(configurations, start=1):
        if not isinstance(config, dict) or config.get("operator") != "AND":
            continue
        if config.get("negate") is True:
            continue
        nodes = config.get("nodes", [])
        if not isinstance(nodes, list) or any(
            isinstance(node, dict) and node.get("negate") is True for node in nodes
        ):
            continue
        criteria = list(_criteria_of(nodes))
        wanted = {
            (FIRMWARE_CRITERION, True),
            (HARDWARE_CRITERION, False),
        }
        actual = {
            (item.get("criteria"), item.get("vulnerable"))
            for item in criteria
            if isinstance(item.get("criteria"), str)
            and type(item.get("vulnerable")) is bool
        }
        if len(criteria) == 2 and actual == wanted:
            matches.append({"index": position - 1, "position": position,
                            "configuration": config,
                            "firmware": next(x for x in criteria
                                             if x.get("criteria") == FIRMWARE_CRITERION),
                            "hardware": next(x for x in criteria
                                             if x.get("criteria") == HARDWARE_CRITERION)})
    if len(matches) != 1:
        raise CveResponseError(
            "No fue posible identificar unívocamente la configuración AND "
            "del hardware IL PN BK-PAC y su firmware."
        )
    return matches[0]


def _timestamp(value, name):
    parsed = parse_datetime(value) if isinstance(value, str) else None
    if parsed is None:
        raise CveResponseError(f"Fecha NVD inválida: {name}.")
    if timezone.is_naive(parsed):
        parsed = parsed.replace(tzinfo=utc_timezone.utc)
    return parsed


def _cvss_summary(metrics):
    """Select a display metric; preserve ALL versions and sources in JSON."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key, [])
        if not isinstance(values, list):
            continue
        rows = [v for v in values if isinstance(v, dict)]
        rows.sort(key=lambda v: v.get("type") != "Primary")
        for item in rows:
            raw = item.get("cvssData")
            if not isinstance(raw, dict):
                continue
            try:
                score = Decimal(str(raw.get("baseScore")))
            except (InvalidOperation, TypeError, ValueError):
                continue
            if not score.is_finite() or not 0 <= score <= 10:
                continue
            severity = raw.get("baseSeverity") or item.get("baseSeverity") or ""
            if not isinstance(severity, str):
                severity = ""
            return severity[:20], score.quantize(Decimal("0.1"))
    return "", None


def validated_cve_payload(payload):
    """Validate the NVD envelope before any of its content can be persisted."""
    if not isinstance(payload, dict):
        raise CveResponseError("Respuesta NVD CVE inválida.")
    records = payload.get("vulnerabilities")
    if (payload.get("totalResults") != 1 or not isinstance(records, list)
            or len(records) != 1 or not isinstance(records[0], dict)
            or not isinstance(records[0].get("cve"), dict)):
        raise CveResponseError("NVD no devolvió exactamente un CVE.")
    record = records[0]["cve"]
    if record.get("id") != EXPERIMENTAL_CVE_ID:
        raise CveResponseError("El identificador CVE recuperado no corresponde a la solicitud.")
    descriptions = record.get("descriptions")
    metrics = record.get("metrics", {})
    configs = record.get("configurations")
    references = record.get("references", [])
    if (not isinstance(descriptions, list) or not isinstance(metrics, dict)
            or not isinstance(configs, list) or not isinstance(references, list)):
        raise CveResponseError("NVD devolvió campos incompletos o inválidos.")
    # Guardar el árbol NVD completo, sin generar CPE ni reinterpretar los rangos.
    target = find_experimental_configuration(configs)
    title = next(
        (d.get("value") for d in descriptions
         if isinstance(d, dict) and d.get("lang") == "en"
         and isinstance(d.get("value"), str)), None
    )
    if title is None:
        title = next(
            (d.get("value") for d in descriptions
             if isinstance(d, dict) and isinstance(d.get("value"), str)), ""
        )
    severity, score = _cvss_summary(metrics)
    return {
        "description": title,
        "descriptions": descriptions,
        "published": _timestamp(record.get("published"), "published"),
        "last_modified": _timestamp(record.get("lastModified"), "lastModified"),
        "severity": severity,
        "base_score": score,
        "metrics": metrics,
        "configurations": configs,
        "references": references,
    }, target


@transaction.atomic
def enqueue_experimental_cve(*, refresh=False):
    """Explicit, idempotent CLI enqueue: no HTTP, no asset updates."""
    cve, created = Cve.objects.select_for_update().get_or_create(
        cve_id=EXPERIMENTAL_CVE_ID,
    )
    if not created:
        if cve.fetch_status in (Cve.FetchStatus.QUEUED, Cve.FetchStatus.RUNNING):
            return cve, True
        if cve.fetch_status == Cve.FetchStatus.COMPLETED and not refresh:
            return cve, True
        cve.fetch_status = Cve.FetchStatus.QUEUED
        cve.fetch_error = ""
        cve.queued_at = timezone.now()
        cve.started_at = None
        cve.finished_at = None
        cve.save(update_fields=[
            "fetch_status", "fetch_error", "queued_at", "started_at", "finished_at"
        ])
    return cve, False


def execute_cve_fetch(cve, pacer, fetcher=fetch_cve):
    """Only the existing locked worker calls this function with its pacer."""
    if cve.fetch_status != Cve.FetchStatus.QUEUED:
        return cve
    if cve.cve_id != EXPERIMENTAL_CVE_ID:
        raise ValueError("CVE no permitido para esta fase.")
    cve.fetch_status = Cve.FetchStatus.RUNNING
    cve.started_at = timezone.now()
    cve.fetch_error = ""
    cve.save(update_fields=["fetch_status", "started_at", "fetch_error"])
    try:
        response = fetcher(cve.cve_id, pacer)
        fields, _ = validated_cve_payload(response)
    except (NvdError, CveResponseError, TimeoutError, ConnectionError,
            OSError, ValueError, TypeError) as error:
        # Any old completed snapshot remains on disk but is NOT marked fresh.
        cve.fetch_status = Cve.FetchStatus.FAILED
        cve.fetch_error = str(error)[:1000]
        cve.finished_at = timezone.now()
        cve.save(update_fields=["fetch_status", "fetch_error", "finished_at"])
        return cve
    with transaction.atomic():
        # Atomic swap of ALL CVE fields; partial records are never "COMPLETED".
        cve = Cve.objects.select_for_update().get(pk=cve.pk)
        for name, value in fields.items():
            setattr(cve, name, value)
        cve.retrieved_at = timezone.now()
        cve.fetch_status = Cve.FetchStatus.COMPLETED
        cve.fetch_error = ""
        cve.finished_at = timezone.now()
        cve.save(update_fields=[
            *fields.keys(), "retrieved_at", "fetch_status", "fetch_error",
            "finished_at",
        ])
    return cve
