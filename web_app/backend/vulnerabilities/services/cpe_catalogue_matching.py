"""Read-only classification of persisted NVD CPE catalogue snapshots.

Phase 2 separates *retrieval* (CpeQueryProduct.nvd_record, immutable NVD
evidence) from *relevance to one inventoried hardware asset* (computed view).
No AssetCpe, CpeSearchRun or CpeQueryProduct is created or modified here.
"""
from collections import Counter

from .candidate_matching import (
    is_manufacturer_related, is_pertinent, matches_vendor, normalize_candidate,
)
from .nvd_references import safe_references
from vulnerabilities.models import CpeQueryProduct, CpeQuerySnapshot

RESULT_ALL = "ALL"
RESULT_CANDIDATES = "CANDIDATES"
RESULT_EXCLUDED = "EXCLUDED"
ALLOWED_VIEWS = (RESULT_ALL, RESULT_CANDIDATES, RESULT_EXCLUDED)

EXCLUDED_NON_HARDWARE = "NON_HARDWARE"
EXCLUDED_OTHER_VENDOR = "OTHER_VENDOR"
EXCLUDED_OTHER_PRODUCT = "OTHER_PRODUCT"
CANDIDATE = "CANDIDATE"

MAX_PREVIEW_LIMIT = 100
DEFAULT_PREVIEW_LIMIT = 25
ITERATOR_BATCH_SIZE = 500


def _require_identity(identity):
    if (not isinstance(identity, dict) or identity.get("asset_type") != "HARDWARE"
            or not str(identity.get("manufacturer") or "").strip()
            or not str(identity.get("model") or "").strip()):
        raise ValueError("Se necesita un activo de hardware con fabricante y modelo.")


def _snapshot_record(evidence):
    """A snapshot's NVD JSON, not possibly newer Cpe catalogue metadata."""
    data = evidence.nvd_record
    cpe = data.get("cpe") if isinstance(data, dict) else None
    if not isinstance(cpe, dict):
        raise ValueError("La evidencia original de este producto NVD no es válida.")
    name = cpe.get("cpeName")
    if not isinstance(name, str):
        raise ValueError("La evidencia no contiene cpeName.")
    return cpe, name


def classify_catalogue_record(evidence, identity):
    """Classify one stored record without discarding its NVD evidence.

    CANDIDATE means a suggested *reviewable* match. It is NOT an AssetCpe
    confirmation. Non-hardware and unrelated products remain accessible
    through the ALL and EXCLUDED catalogue views.
    """
    _require_identity(identity)
    cpe, cpe_name = _snapshot_record(evidence)
    parts = cpe_name.split(":")
    kind = parts[2] if len(parts) > 2 else ""
    vendor = parts[3] if len(parts) > 3 else ""
    candidate = normalize_candidate(evidence.nvd_record, identity, evidence.snapshot.cache.strategy)
    if kind != "h":
        classification = EXCLUDED_NON_HARDWARE
        match_reason = "El registro CPE no corresponde al tipo hardware (h)."
    elif not matches_vendor(vendor, identity):
        classification = EXCLUDED_OTHER_VENDOR
        match_reason = "El fabricante del registro NVD no coincide con el activo."
    elif candidate is None or not is_manufacturer_related(candidate, identity):
        classification = EXCLUDED_OTHER_PRODUCT
        match_reason = (candidate.get("match_reason")
                        if candidate else "No existen datos suficientes para clasificar el producto.")
    else:
        classification = CANDIDATE
        match_reason = candidate["match_reason"]

    names = cpe.get("titles")
    names = names if isinstance(names, list) else []
    title = next((t.get("title") for t in names
                  if isinstance(t, dict) and t.get("lang") == "en"
                  and isinstance(t.get("title"), str) and t.get("title")), None)
    title = title or next((t.get("title") for t in names
                           if isinstance(t, dict) and isinstance(t.get("title"), str)
                           and t.get("title")), cpe_name)

    return {
        "evidence_id": evidence.pk,
        "snapshot_id": evidence.snapshot_id,
        "cpe_name_id": str(cpe.get("cpeNameId", "")),
        "cpe_name": cpe_name,
        "cpe_type": kind,
        "title": title[:400],
        "deprecated": bool(cpe.get("deprecated", False)),
        "nvd_references": safe_references(cpe.get("refs")),
        "classification": classification,
        "is_candidate": classification == CANDIDATE,
        "is_pertinent": bool(
            classification == CANDIDATE and is_pertinent(candidate, identity)
        ),
        "match_level": candidate["match_level"] if candidate else None,
        "match_reason": match_reason,
        "source_strategy": evidence.snapshot.cache.strategy,
    }


def _rows(snapshot, *, after_id=0, chunk_size=ITERATOR_BATCH_SIZE):
    return (CpeQueryProduct.objects.filter(snapshot_id=snapshot.pk, pk__gt=after_id)
            .select_related("snapshot__cache")
            .order_by("pk").iterator(chunk_size=chunk_size))


def _validate_snapshot(snapshot):
    if not isinstance(snapshot, CpeQuerySnapshot) or snapshot.pk is None:
        raise ValueError("Selecciona una recuperación de catálogo persistida.")
    return snapshot


def _state(snapshot):
    """Unfinished or failed snapshots can be explored, never certified complete."""
    return {
        "snapshot_id": snapshot.pk,
        "snapshot_status": snapshot.status,
        "coverage_complete": snapshot.status == CpeQuerySnapshot.Status.COMPLETED,
        "expected_total": snapshot.expected_total,
        "stored_products": snapshot.unique_products_count,
        "next_start_index": snapshot.next_start_index,
        "error_code": snapshot.error_code,
    }


def summarize_catalogue(snapshot, identity):
    """Scan a snapshot with bounded memory; count suggestions and exclusions."""
    _validate_snapshot(snapshot)
    _require_identity(identity)
    counts = Counter()
    levels = Counter()
    for evidence in _rows(snapshot):
        item = classify_catalogue_record(evidence, identity)
        counts[item["classification"]] += 1
        if item["is_candidate"]:
            levels[item["match_level"]] += 1
            if item["is_pertinent"]:
                counts["PERTINENT"] += 1
    return {
        **_state(snapshot),
        "examined": sum(counts[key] for key in (
            CANDIDATE, EXCLUDED_NON_HARDWARE, EXCLUDED_OTHER_VENDOR,
            EXCLUDED_OTHER_PRODUCT,
        )),
        "candidate_count": counts[CANDIDATE],
        "excluded_count": sum(counts[key] for key in (
            EXCLUDED_NON_HARDWARE, EXCLUDED_OTHER_VENDOR, EXCLUDED_OTHER_PRODUCT,
        )),
        "pertinent_count": counts["PERTINENT"],
        "classification_counts": {
            key: counts[key] for key in (
                CANDIDATE, EXCLUDED_NON_HARDWARE, EXCLUDED_OTHER_VENDOR,
                EXCLUDED_OTHER_PRODUCT,
            )
        },
        "match_level_counts": {
            key: levels[key] for key in (
                "SPECIFIC", "FAMILY", "RELATED", "NEEDS_INFO",
            )
        },
    }


def browse_catalogue(snapshot, identity, *, view=RESULT_ALL, after_id=0,
                     limit=DEFAULT_PREVIEW_LIMIT, search="", cpe_type="ALL",
                     deprecated="ALL"):
    """Cursor-based, memory-bounded read of ALL/CANDIDATES/EXCLUDED.

    'next_after' is the LAST returned evidence ID, not the first omitted row:
    this avoids losing records when a filter skips intervening catalogue rows.
    A missing next cursor means the filtered result is exhausted (within the
    retrieved snapshot), not that NVD is complete.
    """
    _validate_snapshot(snapshot)
    _require_identity(identity)
    if view not in ALLOWED_VIEWS:
        raise ValueError("Vista no permitida; usa ALL, CANDIDATES o EXCLUDED.")
    if type(limit) is not int or not 1 <= limit <= MAX_PREVIEW_LIMIT:
        raise ValueError("El límite debe ser un entero entre 1 y 100.")
    if type(after_id) is not int or after_id < 0:
        raise ValueError("El cursor debe ser un entero no negativo.")
    if not isinstance(search, str) or len(search) > 120:
        raise ValueError("El filtro de texto no puede superar 120 caracteres.")
    if cpe_type not in ("ALL", "h", "o", "a"):
        raise ValueError("Tipo CPE inválido.")
    if deprecated not in ("ALL", "YES", "NO"):
        raise ValueError("Filtro de obsolescencia inválido.")
    query = search.strip().casefold()
    items = []
    has_more = False
    for evidence in _rows(snapshot, after_id=after_id):
        item = classify_catalogue_record(evidence, identity)
        if view == RESULT_CANDIDATES and not item["is_candidate"]:
            continue
        if view == RESULT_EXCLUDED and item["is_candidate"]:
            continue
        if cpe_type != "ALL" and item["cpe_type"] != cpe_type:
            continue
        if deprecated == "YES" and not item["deprecated"]:
            continue
        if deprecated == "NO" and item["deprecated"]:
            continue
        if query and not any(query in str(item.get(key) or "").casefold()
                             for key in ("title", "cpe_name", "cpe_name_id")):
            continue
        if len(items) == limit:
            has_more = True
            break
        items.append(item)
    return {
        **_state(snapshot),
        "view": view,
        "limit": limit,
        "filters": {"search": search.strip(), "cpe_type": cpe_type, "deprecated": deprecated},
        "items": items,
        "next_after": items[-1]["evidence_id"] if items and has_more else None,
    }
