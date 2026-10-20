"""Merge official NVD CPE records with explainable inventory correspondence."""
import re
from .identity import normalized, cpu_spelling


def _cpe_part(cpe_name, position):
    parts = cpe_name.split(":")
    return parts[position] if len(parts) > position else ""


def classify(candidate, identity):
    cpe_name = candidate["cpe_name"]
    if _cpe_part(cpe_name, 2) != "h":
        return "POSSIBLE_INCOMPATIBILITY", "Este CPE no identifica hardware (tipo h)."
    vendor = normalized(_cpe_part(cpe_name, 3))
    product = normalized(_cpe_part(cpe_name, 4))
    wanted_vendor = normalized(identity.get("manufacturer"))
    wanted_model = normalized(identity.get("model"))
    wanted_cpu = cpu_spelling(identity.get("cpu_model"))
    if vendor and wanted_vendor and vendor != wanted_vendor:
        return "POSSIBLE_INCOMPATIBILITY", "El fabricante del CPE no coincide con el inventario."
    if wanted_model and wanted_model not in product:
        return "POSSIBLE_INCOMPATIBILITY", "El producto CPE no corresponde claramente a la familia."
    if wanted_cpu:
        if wanted_cpu in product:
            return "SPECIFIC", "Coinciden fabricante, familia y CPU."
        # A different CPU explicitly named in the same family is a contradiction.
        name_cpu = re.search(r"cpu[_-]?([0-9]{3,5}[a-z]?)", _cpe_part(cpe_name, 4))
        if name_cpu:
            return "POSSIBLE_INCOMPATIBILITY", "El CPE especifica una CPU distinta."
        return "FAMILY", "Coincide la familia; el CPE no especifica la CPU inventariada."
    if _cpe_part(cpe_name, 5) not in ("", "-", "*"):
        return "NEEDS_INFO", "El CPE indica una versión no registrada en el inventario."
    return "FAMILY", "Coinciden fabricante y familia; se desconoce el modelo de CPU."


PRIORITY = {
    "SPECIFIC": 0, "FAMILY": 1, "NEEDS_INFO": 2, "POSSIBLE_INCOMPATIBILITY": 3,
}


def normalize_candidate(record, identity, strategy):
    cpe = record.get("cpe") or {}
    name_id = cpe.get("cpeNameId")
    name = cpe.get("cpeName")
    if not isinstance(name_id, str) or not isinstance(name, str):
        return None
    # keywordSearch can return hardware, firmware/OS and applications.
    # Phase 1 inventories hardware only; keep other CPE types out of results.
    if _cpe_part(name, 2) != "h":
        return None
    titles = cpe.get("titles") or []
    title = next((t.get("title") for t in titles if t.get("lang") == "en" and t.get("title")), None)
    title = title or next((t.get("title") for t in titles if t.get("title")), name)
    item = {
        "cpe_name_id": name_id,
        "cpe_name": name,
        "title": title,
        "deprecated": bool(cpe.get("deprecated", False)),
        "cpe_type": _cpe_part(name, 2),
        "version": _cpe_part(name, 5),
        "nvd_created_at": cpe.get("created"),
        "nvd_modified_at": cpe.get("lastModified"),
        "methods": [strategy],
    }
    item["match_level"], item["match_reason"] = classify(item, identity)
    return item


def merge_candidates(results):
    merged = {}
    for entry in results:
        key = entry["cpe_name_id"]
        if key not in merged:
            merged[key] = entry
        else:
            merged[key]["methods"] = sorted(set(merged[key]["methods"] + entry["methods"]))
    return sorted(
        merged.values(),
        key=lambda v: (PRIORITY.get(v["match_level"], 99), v["deprecated"], v["title"].lower(), v["cpe_name"]),
    )



def hardware_candidates(candidates):
    """Read-time filter for search runs created before hardware-only filtering.

    The original JSON is retained as historical evidence. The UI and subsequent
    validation must never suggest firmware/OS CPEs for a hardware-only search.
    """
    return [
        item for item in (candidates or [])
        if isinstance(item, dict) and isinstance(item.get("cpe_name"), str)
        and _cpe_part(item["cpe_name"], 2) == "h"
    ]
