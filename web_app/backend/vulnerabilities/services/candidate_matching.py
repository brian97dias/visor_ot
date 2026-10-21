"""Merge official NVD CPE records with explainable inventory correspondence."""
import re
from .nvd_references import safe_references, combine_references
from .identity import (
    normalized, cpu_spelling, family_term, vendor_variants, catalog_code_prefix,
    _software_product_spellings, software_version_in_branch, SOFTWARE_CPE_PARTS,
    ascii_text,
)


def _cpe_part(cpe_name, position):
    parts = cpe_name.split(":")
    return parts[position] if len(parts) > position else ""


def matches_vendor(value, identity):
    """Match only enumerated CPE vendor aliases, not arbitrary similar brands."""
    return normalized(value) in {
        normalized(v) for v in vendor_variants(identity.get("manufacturer"))
    }


def shares_catalog_code(product, identity):
    """A shared industrial prefix is related only; it proves no equivalence."""
    code = catalog_code_prefix(identity.get("model"))
    return bool(code and re.match(r"^" + re.escape(code) + r"(?=[_-]|$)", product.lower()))


def _technical_model_designation(identity):
    """Remove a redundant verified vendor prefix from a numeric model only.

    AXIS 206 -> 206, but retain the inventoried name, identity fingerprint
    and non-numeric model names such as SIMATIC S7-1200 unchanged.
    """
    raw = str(identity.get("model") or "").strip()
    prefixed = re.fullmatch(r"([a-z][a-z0-9_-]*)[ _-]+([0-9]{3,6})", raw, re.I)
    if (prefixed and normalized(prefixed.group(1)) in {
            normalized(alias) for alias in vendor_variants(identity.get("manufacturer"))}):
        return prefixed.group(2)
    return raw


def _product_without_vendor_prefix(product, identity):
    """Compare CPE 207w and axis_207_network_camera consistently."""
    aliases = sorted(vendor_variants(identity.get("manufacturer")), key=len, reverse=True)
    for alias in aliases:
        for sep in ("_", "-"):
            if product.startswith(alias + sep):
                return product[len(alias) + 1:]
    return product


def _exploratory_proximity(candidate, identity):
    """Infer weak correspondence from shared model series, never from vendor alone.

    All comparisons run against an already fetched NVD record. No prefix
    variations trigger extra NVD requests or certify a hardware identity.
    """
    model = _technical_model_designation(identity).strip().lower()
    product = _product_without_vendor_prefix(
        _cpe_part(candidate.get("cpe_name", ""), 4).lower(), identity
    )

    # Numeric designation: compare nearby products within the SAME decade.
    # AXIS 206 -> 207w and 200; AXIS 206 -> 2060 is not a nearby model.
    if re.fullmatch(r"[0-9]{3,6}", model):
        other = re.fullmatch(
            r"([0-9]{3,6})(?:[a-z](?:[_-][a-z0-9_-]+)?|[_-][a-z0-9_-]+)?",
            product,
        )
        if other:
            number = other.group(1)
            distance = abs(int(model) - int(number))
            if (len(model) == len(number) and model[:-1] == number[:-1]
                    and 0 < distance <= 9):
                return distance, (
                    f"Mismo fabricante y prefijo numérico {model[:-1]}; "
                    f"designaciones {model} y {number} diferentes. "
                    "Solo correspondencia exploratoria."
                )
        return None

    # Lettered model series: CX 1010-0012 -> CX1010, CX1020, CX9020.
    # EAGLE 20 -> eagle_30. The shared lettered series is evidence of
    # proximity, not technical equivalence; numeric differences can be large.
    wanted = re.fullmatch(
        r"([a-z]{2,12})[ _-]*([0-9]{2,6})([a-z]?)(?:[ _/-]+[a-z0-9_.-]+)?",
        model,
    )
    other = re.fullmatch(
        r"([a-z]{2,12})[_-]*([0-9]{2,6})([a-z]?)"
        r"(?:[_-][a-z0-9_.-]+)?",
        product,
    )
    if wanted and other and wanted.group(1) == other.group(1):
        own_number, other_number = wanted.group(2), other.group(2)
        if len(own_number) != len(other_number):
            return None
        common = len(re.match(
            r"^" + re.escape(own_number[:1]), other_number
        ).group(0)) if own_number[0] == other_number[0] else 0
        for a, b in zip(own_number[common:], other_number[common:]):
            if a != b:
                break
            common += 1
        # A shared series is weak evidence. Prefer a matching numeric stem
        # and matching revision, not mere vendor-level co-occurrence.
        distance = abs(int(own_number) - int(other_number))
        score = (
            (len(own_number) - common) * 100000
            + min(distance, 99999)
            + (0 if wanted.group(3) == other.group(3) else 10000)
        )
        return score, (
            f"Mismo fabricante y serie {wanted.group(1).upper()}; "
            f"referencias {wanted.group(2) + wanted.group(3).upper()} "
            f"y {other.group(2) + other.group(3).upper()} distintas. "
            "La similitud no demuestra compatibilidad técnica."
        )
    # A model designation may appear as an INNER token of a compound NVD
    # product: RX1100-F-RM-24P-HIP vs ruggedcom_rox_rx1400. Both code
    # lengths and series must match, and the token must be delimited.
    # This never establishes equivalence or triggers extra NVD queries.
    if wanted:
        series, own_number = wanted.group(1), wanted.group(2)
        for token in re.split(r"[_-]+", product)[1:]:
            embedded = re.fullmatch(r"([a-z]{2,12})([0-9]{2,6})([a-z]?)", token)
            if (not embedded or embedded.group(1) != series
                    or len(embedded.group(2)) != len(own_number)):
                continue
            other_number = embedded.group(2)
            distance = abs(int(own_number) - int(other_number))
            return 200000 + min(distance, 99999), (
                f"Mismo fabricante y componente interno de serie "
                f"{series.upper()}: códigos {own_number} y {other_number}. "
                "El resto del nombre de producto y la configuración "
                "requieren verificación. Correspondencia débil; "
                "no demuestra equivalencia ni compatibilidad técnica."
            )

    # Last-resort short series prefix. A model with multiple meaningful
    # segments (FL IL 24 BK PAC) may share only FL with other vendor products.
    # Never infer compatibility; keep boundary checks to avoid matching
    # unrelated names like FLUFFY or FL2.
    parts = re.split(r"[ _-]+", model)
    if (len(parts) >= 3 and re.fullmatch(r"[a-z]{2,3}", parts[0])
            and parts[0] not in {
                normalized(v) for v in vendor_variants(identity.get("manufacturer"))
            }):
        prefix = parts[0]
        candidate_parts = re.split(r"[_-]+", product)
        if candidate_parts and candidate_parts[0] == prefix:
            matched = 0
            for expected, actual in zip(parts, candidate_parts):
                if expected != actual:
                    break
                matched += 1
            # Keep this class below the existing numerical/series signals.
            # Greater shared prefix wins; ties rank by current status/name.
            distance = 1000000 - min(matched, len(parts)) * 100000
            common = " ".join(part.upper() for part in parts[:matched])
            return distance, (
                f"Mismo fabricante y prefijo de producto «{common}». "
                "Los demás componentes del modelo no están verificados. "
                "Afinidad exploratoria mínima: no acredita compatibilidad técnica."
            )
    return None


def classify_alternative_vendor(candidate, identity):
    """Recognize a brand/model under another NVD vendor, as evidence ONLY.

    The product designation must contain the complete inventoried model,
    bounded by alphanumeric word boundaries; matching a brand alone is
    insufficient. No vendor association or AssetCpe is created here.
    """
    name = candidate.get("cpe_name", "")
    if _cpe_part(name, 2) != "h":
        return None
    nvd_vendor = _cpe_part(name, 3)
    if not nvd_vendor or matches_vendor(nvd_vendor, identity):
        return None

    def phrase_pattern(value):
        from .identity import ascii_text
        parts = re.findall(r"[a-z]+|[0-9]+", ascii_text(value).lower())
        if not parts:
            return None
        # Allow CPE underscores, hyphens and spaces within a compound model
        # (EAGLE20 vs eagle_20), but never EAGLE20 vs EAGLE200.
        return re.compile(
            r"(?<![a-z0-9])" + r"[^a-z0-9]*".join(map(re.escape, parts))
            + r"(?![a-z0-9])"
        )

    manufacturer = str(identity.get("manufacturer") or "").strip()
    model = str(identity.get("model") or "").strip()
    if len(normalized(manufacturer)) < 4 or len(normalized(model)) < 5:
        return None
    brand_match = phrase_pattern(manufacturer)
    model_match = phrase_pattern(model)
    cpe_product = _cpe_part(name, 4).lower()
    title = str(candidate.get("title") or "").lower()
    if (not brand_match or not model_match
            or not (brand_match.search(cpe_product) or brand_match.search(title))
            or not model_match.search(cpe_product)):
        return None
    return (
        f"Posible diferencia de marca/proveedor: inventario «{manufacturer}», "
        f"fabricante NVD «{nvd_vendor}». La denominación del modelo «{model}» "
        "figura en el CPE. Verifica la placa y documentación; "
        "no constituye una identificación técnica confirmada."
    )


def _software_product_match(cpe_product, identity):
    """Compare complete CPE product tokens, never IOS with IOS XE as exact."""
    spellings = _software_product_spellings(
        identity.get("product") or "", identity.get("manufacturer") or ""
    )
    product = cpe_product.casefold()
    if product in spellings:
        return "EXACT"
    if any(product.startswith(v + sep) for v in spellings for sep in ("_", "-")):
        return "RELATED"
    return "NONE"


def classify_software(candidate, identity):
    """Explain a possible CPE software association; NEVER validate a version."""
    name = candidate["cpe_name"]
    part = SOFTWARE_CPE_PARTS.get(identity.get("software_type"))
    if _cpe_part(name, 2) != part:
        return "POSSIBLE_INCOMPATIBILITY", "La parte CPE no corresponde al tipo de software."
    if not matches_vendor(_cpe_part(name, 3), identity):
        return "POSSIBLE_INCOMPATIBILITY", "El fabricante del CPE difiere del inventario."
    product = _software_product_match(_cpe_part(name, 4), identity)
    if product == "NONE":
        return "POSSIBLE_INCOMPATIBILITY", "El producto CPE no corresponde al software inventariado."
    if product == "RELATED":
        return ("EXPLORATORY", "El producto comparte una denominación con el inventario, "
                "pero es otro producto o variante; requiere investigación.")

    recorded = ascii_text(identity.get("version")).strip().casefold()
    cpe_version = re.sub(r"\\(.)", r"\1", _cpe_part(name, 5)).casefold()
    if not recorded:
        return ("SOFTWARE_PRODUCT", "Coinciden fabricante y producto; "
                "el inventario no registra una versión.")
    if cpe_version == recorded:
        return ("SOFTWARE_EXACT", "Fabricante, producto y versión CPE coinciden "
                "textualmente con el inventario; no es una confirmación automática.")
    if software_version_in_branch(recorded, cpe_version):
        return ("SOFTWARE_BRANCH", f"Producto coincidente y versión NVD "
                f"«{cpe_version}» perteneciente a la rama inventariada «{recorded}». "
                "No demuestra que esta variante esté instalada.")
    return ("SOFTWARE_PRODUCT", f"Fabricante y producto coincidentes, pero la "
            f"versión NVD «{cpe_version}» difiere de la versión "
            f"inventariada «{recorded}» o no está especificada.")


def classify(candidate, identity):
    if identity.get("asset_type") == "SOFTWARE":
        return classify_software(candidate, identity)
    cpe_name = candidate["cpe_name"]
    if _cpe_part(cpe_name, 2) != "h":
        return "POSSIBLE_INCOMPATIBILITY", "Este CPE no identifica hardware (tipo h)."
    vendor = normalized(_cpe_part(cpe_name, 3))
    product = normalized(_cpe_part(cpe_name, 4))
    wanted_model = normalized(_technical_model_designation(identity))
    wanted_cpu = cpu_spelling(identity.get("cpu_model"))
    if not matches_vendor(_cpe_part(cpe_name, 3), identity):
        return "POSSIBLE_INCOMPATIBILITY", "El fabricante del CPE no coincide con el inventario."
    # Numeric model designations must not match longer neighbouring models:
    # AXIS 206 does not identify AXIS 2060 or AXIS 2067.
    raw_model = _technical_model_designation(identity).lower()
    raw_product = _cpe_part(cpe_name, 4).lower()
    numeric_model = re.fullmatch(r"[0-9]+", raw_model)
    if numeric_model and re.search(
        r"(?<![a-z0-9])" + re.escape(raw_model) + r"[a-z0-9]", raw_product
    ):
        return ("POSSIBLE_INCOMPATIBILITY",
                "El número de modelo es prefijo de otro modelo diferente.")
    if wanted_model and wanted_model not in product:
        term = family_term(identity.get("model"))
        # A series prefix can help discovery but never proves equivalence.
        # Requiring a boundary avoids treating ADAM as related to ADAMANT.
        raw_product = _cpe_part(cpe_name, 4).lower()
        prefix = re.escape(term.lower())
        if (normalized(term) != wanted_model and
                re.match(r"^" + prefix + r"(?:[_-]|[0-9]|$)", raw_product)):
            return "RELATED", "Comparte prefijo de una serie declarada; el modelo exacto difiere."
        if shares_catalog_code(raw_product, identity):
            return ("RELATED", "Solo comparte un prefijo de catálogo, no el modelo "
                    "exacto; exige revisión del analista.")
        proximity = _exploratory_proximity(candidate, identity)
        if proximity:
            return "EXPLORATORY", proximity[1]
        return "POSSIBLE_INCOMPATIBILITY", "El producto CPE no corresponde claramente a la familia."
    if wanted_cpu:
        product_raw = _cpe_part(cpe_name, 4).lower()
        if re.search(r"(?:^|[_-])cpu[_-]?" + re.escape(wanted_cpu) + r"$", product_raw):
            # This is a precise textual designation, never human validation.
            return "SPECIFIC", "El nombre del producto CPE indica la CPU inventariada."
        if wanted_cpu in product:
            # E.g. cpu_12_1215c is not the same product string as cpu_1215c.
            # Keep the record but do not call it an exact textual match.
            return "FAMILY", "La familia y el texto de CPU aparecen con otros componentes."
        # A different CPU explicitly named in the same family is a contradiction.
        name_cpu = re.search(r"cpu[_-]?([0-9]{3,5}[a-z]?)", _cpe_part(cpe_name, 4))
        if name_cpu:
            return "POSSIBLE_INCOMPATIBILITY", "El CPE especifica una CPU distinta."
        return "FAMILY", "Coincide la familia; el CPE no especifica la CPU inventariada."
    if _cpe_part(cpe_name, 5) not in ("", "-", "*"):
        return "NEEDS_INFO", "El CPE indica una versión no registrada en el inventario."
    return "FAMILY", "Coinciden fabricante y familia; se desconoce el modelo de CPU."


def is_manufacturer_related(candidate, identity):
    """Keep only manufacturer-level hardware with explainable product relevance.

    A manufacturer-wide query can return hundreds of unrelated products. Those
    products are not evidence for the inventoried model and must not consume
    candidate storage. Classifications remain suggestions, not validations.
    """
    if identity.get("asset_type") == "SOFTWARE":
        return (candidate.get("match_level") in (
            "SOFTWARE_EXACT", "SOFTWARE_BRANCH", "SOFTWARE_PRODUCT", "EXPLORATORY"
        ) and matches_vendor(_cpe_part(candidate.get("cpe_name", ""), 3), identity)
            and _cpe_part(candidate.get("cpe_name", ""), 2)
            == SOFTWARE_CPE_PARTS.get(identity.get("software_type")))
    if _cpe_part(candidate.get("cpe_name", ""), 2) != "h":
        return False
    if not matches_vendor(_cpe_part(candidate["cpe_name"], 3), identity):
        return False
    return candidate.get("match_level") in (
        "SPECIFIC", "FAMILY", "RELATED", "NEEDS_INFO", "EXPLORATORY"
    )


def is_pertinent(candidate, identity):
    """Strong, explainable evidence for STOPPING further discovery.

    Candidate != confirmed AssetCpe. A related family-only result with
    unknown CPU never becomes a definitive match automatically.
    """
    if identity.get("asset_type") == "SOFTWARE":
        return (not candidate.get("deprecated")
                and candidate.get("match_level") == "SOFTWARE_EXACT"
                and is_manufacturer_related(candidate, identity))
    cpe_name = candidate.get("cpe_name", "")
    if (_cpe_part(cpe_name, 2) != "h" or candidate.get("deprecated")
            or not matches_vendor(_cpe_part(cpe_name, 3), identity)):
        return False
    model = normalized(_technical_model_designation(identity))
    product = normalized(_cpe_part(cpe_name, 4))
    if not model or model not in product:
        return False
    if cpu_spelling(identity.get("cpu_model")):
        return candidate.get("match_level") == "SPECIFIC"
    # With unknown CPU, require the product field to match the full model.
    return product == model and _cpe_part(cpe_name, 5) in ("", "-", "*")


PRIORITY = {
    "SPECIFIC": 0, "SOFTWARE_EXACT": 0,
    "FAMILY": 1, "SOFTWARE_BRANCH": 1,
    "RELATED": 2, "SOFTWARE_PRODUCT": 2,
    "NEEDS_INFO": 3, "EXPLORATORY": 4, "POSSIBLE_INCOMPATIBILITY": 5,
}


def normalize_candidate(record, identity, strategy):
    cpe = record.get("cpe") or {}
    name_id = cpe.get("cpeNameId")
    name = cpe.get("cpeName")
    if not isinstance(name_id, str) or not isinstance(name, str):
        return None
    # Only the CPE part appropriate to this *inventoried* asset is accepted.
    expected_part = (SOFTWARE_CPE_PARTS.get(identity.get("software_type"))
                     if identity.get("asset_type") == "SOFTWARE" else "h")
    if _cpe_part(name, 2) != expected_part:
        return None
    titles = cpe.get("titles")
    titles = titles if isinstance(titles, list) else []
    title = next((t.get("title") for t in titles
                  if isinstance(t, dict) and t.get("lang") == "en"
                  and isinstance(t.get("title"), str) and t.get("title")), None)
    title = title or next((t.get("title") for t in titles
                           if isinstance(t, dict) and isinstance(t.get("title"), str)
                           and t.get("title")), name)
    item = {
        "cpe_name_id": name_id,
        "cpe_name": name,
        "title": title,
        "deprecated": bool(cpe.get("deprecated", False)),
        "cpe_type": _cpe_part(name, 2),
        "version": _cpe_part(name, 5),
        "nvd_created_at": cpe.get("created"),
        "nvd_modified_at": cpe.get("lastModified"),
        "nvd_references": safe_references(cpe.get("refs")),
        "methods": [strategy],
    }
    item["match_level"], item["match_reason"] = classify(item, identity)
    if item["match_level"] == "EXPLORATORY":
        item["exploratory_distance"] = (
            0 if identity.get("asset_type") == "SOFTWARE"
            else _exploratory_proximity(item, identity)[0]
        )
    return item


def merge_candidates(results):
    merged = {}
    for entry in results:
        key = entry["cpe_name_id"]
        if key not in merged:
            merged[key] = entry
        else:
            merged[key]["methods"] = sorted(set(merged[key]["methods"] + entry["methods"]))
            merged[key]["nvd_references"] = combine_references(
                merged[key].get("nvd_references", []), entry.get("nvd_references", [])
            )
    return sorted(
        merged.values(),
        key=lambda v: (bool(v.get("deprecated", False)), PRIORITY.get(v["match_level"], 99),
                       v.get("exploratory_distance", 0),
                       str(v.get("title") or "").casefold(), str(v.get("cpe_name") or "")),
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

def candidates_for_identity(candidates, identity):
    """Filter stored NVD candidates by the actual inventoried CPE part."""
    part = (SOFTWARE_CPE_PARTS.get(identity.get("software_type"))
            if identity.get("asset_type") == "SOFTWARE" else "h")
    return [
        row for row in (candidates or [])
        if isinstance(row, dict) and isinstance(row.get("cpe_name"), str)
        and _cpe_part(row["cpe_name"], 2) == part
    ]
