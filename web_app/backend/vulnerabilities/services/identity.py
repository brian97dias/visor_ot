"""Read-only construction of hardware search identities and NVD query plans."""
import hashlib
import json
import re
import unicodedata

from assets.models import Asset


def compact(value):
    return " ".join(str(value or "").strip().split())


def ascii_text(value):
    value = unicodedata.normalize("NFKD", compact(value))
    return "".join(ch for ch in value if not unicodedata.combining(ch))


def normalized(value):
    """Comparable alphanumeric spelling; never mutate the actual inventory."""
    return re.sub(r"[^a-z0-9]", "", ascii_text(value).lower())


def family_spelling(value):
    name = ascii_text(value).lower()
    name = re.sub(r"\bs7[\s_-]*1200\b", "s7-1200", name)
    name = re.sub(r"[\s_]+", "_", name)
    return re.sub(r"[^a-z0-9_-]", "", name).strip("_")


def vendor_spelling(value):
    return re.sub(r"[^a-z0-9_]", "", re.sub(r"[\s_-]+", "_", ascii_text(value).lower())).strip("_")


# Controlled alternatives for CPE vendors, not changes to inventory or trust.
KNOWN_CPE_VENDOR_ALIASES = {
    "rockwell_automation": ("rockwellautomation",),
    "axis_communications": ("axis",),
    "phoenix_contact": ("phoenixcontact",),
}


def vendor_variants(value):
    """Return deterministic CPE vendor alternatives with duplicates removed."""
    canonical = vendor_spelling(value)
    if not canonical:
        return []
    variants = [*KNOWN_CPE_VENDOR_ALIASES.get(canonical, ()), canonical]
    if "_" in canonical:
        variants.extend((canonical.replace("_", ""), canonical.replace("_", "-")))
    return list(dict.fromkeys(filter(None, variants)))


def catalog_code_prefix(value):
    """1783-EMS08T/B -> 1783; not Axis 206 -> 20, nor nearby 206/207."""
    match = re.match(r"^([0-9]{3,5})[-_/][A-Za-z0-9]", compact(value))
    return match.group(1) if match else ""


def cpu_spelling(value):
    value = re.sub(r"^\s*cpu[\s_:-]*", "", compact(value), flags=re.I)
    return re.sub(r"[^a-z0-9]", "", ascii_text(value).lower())


def hardware_identity(asset):
    if asset.asset_type != Asset.AssetType.HARDWARE:
        raise ValueError("El descubrimiento CPE de software llegará en la fase 4.")
    hw = asset.hardware
    return {
        "asset_type": "HARDWARE",
        "manufacturer": compact(hw.manufacturer),
        "model": compact(hw.model),
        "cpu_model": compact(hw.cpu_model),
        "role": hw.role,
    }


def fingerprint(identity):
    # Changing MAC, location, cost or name does NOT invalidate a CPE search.
    canonical = {key: normalized(identity.get(key)) for key in (
        "asset_type", "manufacturer", "model", "cpu_model", "role"
    )}
    data = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def family_term(model):
    """Conservative family fallback only when inventory explicitly says 'Series'.

    No numeric designation is dropped without that explicit cue. Keep the
    original model untouched for human validation and identity fingerprints.
    """
    value = compact(model)
    series = re.search(r"[\s_-]+(?:series|serie|family|familia)$", value, re.I)
    if not series:
        return value
    core = value[:series.start()].strip()
    # ADAM-5000 Series -> ADAM. Different model numbers remain distinct CPEs;
    # this is a DISCOVERY term, not evidence of product equivalence.
    single_prefix = re.fullmatch(r"([a-z][a-z0-9]*)[-_ ]+\d+[a-z0-9_-]*", core, re.I)
    return single_prefix.group(1) if single_prefix else (core or value)


def build_level_queries(identity, level):
    """One level's plan. The worker skips duplicate requests across levels."""
    if level == "SPECIFIC":
        return build_queries(identity, "SPECIFIC")
    if level == "FAMILY":
        return build_queries({**identity, "model": family_term(identity.get("model")),
                              "cpu_model": ""}, "BROAD")
    if level == "MANUFACTURER":
        variants = vendor_variants(identity.get("manufacturer"))
        if not variants:
            raise ValueError("Registra un fabricante válido para ampliar a fabricante.")
        code = catalog_code_prefix(identity.get("model"))
        # Narrow catalog-code requests before broad vendor-only requests.
        params = [f"cpe:2.3:h:{v}:{code}*" for v in variants] if code else []
        params += [f"cpe:2.3:h:{v}" for v in variants]
        return [{"strategy": "cpeMatchString", "parameter": q}
                for q in dict.fromkeys(params)]
    raise ValueError("Nivel de descubrimiento CPE no permitido.")


def build_queries(identity, scope="SPECIFIC"):
    manufacturer = compact(identity.get("manufacturer"))
    family = compact(identity.get("model"))
    cpu = cpu_spelling(identity.get("cpu_model"))
    if not family:
        raise ValueError("Registra el modelo o familia del hardware para buscar CPE.")
    if not manufacturer:
        raise ValueError("Registra el fabricante del hardware para buscar CPE.")

    exact = scope == "SPECIFIC" and bool(cpu)
    # Avoid repeating CPU when the model already incorporates its designation.
    keywords = [manufacturer, family]
    if exact and normalized(cpu) not in normalized(family):
        cpu_label = compact(identity.get("cpu_model"))
        keywords.append(cpu_label if cpu_label.lower().startswith("cpu") else "CPU " + cpu_label)
    keyword = " ".join(keywords)
    vendor = vendor_spelling(manufacturer)
    product = family_spelling(family)
    if not vendor or not product:
        raise ValueError("La identidad técnica no permite construir consultas NVD.")
    if exact and cpu not in normalized(product):
        product += "_cpu_" + cpu

    # cpeMatchString is only a query PREFIX. Never treat it as an official CPE.
    # A trailing wildcard permits variants (and broader family matches).
    return [
        {"strategy": "keywordSearch", "parameter": keyword},
        {"strategy": "cpeMatchString", "parameter": f"cpe:2.3:h:{vendor}:{product}*"},
    ]

# Standalone automatic cpeMatchString plan. Increment 1: NOT wired to the worker.
# The user may inspect this pure plan before enabling it in Increment 2.
MAX_CPE_PLAN_QUERIES = 30
_CPE_MODEL_PATTERN = re.compile(r"[a-z0-9 _/.-]+\Z")
_CPE_VENDOR_PATTERN = re.compile(r"[a-z0-9_-]{2,80}\Z")
_CPE_PRODUCT_PATTERN = re.compile(r"[a-z0-9._-]{1,119}\Z")


def _planned_model_core(value):
    """Preserve model numbers and suffixes; drop only explicit family labels."""
    if not isinstance(value, str) or not compact(value):
        raise ValueError("Registra un modelo válido para buscar CPE.")
    model = ascii_text(value).lower()
    if not _CPE_MODEL_PATTERN.fullmatch(model):
        raise ValueError("El modelo contiene caracteres no admitidos para el plan CPE.")
    return re.sub(r"[ _-]+(?:series|serie|family|familia)$", "", model).strip()


def _planned_product_spellings(core):
    """Up to three *syntactic* variants, not fuzzy model substitutions."""
    # Slash carries a model suffix (e.g. /B) and becomes a separator, not a deletion.
    primary = re.sub(r"[ /]+", "_", core).strip("_")
    underscore = primary.replace("-", "_")
    joined = primary.replace("-", "").replace("_", "")
    values = list(dict.fromkeys((primary, underscore, joined)))
    if any(not _CPE_PRODUCT_PATTERN.fullmatch(value) for value in values):
        raise ValueError("El modelo excede la longitud o sintaxis admitida por el plan CPE.")
    return values


def _planned_family_prefix(model, core, manufacturer):
    """Only explicit series, established catalogue code or recognizable family.

    A numeric code such as AXIS 206 must not be reduced to 20/2 or mixed with
    AXIS 207. Any prefix is a discovery query, never evidence of equivalence.
    """
    declared = family_term(model)
    if normalized(declared) != normalized(model):
        return _planned_product_spellings(_planned_model_core(declared))[0]
    code = catalog_code_prefix(model)
    if code:
        return code
    fragments = re.split(r"[ _-]+", core)
    if (len(fragments) >= 2 and re.fullmatch(r"[a-z]{4,}", fragments[0])
            and any(char.isdigit() for char in fragments[1])
            and normalized(fragments[0]) not in {
                normalized(term) for term in re.split(r"[ _-]+", manufacturer)
            }
            and normalized(fragments[0]) not in {
                normalized(v) for v in vendor_variants(manufacturer)
            }):
        return fragments[0]
    return ""


def build_cpe_match_plan(identity):
    """Plan hardware CPE queries from specific to manufacturer, without NVD I/O.

    Kept separate from build_queries/build_level_queries until Increment 2.
    Every entry is a search pattern, NOT an official identification. Only a
    human analyst can validate a CPE-to-asset association.
    """
    if not isinstance(identity, dict) or identity.get("asset_type") != "HARDWARE":
        raise ValueError("Este plan automático requiere un activo de hardware.")
    manufacturer = identity.get("manufacturer")
    model = identity.get("model")
    cpu_value = identity.get("cpu_model", "")
    if not isinstance(manufacturer, str) or not compact(manufacturer):
        raise ValueError("Registra un fabricante válido para buscar CPE.")
    if not isinstance(cpu_value, str):
        raise ValueError("El modelo de CPU debe ser texto.")
    if not isinstance(model, str) or not compact(model):
        raise ValueError("Registra un modelo válido para buscar CPE.")

    vendors = vendor_variants(manufacturer)
    if not vendors or any(not _CPE_VENDOR_PATTERN.fullmatch(v) for v in vendors):
        raise ValueError("El fabricante no puede representarse como identificador CPE.")
    model_core = _planned_model_core(model)
    cpu = cpu_spelling(cpu_value)
    if compact(cpu_value) and not cpu:
        raise ValueError("La CPU no puede representarse como identificador CPE.")
    # Remove the CPU only when it is explicitly the model's final CPU field.
    # Never strip arbitrary numeric/alpha suffixes such as Rockwell '/B'.
    family_core = model_core
    suffix = None
    if cpu:
        suffix = re.search(
            r"(?:[ _-]+cpu[ _:-]*|[ _-]+)" + re.escape(cpu) + r"$",
            model_core,
        )
        if suffix:
            family_core = model_core[:suffix.start()].strip(" _-")
    model_forms = _planned_product_spellings(family_core)
    has_cpu_in_model = suffix is not None
    full_forms = _planned_product_spellings(model_core)
    if cpu and not has_cpu_in_model:
        full_forms = [form + "_cpu_" + cpu for form in model_forms]
    if any(not _CPE_PRODUCT_PATTERN.fullmatch(form) for form in full_forms):
        raise ValueError("El sufijo de CPU excede la longitud del producto CPE.")

    family_prefix = _planned_family_prefix(model, family_core, manufacturer)
    seen = set()
    plan = []

    def append(level, vendor, product):
        parameter = f"cpe:2.3:h:{vendor}:{product}*" if product else f"cpe:2.3:h:{vendor}:*"
        if parameter not in seen:
            seen.add(parameter)
            plan.append({"level": level, "strategy": "cpeMatchString", "parameter": parameter})

    # Keep the concatenated spelling for the highest-priority vendor only.
    # Other verified vendor variants receive the two separator spellings.
    for index, vendor in enumerate(vendors):
        for product in full_forms[:3 if index == 0 else 2]:
            append("SPECIFIC", vendor, product)

    if cpu:
        for index, vendor in enumerate(vendors):
            for product in model_forms[:3 if index == 0 else 2]:
                append("FAMILY", vendor, product)

    # A broad family prefix is useful for discovery, never an exact match.
    if family_prefix:
        for vendor in vendors:
            append("FAMILY", vendor, family_prefix)

    for vendor in vendors:
        append("MANUFACTURER", vendor, "")

    if len(plan) > MAX_CPE_PLAN_QUERIES:
        raise ValueError("La identidad genera demasiadas variantes CPE.")
    return plan

# Final optional discovery level: NVD may attribute a product to a different
# manufacturer even though the inventoried brand occurs in the CPE title/model.
# Both expressions are cacheable keywordSearch queries, not new vendor aliases.
MAX_ALTERNATIVE_QUERIES = 2


def build_alternative_keyword_plan(identity):
    """Bounded terms to investigate brand/provider discrepancies.

    No automatic inventory correction or cross-vendor trust is implied.
    """
    if identity.get("asset_type") != "HARDWARE":
        raise ValueError("La investigación alternativa requiere hardware.")
    manufacturer = compact(identity.get("manufacturer"))
    model = compact(identity.get("model"))
    if not manufacturer or not model:
        raise ValueError("Faltan fabricante o modelo para la búsqueda alternativa.")
    # Keyword API grammar also forbids arbitrary URL/query injection.
    if any(not re.fullmatch(r"[\\w ./-]+", ascii_text(part))
           for part in (manufacturer, model)):
        raise ValueError("La identidad no admite búsqueda textual alternativa.")
    specific = compact(ascii_text(manufacturer) + " " + ascii_text(model))
    general = ascii_text(manufacturer)
    if len(general) < 4 or len(specific) > 120 or len(general) > 120:
        return []
    terms = list(dict.fromkeys([specific, general]))[:MAX_ALTERNATIVE_QUERIES]
    return [{"level": "ALTERNATIVE", "strategy": "keywordSearch",
             "parameter": term} for term in terms]
