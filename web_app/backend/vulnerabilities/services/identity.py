"""Read-only construction of hardware and software CPE search identities."""
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
        raise ValueError("Esta identidad CPE requiere un activo de hardware.")
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
    if identity.get("asset_type") == "SOFTWARE":
        # Preserve punctuation in versions: 12.1 and 121 are not equivalent.
        canonical = {
            "asset_type": "software",
            "software_type": normalized(identity.get("software_type")),
            "manufacturer": normalized(identity.get("manufacturer")),
            "product": normalized(identity.get("product")),
            "version": ascii_text(identity.get("version")).casefold(),
        }
    else:
        # Keep the established hardware fingerprint byte-for-byte identical.
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


def _planned_progressive_model_prefixes(model, core, manufacturer):
    """Model-derived FAMILY probes, never automatic product identification.

    For EDS-508A, query EDS-508*, EDS-50*, EDS-5* in that order.
    Only an explicit alphanumeric model with a three-or-more-letter series,
    three-or-more-digit code and optional single-letter suffix is eligible.
    Avoid unbounded one-letter/number probes and redundant brand prefixes.
    """
    if re.search(r"[ _-]+(?:series|serie|family|familia)$", model, re.I):
        return []
    found = re.fullmatch(r"([a-z]{3,12})[ _-]+([0-9]{3,6})([a-z]?)", core)
    if not found:
        return []
    series, digits = found.group(1), found.group(2)
    vendor_words = {
        normalized(word) for word in re.split(r"[ _-]+", manufacturer)
    }
    vendor_words.update(normalized(v) for v in vendor_variants(manufacturer))
    if normalized(series) in vendor_words:
        return []
    sizes = dict.fromkeys((len(digits), len(digits) - 1, 1))
    return [f"{series}-{digits[:size]}" for size in sizes if size > 0]


def _planned_short_series_prefixes(core, manufacturer):
    """Up to three increasingly broad product-prefix probes.

    'FL IL 24 BK PAC' -> 'fl_il_24', 'fl_il', 'fl'. Only segmented
    models beginning with a 2-3 letter series qualify. A full model still
    outranks these exploratory probes; prefix hits never prove identity.
    """
    parts = re.split(r"[ _-]+", core)
    if len(parts) < 3 or not re.fullmatch(r"[a-z]{2,3}", parts[0]):
        return []
    if parts[0] in {
        normalized(v) for v in vendor_variants(manufacturer)
    }:
        return []
    if any(not re.fullmatch(r"[a-z0-9]{1,24}", part) for part in parts):
        return []
    # Do not use bare one-character model tokens as the fallback series.
    return ["_".join(parts[:count]) for count in (3, 2, 1)]


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
    # Search nearest model stem before widening. Weak matches cannot satisfy
    # the existing stop condition and must never be mistaken for exact IDs.
    for product in _planned_progressive_model_prefixes(model, family_core, manufacturer):
        for vendor in vendors:
            append("FAMILY", vendor, product)

    for product in _planned_short_series_prefixes(family_core, manufacturer):
        for vendor in vendors:
            append("FAMILY", vendor, product)

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
# Cacheable keywordSearch hints, never new vendor aliases.
# Hardware/noncompound software use two; eligible compound software uses three.
MAX_ALTERNATIVE_QUERIES = 3


def build_alternative_keyword_plan(identity):
    """Bounded terms to investigate brand/provider discrepancies.

    No automatic inventory correction or cross-vendor trust is implied.
    """
    asset_type = identity.get("asset_type")
    if asset_type not in ("HARDWARE", "SOFTWARE"):
        raise ValueError("La investigación alternativa requiere hardware o software.")
    manufacturer = compact(identity.get("manufacturer"))
    model = compact(identity.get(
        "model" if asset_type == "HARDWARE" else "product"
    ))
    if not manufacturer or not model:
        raise ValueError("Faltan fabricante o modelo/producto para la búsqueda alternativa.")
    if asset_type == "SOFTWARE" and (
        compact(identity.get("software_type")).upper() not in SOFTWARE_CPE_PARTS
    ):
        raise ValueError("Tipo de software desconocido.")
    # Keyword API grammar also forbids arbitrary URL/query injection.
    if any(not re.fullmatch(r"[A-Za-z0-9 _./-]+", ascii_text(part))
           for part in (manufacturer, model)):
        return []  # No alterar la búsqueda estructurada por caracteres no admitidos.
    specific = compact(ascii_text(manufacturer) + " " + ascii_text(model))
    general = ascii_text(manufacturer)
    # Short vendor identifiers such as ATC are meaningful for software
    # exploration, but cannot by themselves establish a CPE identification.
    minimum_vendor_length = 3 if asset_type == "SOFTWARE" else 4
    if (len(normalized(general)) < minimum_vendor_length
            or len(specific) > 120 or len(general) > 120):
        return []
    terms = [specific]
    # A compound device product can include a CPU identifier absent from NVD.
    # Preserve manufacturer + product family as a middle keyword probe.
    # Hardware and all other software keep the existing two-query behaviour.
    if asset_type == "SOFTWARE":
        compound = software_compound_cpu_family(model, manufacturer)
        if compound:
            family_phrase = " ".join(compound[:3]).upper()
            middle = compact(manufacturer + " " + family_phrase)
            if len(middle) <= 120:
                terms.append(middle)
    terms.append(general)
    terms = list(dict.fromkeys(terms))[:MAX_ALTERNATIVE_QUERIES]
    return [{"level": "ALTERNATIVE", "strategy": "keywordSearch",
             "parameter": term} for term in terms]


# Software identity and pure query plans; the existing worker executes them.
# No identity constructor infers software versions from installed hardware.
SOFTWARE_CPE_PARTS = {"OS": "o", "FIRMWARE": "o", "APPLICATION": "a"}
_SOFTWARE_VERSION_FORMAT = re.compile(r"[a-z0-9][a-z0-9._()+-]{0,99}\Z")
_SOFTWARE_BRANCH_FORMAT = re.compile(r"[0-9]+\.[0-9]+\Z")


def software_identity(asset):
    """Extract software fields only, never infer an installed version from hardware."""
    if asset.asset_type != Asset.AssetType.SOFTWARE:
        raise ValueError("La identidad CPE solicitada no corresponde a software.")
    software = asset.software
    subtype = compact(software.software_type).upper()
    if subtype not in SOFTWARE_CPE_PARTS:
        raise ValueError("Tipo de software no admitido para planificar CPE.")
    return {
        "asset_type": "SOFTWARE",
        "software_type": subtype,
        "manufacturer": compact(software.manufacturer),
        "product": compact(software.product),
        "version": compact(software.version),
    }


def _software_product_spellings(product, manufacturer):
    """Remove a redundant, delimited vendor word (Cisco IOS -> ios).

    The value in the inventory is not changed. Do not drop unrelated tokens
    such as Catalyst or guess a software product from the asset name.
    """
    core = _planned_model_core(product)
    for alias in sorted(vendor_variants(manufacturer), key=len, reverse=True):
        for separator in (" ", "_", "-"):
            if core.startswith(alias + separator):
                core = core[len(alias) + 1:]
                break
        else:
            continue
        break
    forms = _planned_product_spellings(core)
    if not forms or any(not _CPE_PRODUCT_PATTERN.fullmatch(x) for x in forms):
        raise ValueError("El producto no se puede representar en CPE.")
    return forms


def software_series_stem(product, manufacturer):
    """Bounded software-series fallback from a delimited model code.

    ADAM-5510 -> adam; a generic IOS product does not produce an unsafe
    short prefix. A shared series helps discovery, not CPE identification.
    """
    core = _planned_model_core(product)
    match = re.fullmatch(r"([a-z]{4,12})[ _-]+[0-9]{3,6}[a-z]?", core)
    if not match:
        return ""
    series = match.group(1)
    if normalized(series) in {
        normalized(word) for word in re.split(r"[ _-]+", manufacturer)
    } or normalized(series) in {
        normalized(alias) for alias in vendor_variants(manufacturer)
    }:
        return ""
    return series


def software_numeric_model(product, manufacturer):
    """Extract a whole numeric firmware model after verified vendor stripping.

    Axis Communications / AXIS 206 Firmware -> 206. The source product must
    explicitly contain 'firmware'; numbers embedded in generic software names
    or version fields must never become model identifiers.
    """
    forms = _software_product_spellings(product, manufacturer)
    match = re.fullmatch(r"([0-9]{3,6})_firmware", forms[0])
    return match.group(1) if match else ""


def software_numeric_prefixes(product, manufacturer):
    """Bounded, less specific CPE product prefixes; discovery evidence only.

    206_firmware -> 206*, 20*. No one-digit prefix, no change to inventory
    and no implication that 207W firmware is compatible with model 206.
    """
    model = software_numeric_model(product, manufacturer)
    if not model:
        return []
    return list(dict.fromkeys((model + "*", model[:-1] + "*")))


def software_short_series_model(product, manufacturer):
    """Recover segmented device series from explicitly named firmware products.

    Phoenix Contact / FL IL 24 BK PAC Firmware -> fl_il_24_bk_pac.
    The suffix is a software descriptor, not part of the device model.
    Do not treat an unrelated OS/application version or arbitrary short
    word as a product family.
    """
    canonical = _software_product_spellings(product, manufacturer)[0]
    if not canonical.endswith("_firmware"):
        return ""
    core = canonical[:-len("_firmware")]
    return core if _planned_short_series_prefixes(core, manufacturer) else ""


def software_short_series_prefixes(product, manufacturer):
    """Reuse hardware's bounded FL IL 24 -> FL IL -> FL progression.

    The two-letter fallback is delimited (fl_*) so it will not query
    unrelated products such as fluffy, fl2 or flserver.
    """
    core = software_short_series_model(product, manufacturer)
    if not core:
        return []
    prefixes = _planned_short_series_prefixes(core, manufacturer)
    return [p + "*" if "_" in p else p + "_*" for p in prefixes]


def software_compound_cpu_family(product, manufacturer):
    """A bounded compound device-series identity, not an installed firmware claim.

    SIMATIC S7 1200 CPU 1215C -> ('simatic', 's7', '1200', '1215c').
    Require an explicit CPU designation and three distinctive family tokens.
    This cannot turn IOS versions, AXIS numbers or a broad brand into a series.
    """
    primary = _software_product_spellings(product, manufacturer)[0]
    match = re.fullmatch(
        r"([a-z][a-z0-9]{3,23})_([a-z]{1,8}[0-9]{1,3})_"
        r"([0-9]{3,6})_cpu_([0-9]{3,6}[a-z]?)",
        primary,
    )
    if not match:
        return None
    brand, series, model, cpu = match.groups()
    if brand in {normalized(v) for v in vendor_variants(manufacturer)}:
        return None
    return brand, series, model, cpu


def software_compound_cpu_prefixes(product, manufacturer):
    """Broaden a compound product by removing CPU revision, then CPU token."""
    family = software_compound_cpu_family(product, manufacturer)
    if not family:
        return []
    stem = "_".join(family[:3])
    return [stem + "_cpu*", stem + "*"]


def _software_cpe_version(version):
    """Escape CPE 2.3 special characters, preserving Cisco version suffixes.

    Do not collapse 12.1(22)EA14 into 12.1 or remove punctuation. Unknown
    syntax fails before generating any manufacturer-wide fallback.
    """
    text = ascii_text(version).lower()
    if not _SOFTWARE_VERSION_FORMAT.fullmatch(text):
        raise ValueError("La versión no tiene un formato CPE admitido.")
    return (text.replace("+", r"\+")
                .replace("(", r"\(")
                .replace(")", r"\)"))


def software_version_in_branch(recorded, nvd_version):
    """Pure *future* local filter for version-branch suggestions, not confirmation.

    NVD's broad prefix 12.1* may also retrieve 12.10. The classifier in a
    later phase must filter locally. 12.1(22)EA14 belongs to 12.1; 12.10
    does not. Exact version identity still requires human review.
    """
    base = ascii_text(recorded).strip().casefold()
    observed = re.sub(r"\\(.)", r"\1", ascii_text(nvd_version)).casefold()
    if observed == base:
        return True
    if not _SOFTWARE_BRANCH_FORMAT.fullmatch(base) or not observed.startswith(base):
        return False
    suffix = observed[len(base):]
    return bool(suffix) and (suffix[0] in "(.+-_" or suffix[0].isalpha())


def build_software_cpe_match_plan(identity):
    """Pure ordered OS/firmware/application query plan; no NVD or DB access.

    '12.1' is the recorded version, not proof that 12.1(22)EA14 is installed.
    Prefix results and product catalogues are filtered locally by the worker.
    Existing build_cpe_match_plan continues to handle hardware unmodified.
    """
    if not isinstance(identity, dict) or identity.get("asset_type") != "SOFTWARE":
        raise ValueError("Este plan requiere una identidad de software.")
    subtype = compact(identity.get("software_type")).upper()
    part = SOFTWARE_CPE_PARTS.get(subtype)
    if part is None:
        raise ValueError("Tipo de software no admitido para generar CPE.")
    manufacturer = identity.get("manufacturer")
    product = identity.get("product")
    version = identity.get("version") or ""
    if not isinstance(manufacturer, str) or not compact(manufacturer):
        raise ValueError("Registra un fabricante para identificar software.")
    if not isinstance(product, str) or not compact(product):
        raise ValueError("Registra un producto para identificar software.")
    if not isinstance(version, str):
        raise ValueError("La versión del software debe ser texto.")

    vendors = vendor_variants(manufacturer)
    if not vendors or any(not _CPE_VENDOR_PATTERN.fullmatch(v) for v in vendors):
        raise ValueError("El fabricante no admite representación CPE.")
    products = _software_product_spellings(product, manufacturer)
    recorded_version = compact(version)
    version_token = _software_cpe_version(recorded_version) if recorded_version else ""

    plan = []
    seen = set()

    def add(level, vendor, prod, version_expr, scope, *, local_filter=False):
        suffix = ":" + version_expr if version_expr is not None else ""
        parameter = f"cpe:2.3:{part}:{vendor}:{prod}{suffix}"
        if parameter not in seen:
            seen.add(parameter)
            plan.append({
                "level": level,
                "strategy": "cpeMatchString",
                "parameter": parameter,
                "version_scope": scope,
                "requires_local_version_filter": local_filter,
            })

    # One syntactic spelling is preferred; additional vendor/product spellings
    # are bounded and have exactly the same order of search levels as hardware.
    pairs = [(vendor, prod)
             for i, vendor in enumerate(vendors)
             for prod in products[:3 if i == 0 else 2]]
    if version_token:
        for vendor, prod in pairs:
            add("SPECIFIC", vendor, prod, version_token, "RECORDED_VERSION")
        if _SOFTWARE_BRANCH_FORMAT.fullmatch(recorded_version):
            for vendor, prod in pairs:
                # The wildcard query is NOT an exhaustive or exact branch match.
                add("FAMILY", vendor, prod, version_token + "*", "BRANCH_PREFIX",
                    local_filter=True)

    # Always retrieve all versions of this product. Phase 2 must classify
    # local versions such as Cisco's escaped 12.1\(22\)ea14 conservatively.
    for vendor, prod in pairs:
        add("FAMILY", vendor, prod, "*", "PRODUCT_CATALOGUE", local_filter=True)

    # A model-like software product may have other members in the same series.
    # ADAM-5510 -> adam*, strictly after exact-product and version searches.
    # This is not an equivalence claim: all rows must be checked locally.
    series = software_series_stem(product, manufacturer)
    if series:
        for vendor in vendors:
            add("FAMILY", vendor, series + "*", None, "RELATED_SERIES",
                local_filter=True)

    # Share hardware's progressive numeric-model discovery technique, but only
    # for an explicitly inventoried firmware product with a numeric model.
    # The catalogue classifier (not this query) decides weak proximity.
    for prefix in software_numeric_prefixes(product, manufacturer):
        for vendor in vendors:
            add("FAMILY", vendor, prefix, None, "NUMERIC_MODEL_PREFIX",
                local_filter=True)

    # Hardware already uses the same progressive short-series planner.
    # Keep the firmware qualifier out of the model comparison, and retain
    # a delimited final prefix: fl_il_24* -> fl_il* -> fl_*.
    for prefix in software_short_series_prefixes(product, manufacturer):
        for vendor in vendors:
            add("FAMILY", vendor, prefix, None, "SHORT_SERIES_PREFIX",
                local_filter=True)

    for prefix in software_compound_cpu_prefixes(product, manufacturer):
        for vendor in vendors:
            add("FAMILY", vendor, prefix, None, "COMPOUND_CPU_FAMILY",
                local_filter=True)

    for vendor in vendors:
        add("MANUFACTURER", vendor, "*", None, "MANUFACTURER_CATALOGUE",
            local_filter=True)

    if len(plan) > MAX_CPE_PLAN_QUERIES:
        raise ValueError("El software genera demasiadas consultas CPE.")
    return plan
