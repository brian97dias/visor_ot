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
        keywords += ["CPU", compact(identity.get("cpu_model"))]
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
