"""Read-only, conservative evaluation of NVD CPE criteria and version bounds.

Three-valued logic prevents missing inventory, ambiguous version formats, or
unsupported CPE expressions from becoming a false "No aplica". It does not
create analyst decisions, mutate CPE associations, or contact NVD.
"""
import re

COMPATIBLE = "COMPATIBLE"
EXCLUDED = "EXCLUDED"
INDETERMINATE = "INDETERMINATE"
VERSION_KEYS = (
    "versionStartIncluding", "versionStartExcluding",
    "versionEndIncluding", "versionEndExcluding",
)
_NUMERIC = re.compile(r"^[vV]?[0-9]+(?:\.[0-9]+)*$")


def _version_tuple(value):
    if not isinstance(value, str) or not _NUMERIC.fullmatch(value.strip()):
        return None
    return tuple(int(x) for x in value.strip().lstrip("vV").split("."))


def compare_numeric_versions(installed, reference):
    """Return -1/0/1 or None if equality is ambiguous due to precision.

    4.0 > 3.0.0 is provable from the first component. But 4.0 versus
    4.0.0 is not silently padded with zeroes, and nonnumeric vendor strings
    are deliberately unsupported.
    """
    a = _version_tuple(installed)
    b = _version_tuple(reference)
    if a is None or b is None:
        return None
    for left, right in zip(a, b):
        if left < right:
            return -1
        if left > right:
            return 1
    return 0 if len(a) == len(b) else None


def evaluate_version(installed, criterion_version="*", bounds=None):
    """Evaluate a version constraint; returns a result and a short explanation."""
    bounds = bounds or {}
    if not isinstance(bounds, dict) or any(k not in VERSION_KEYS for k in bounds):
        return INDETERMINATE, "El criterio contiene límites de versión desconocidos."
    if any(not isinstance(value, str) or not value for value in bounds.values()):
        return INDETERMINATE, "Uno de los límites NVD está vacío o no es texto."
    if criterion_version not in ("*", "-"):
        result = compare_numeric_versions(installed, criterion_version)
        if result is None:
            return INDETERMINATE, "No se puede verificar la versión exacta del CPE."
        if result != 0:
            return EXCLUDED, "La versión instalada no corresponde a la versión exacta del criterio."
    elif criterion_version == "-":
        # CPE NA is not an alias for ANY. The product can be identified
        # separately, but this version expression is not safely satisfiable.
        return INDETERMINATE, "El criterio CPE usa NA (-), que no significa cualquier versión."
    if not bounds:
        return COMPATIBLE, "El criterio no restringe la versión instalada." if criterion_version == "*" else "La versión coincide con el criterio."

    if not installed:
        return INDETERMINATE, "El inventario no tiene una versión instalada."
    uncertain = False
    for key, bound in bounds.items():
        cmp = compare_numeric_versions(installed, bound)
        if cmp is None:
            uncertain = True
            continue
        if key == "versionStartIncluding" and cmp < 0:
            return EXCLUDED, "La versión está por debajo del mínimo incluido por NVD."
        if key == "versionStartExcluding" and cmp <= 0:
            return EXCLUDED, "La versión no supera el mínimo excluido por NVD."
        if key == "versionEndIncluding" and cmp > 0:
            return EXCLUDED, "La versión supera el máximo incluido por NVD."
        if key == "versionEndExcluding" and cmp >= 0:
            return EXCLUDED, "La versión alcanza o supera el máximo excluido por NVD."
    if uncertain:
        return INDETERMINATE, "Formato o precisión de versión insuficiente para resolver el límite."
    return COMPATIBLE, "La versión satisface todos los límites NVD evaluados."


def _parse_cpe(raw):
    if not isinstance(raw, str):
        return None
    fields = raw.split(":")
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        return None
    if fields[2] not in ("h", "o", "a") or not fields[3] or not fields[4]:
        return None
    return fields


def _product_match(criterion, confirmed):
    """Compare CPE vendor/product literally, never using fuzzy family names."""
    if criterion[2:5] != confirmed[2:5]:
        return False
    for index in range(6, 13):
        # Wildcard in NVD may accept a concrete inventory field; '-' is NA.
        if criterion[index] != "*" and criterion[index] != confirmed[index]:
            return False
    return True



def _verified_distinct_product(criterion, confirmed):
    """Only disjoint, explicit Siemens *product lines*; never fuzzy CPE matching.

    NVD CPE family and variant relationships cannot be deduced from arbitrary
    spelling differences. These two Siemens product lines are not aliases:
    S7-PLCSIM Advanced is simulation software, not a S7-1200 CPU.
    Extend only with independently verified disjoint families.
    """
    if criterion[3] != confirmed[3] or criterion[3] != "siemens":
        return False
    names = (criterion[4].lower(), confirmed[4].lower())
    return ((any("s7-plcsim" in name for name in names)
             and any("s7-1200" in name for name in names)))


def _identity(criterion, candidates):
    if any(_product_match(criterion, candidate) for candidate in candidates):
        return "MATCHED"
    if candidates and all(
        _verified_distinct_product(criterion, candidate)
        for candidate in candidates
    ):
        return "DISTINCT"
    return "UNKNOWN"


def _trace(result, reason, *, identity="UNKNOWN", cpe=None, asset=None, version=None,
           distinct_cpes=None):
    observation = {"result": result, "reason": reason, "identity": identity}
    if cpe:
        observation["matched_cpe"] = ":".join(cpe)
    if distinct_cpes:
        observation["distinct_confirmed_cpes"] = [":".join(row) for row in distinct_cpes]
    if asset:
        observation["software_asset_id"] = asset.get("software_asset_id")
        observation["software_name"] = asset.get("software_name")
        observation["software_installation_id"] = asset.get("installation_id")
        observation["installed_version"] = asset.get("version") or ""
    elif version is not None:
        observation["installed_version"] = version
    return observation


def evaluate_criterion(criterion, hardware_cpes, installed_software):
    """Return result for one cpeMatch, without interpreting vulnerable:false as safe."""
    if not isinstance(criterion, dict) or not isinstance(criterion.get("vulnerable"), bool):
        return {"result": INDETERMINATE, "reason": "Criterio NVD incompleto."}
    cpe = _parse_cpe(criterion.get("criteria"))
    if not cpe:
        return {"result": INDETERMINATE, "reason": "El CPE del criterio no es válido."}
    bounds = {key: criterion[key] for key in VERSION_KEYS if key in criterion}
    if cpe[2] == "h":
        names = [_parse_cpe(name) for name in hardware_cpes]
        names = [name for name in names if name and name[2] == "h"]
        identity = _identity(cpe, names)
        candidate = next((name for name in names if _product_match(cpe, name)), None)
        if not names:
            return _trace(INDETERMINATE, "No existe CPE vigente confirmado del hardware.")
        if identity == "DISTINCT":
            return _trace(EXCLUDED,
                "Producto distinto comprobado: S7-PLCSIM y S7-1200 no son la misma línea de producto.",
                identity=identity, distinct_cpes=names)
        if identity != "MATCHED":
            return _trace(INDETERMINATE,
                "La relación de familia o variante entre CPE no está acreditada.",
                identity=identity)
        if bounds or cpe[5] not in ("*", "-"):
            return _trace(INDETERMINATE,
                "La comparación de versión del hardware requiere otra evidencia.",
                identity=identity, cpe=candidate)
        return _trace(COMPATIBLE,
            "CPE de hardware confirmado; condición de plataforma satisfecha.",
            identity=identity, cpe=candidate)

    expected_type = ("FIRMWARE", "OS") if cpe[2] == "o" else ("APPLICATION",)
    relevant = [sw for sw in installed_software if sw.get("software_type") in expected_type]
    if not relevant:
        return _trace(INDETERMINATE, "No hay instalación vigente del tipo de software requerido.")

    matching = []
    unknown = False
    for sw in relevant:
        names = [_parse_cpe(name) for name in sw.get("confirmed_cpes", [])]
        names = [name for name in names if name and name[2] == cpe[2]]
        if not names:
            unknown = True
            continue
        candidate = next((name for name in names if _product_match(cpe, name)), None)
        if not candidate:
            # Lack of a specific installed software name does not attest an
            # exhaustive software inventory. This is never an absence proof.
            unknown = True
            continue
        matching.append((sw, candidate))

    if not matching:
        return _trace(INDETERMINATE,
            "No hay correspondencia exacta con un CPE vigente confirmado del producto instalado.")

    exclusions = []
    for sw, candidate in matching:
        result, reason = evaluate_version(sw.get("version", ""), cpe[5], bounds)
        if candidate[5] not in ("*", "-", sw.get("version", "")):
            result, reason = INDETERMINATE, (
                "La versión del CPE confirmado difiere de la versión inventariada."
            )
        if result == COMPATIBLE:
            return _trace(COMPATIBLE, reason, identity="MATCHED",
                          cpe=candidate, asset=sw)
        if result == INDETERMINATE:
            unknown = True
        else:
            exclusions.append((sw, candidate, reason))
    if unknown:
        sw, candidate = matching[0]
        return _trace(INDETERMINATE,
            "No puede resolverse la versión o existen otras instalaciones sin verificar.",
            identity="MATCHED", cpe=candidate, asset=sw)
    sw, candidate, reason = exclusions[0]
    return _trace(EXCLUDED, reason, identity="MATCHED",
                  cpe=candidate, asset=sw)


def _combine(results, operator):
    if operator == "AND":
        if EXCLUDED in results:
            return EXCLUDED
        if results and all(x == COMPATIBLE for x in results):
            return COMPATIBLE
    elif operator == "OR":
        if COMPATIBLE in results:
            return COMPATIBLE
        if results and all(x == EXCLUDED for x in results):
            return EXCLUDED
    return INDETERMINATE


def _evaluate_group(group, hardware_cpes, installed):
    if not isinstance(group, dict):
        return {"kind": "GROUP", "result": INDETERMINATE, "children": [],
                "reason": "Estructura NVD inválida."}
    operator = group.get("operator", "OR")
    if operator not in ("AND", "OR"):
        operator = None
    nodes = group.get("nodes", [])
    matches = group.get("cpeMatch", [])
    if not isinstance(nodes, list) or not isinstance(matches, list):
        return {"kind": "GROUP", "result": INDETERMINATE, "children": [],
                "reason": "Árbol NVD no interpretable."}
    children = [_evaluate_group(node, hardware_cpes, installed) for node in nodes]
    children.extend(
        {"kind": "CRITERION", "criteria": item.get("criteria"),
         "vulnerable": item.get("vulnerable"),
         "part": _parse_cpe(item.get("criteria"))[2]
             if _parse_cpe(item.get("criteria")) else None,
         "version_constraints": {
             key: item[key] for key in VERSION_KEYS if key in item
         },
         **evaluate_criterion(item, hardware_cpes, installed)}
        for item in matches
        if isinstance(item, dict)
    )
    value = _combine([child["result"] for child in children], operator)
    if group.get("negate") is True:
        value = {COMPATIBLE: EXCLUDED, EXCLUDED: COMPATIBLE}.get(value, INDETERMINATE)
    return {"kind": "GROUP", "operator": operator or "UNKNOWN",
            "negate": group.get("negate") is True, "result": value,
            "children": children}


def evaluate_configurations(configurations, hardware_cpes, installed_software):
    """Returns annotated original NVD logic; alternatives are OR at CVE level."""
    if not isinstance(configurations, list) or not configurations:
        return {"result": INDETERMINATE, "configurations": []}
    rows = [_evaluate_group(config, hardware_cpes, installed_software)
            for config in configurations]
    return {"result": _combine([row["result"] for row in rows], "OR"),
            "configurations": rows}
