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


def evaluate_criterion(criterion, hardware_cpes, installed_software):
    """Return result for one cpeMatch, without interpreting vulnerable:false as safe."""
    if not isinstance(criterion, dict) or not isinstance(criterion.get("vulnerable"), bool):
        return {"result": INDETERMINATE, "reason": "Criterio NVD incompleto."}
    cpe = _parse_cpe(criterion.get("criteria"))
    if not cpe:
        return {"result": INDETERMINATE, "reason": "El CPE del criterio no es válido."}
    bounds = {key: criterion[key] for key in VERSION_KEYS if key in criterion}
    if cpe[2] == "h":
        names = [_parse_cpe(cpe_name) for cpe_name in hardware_cpes]
        names = [item for item in names if item and item[2] == "h"]
        if not names:
            result, reason = INDETERMINATE, "No existe un CPE vigente confirmado del hardware."
        elif not any(_product_match(cpe, name) for name in names):
            result, reason = EXCLUDED, "El CPE confirmado del hardware corresponde a otro producto."
        elif bounds or cpe[5] not in ("*", "-"):
            result, reason = INDETERMINATE, "La comparación de versión del hardware requiere otra evidencia."
        else:
            result, reason = COMPATIBLE, "La identidad del hardware coincide con el criterio de plataforma NVD."
        return {"result": result, "reason": reason}

    expected_type = ("FIRMWARE", "OS") if cpe[2] == "o" else ("APPLICATION",)
    relevant = [sw for sw in installed_software if sw.get("software_type") in expected_type]
    if not relevant:
        return {"result": INDETERMINATE, "reason": "No hay instalación vigente del tipo de software requerido."}
    matching = []
    unknown = False
    for sw in relevant:
        # Confirmed CPEs must be current for *this* software identity.
        names = [_parse_cpe(row) for row in sw.get("confirmed_cpes", [])]
        names = [name for name in names if name and name[2] == cpe[2]]
        if not names:
            unknown = True
            continue
        if not any(_product_match(cpe, name) for name in names):
            # Without complete inventory attestation, different products
            # cannot prove that the NVD target is absent from the equipment.
            unknown = True
            continue
        matching.append(sw)
    if not matching:
        return {"result": INDETERMINATE,
                "reason": "No hay correspondencia exacta con un CPE vigente confirmado del producto instalado."}

    excluded = []
    for sw in matching:
        result, reason = evaluate_version(sw.get("version", ""), cpe[5], bounds)
        # An official CPE with a fixed version must not contradict the software
        # inventory version even if the identity fingerprint happened to match.
        if any(
            (_parse_cpe(name) or [None] * 13)[5] not in ("*", "-", sw.get("version", ""))
            for name in sw.get("confirmed_cpes", [])
            if _parse_cpe(name) and _product_match(cpe, _parse_cpe(name))
        ):
            result, reason = INDETERMINATE, "Versión del CPE confirmado distinta de la registrada."
        if result == COMPATIBLE:
            return {"result": COMPATIBLE, "reason": reason,
                    "software_installation_id": sw["installation_id"],
                    "installed_version": sw.get("version") or ""}
        if result == INDETERMINATE:
            unknown = True
        else:
            excluded.append(reason)
    if unknown:
        return {"result": INDETERMINATE,
                "reason": "Hay otra instalación o una versión sin correspondencia verificable."}
    return {"result": EXCLUDED, "reason": excluded[0] if excluded else "Criterio excluido por versión.",
            "installed_version": matching[0].get("version") or ""}


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
        {"kind": "CRITERION", **evaluate_criterion(item, hardware_cpes, installed)}
        for item in matches
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
