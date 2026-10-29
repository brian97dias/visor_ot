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



# These are device/model identities, never free-form name similarity.
# Siemens' S7-1200 manuals distinguish the CPU models 1211C, 1212C,
# 1214C, 1215C and 1217C; SiePortal separately identifies fail-safe FCs.
# A bare family CPE remains UNKNOWN because it can include a specific CPU.
_SIEMENS_S7_1200_CPU_MODELS = frozenset({
    "1211c", "1212c", "1212fc", "1214c", "1214fc",
    "1215c", "1215fc", "1217c",
})


def _exclusive_siemens_hardware(product):
    """A strictly identified Siemens *device*, not an implied family match.

    Return None for unknown variants and general family/umbrella products.
    Only distinct, independently enumerated hardware model identities and
    established disjoint product lines can be used as negative evidence.
    """
    name = product.lower()
    for model in _SIEMENS_S7_1200_CPU_MODELS:
        if name == "simatic_s7-1200_cpu_" + model:
            return ("s7-1200-cpu", model)
    if name == "simatic_s7-plcsim_advanced":
        return ("simulator", "s7-plcsim-advanced")
    # Explicit physical controller models in Siemens SSA-838121/NVD.
    # Never classify an arbitrary suffix or a generic family name as a CPU.
    if name in {
        "simatic_drive_controller_cpu_1504d_tf",
        "simatic_drive_controller_cpu_1507d_tf",
    }:
        return ("drive-controller-cpu", name)
    if name == "simatic_et_200sp_open_controller_cpu_1515sp_pc2":
        return ("et-200sp-open-controller", "1515sp-pc2")
    if name in {
        "tim_1531_irc", "siplus_tim_1531_irc",
        "simatic_tim_1531_irc", "simatic_siplus_tim_1531_irc",
    }:
        # SIPLUS/SIMATIC prefixes may name the same TIM device family.
        return ("tim-1531-irc", "1531-irc")
    # Explicit S7-1500 CPU model; an S7-1500 family/umbrella name is NOT
    # enough to prove device exclusivity on its own.
    if name.startswith("simatic_s7-1500_cpu_"):
        model = name.removeprefix("simatic_s7-1500_cpu_")
        # Explicit numeric CPU model only. Names such as cpu_family,
        # cpu_series or other generic products must remain UNKNOWN.
        if re.fullmatch(
            r"1[5-9][0-9]{2}(?:spf|sp|fc|tf|c|f|t|h|r)?"
            r"(?:-[1-9][0-9]?)?(?:_(?:pn|dp))?", model
        ):
            return ("s7-1500-cpu", model)
    return None


def _verified_distinct_product(criterion, confirmed):
    """Prove distinct Siemens CPU devices without treating CPE mismatch as absence.

    Guardrails: confirmed Siemens hardware CPEs only, exact known S7-1200
    model products, explicit S7-1500 CPU models, selected SSA-838121 controllers,
    or the separate PLCSIM
    simulation line. Unknown family aliases and arbitrary vendor products
    are not proof that a hardware platform is absent.
    """
    if (criterion[2] != "h" or confirmed[2] != "h"
            or criterion[3] != "siemens" or confirmed[3] != "siemens"):
        return False
    left = _exclusive_siemens_hardware(criterion[4])
    right = _exclusive_siemens_hardware(confirmed[4])
    return bool(left and right and left != right)


# Supported hardware-only exclusion. Siemens documents S7-1500S Software
# Controller as a PC/IPC-based runtime, not an application executed on a
# physical S7-1200 CPU. Do not generalize this rule to STEP 7 or other apps.
# Documentation: https://www.siemens.com/en-us/products/simatic/s7-1500s-controller/
_PC_ONLY_SOFTWARE_PRODUCTS = frozenset({
    ("a", "siemens", "simatic_s7-1500_software_controller"),
})


def _verified_pc_software_excluded(cpe, confirmed_hardware):
    """Proof of an incompatible runtime platform, NOT an absent inventory row.

    Requires one or more verified hardware CPEs, all corresponding to
    independently enumerated physical S7-1200 CPU models. Unexpected extra
    hardware identities must make the relationship unknown.
    """
    if (cpe[2], cpe[3], cpe[4]) not in _PC_ONLY_SOFTWARE_PRODUCTS:
        return False
    return bool(confirmed_hardware) and all(
        name[2] == "h" and name[3] == "siemens"
        and (_exclusive_siemens_hardware(name[4]) or (None,))[0]
        == "s7-1200-cpu"
        for name in confirmed_hardware
    )


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
                "Dispositivo/plataforma Siemens distintos demostrados por modelos "
                "o líneas de producto explícitas; no se infiere ausencia de software.",
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
        # An explicitly incompatible software runtime can be excluded only
        # with its documented platform prerequisite and confirmed physical CPU.
        # Other software remains UNKNOWN, never automatically absent.
        hw_names = [_parse_cpe(name) for name in hardware_cpes]
        hw_names = [name for name in hw_names if name and name[2] == "h"]
        if _verified_pc_software_excluded(cpe, hw_names):
            return _trace(
                EXCLUDED,
                "SIMATIC S7-1500 Software Controller requiere un IPC; "
                "no se ejecuta en una CPU física S7-1200.",
                identity="PLATFORM_DISTINCT", distinct_cpes=hw_names,
            )
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
        # No installed CPE matched: distinguish only a documented impossible
        # platform, not absence of an arbitrary software product.
        hw_names = [_parse_cpe(name) for name in hardware_cpes]
        hw_names = [name for name in hw_names if name and name[2] == "h"]
        if _verified_pc_software_excluded(cpe, hw_names):
            return _trace(
                EXCLUDED,
                "SIMATIC S7-1500 Software Controller requiere un IPC; "
                "no se ejecuta en una CPU física S7-1200.",
                identity="PLATFORM_DISTINCT", distinct_cpes=hw_names,
            )
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
