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


def evaluate_version(installed, criterion_version="*", bounds=None, *, software_type=None):
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
        if criterion_version == "*":
            product = "este firmware" if software_type == "FIRMWARE" else "este producto"
            if installed:
                return COMPATIBLE, (
                    f"La condición NVD admite cualquier versión de {product}. "
                    f"La versión instalada ({installed}) cumple esta condición."
                )
            return COMPATIBLE, (
                f"La condición NVD admite cualquier versión de {product}; "
                "no es necesario conocer la versión instalada para comprobarla."
            )
        return COMPATIBLE, "La versión coincide con el criterio."

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


# Two different official NVD CPE product identifiers refer to the Siemens
# S7-1200 CPU 1214C firmware. Never treat this as a general prefix rule:
# https://nvd.nist.gov/products/cpe/detail/696056
# https://nvd.nist.gov/vuln/detail/CVE-2021-44695 (configuration 6)
_SIEMENS_1214C_FIRMWARE_ALIAS = (
    "simatic_s7-1200_cpu_1214c_firmware",
    "s7-1200_cpu_1214c_firmware",
)
_SIEMENS_1214C_HARDWARE = (
    "cpe:2.3:h:siemens:simatic_s7-1200_cpu_1214c:-:*:*:*:*:*:*:*"
)


def _verified_siemens_1214c_firmware_alias(criterion, confirmed, hardware_cpes):
    """Accept one documented product-name variant, never a fuzzy match.

    The confirmed dictionary CPE has version '-' (not applicable). We use it
    solely for *product identity*. A separately inventoried numeric firmware
    version must satisfy the CVE's actual NVD range.
    """
    if (criterion[2:4] != ["o", "siemens"]
            or confirmed[2:4] != ["o", "siemens"]
            or (criterion[4], confirmed[4]) != _SIEMENS_1214C_FIRMWARE_ALIAS
            or criterion[5] != "*" or confirmed[5] != "-"):
        return False
    if _SIEMENS_1214C_HARDWARE not in hardware_cpes:
        return False
    return all(
        criterion[index] == "*" or criterion[index] == confirmed[index]
        for index in range(6, 13)
    )


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

# Explicit CPU identifiers appearing as distinct hardware platforms in the
# NVD configuration branches of CVE-2021-37205. These are enumerated models,
# NOT a fuzzy prefix/product-name match.
_SIEMENS_S7_1500_DOCUMENTED_MODELS = frozenset({
    "1513prof-2", "1513pro-2", "1516pro_f", "1516pro-2", "1518hf-4",
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
    if name in {
        "simatic_et_200sp_open_controller_cpu_1515sp_pc",
        "simatic_et_200sp_open_controller_cpu_1515sp_pc2",
    }:
        # Two explicitly named ET 200SP Open Controller platforms (not a
        # fuzzy family/prefix inference).
        return ("et-200sp-open-controller",
                name.removeprefix("simatic_et_200sp_open_controller_cpu_"))
    if name in {
        "tim_1531_irc", "siplus_tim_1531_irc",
        "simatic_tim_1531_irc", "simatic_siplus_tim_1531_irc",
    }:
        # SIPLUS/SIMATIC prefixes may name the same TIM device family.
        return ("tim-1531-irc", "1531-irc")
    # NVD contains two explicit CPU product IDs with a duplicated "cpu_"
    # token. Preserve the exact CPE spelling rather than fuzzy normalization.
    if name in {
        "simatic_s7-1500_cpu_cpu_1513prof-2",
        "simatic_s7-1500_cpu_cpu_1513pro-2",
    }:
        return ("s7-1500-cpu", name.removeprefix("simatic_s7-1500_cpu_cpu_"))
    # Explicit S7-1500 CPU model; an S7-1500 family/umbrella name is NOT
    # enough to prove device exclusivity on its own.
    if name.startswith("simatic_s7-1500_cpu_"):
        model = name.removeprefix("simatic_s7-1500_cpu_")
        # Names such as cpu_family or cpu_series stay UNKNOWN. NVD also
        # contains a small number of explicit Siemens CPU names outside the
        # regular numeric model pattern; only these enumerated device models
        # qualify for negative platform evidence.
        if model in _SIEMENS_S7_1500_DOCUMENTED_MODELS:
            return ("s7-1500-cpu", model)
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
           distinct_cpes=None, identity_basis=None):
    observation = {"result": result, "reason": reason, "identity": identity}
    if identity_basis:
        observation["identity_basis"] = identity_basis
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
        alias_verified = False
        if candidate is None:
            candidate = next((
                name for name in names
                if _verified_siemens_1214c_firmware_alias(
                    cpe, name, hardware_cpes
                )
            ), None)
            alias_verified = candidate is not None
        if not candidate:
            # Lack of a specific installed software name does not attest an
            # exhaustive software inventory. This is never an absence proof.
            unknown = True
            continue
        matching.append((sw, candidate, alias_verified))

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
    for sw, candidate, alias_verified in matching:
        result, reason = evaluate_version(
            sw.get("version", ""), cpe[5], bounds,
            software_type=sw.get("software_type"),
        )
        if candidate[5] not in ("*", "-", sw.get("version", "")):
            result, reason = INDETERMINATE, (
                "La versión del CPE confirmado difiere de la versión inventariada."
            )
        # The curated alias only proves the product identity, not a version.
        # A missing/unparseable inventoried version never proves its range.
        if alias_verified and _version_tuple(sw.get("version", "")) is None:
            result, reason = INDETERMINATE, (
                "La versión inventariada no es numérica o no está disponible."
            )
        if alias_verified:
            reason += (
                " Identidad de producto verificada mediante equivalencia "
                "específica Siemens 1214C; la versión proviene del inventario."
            )
        if result == COMPATIBLE:
            return _trace(
                COMPATIBLE, reason, identity="MATCHED", cpe=candidate, asset=sw,
                identity_basis=(
                    "CURATED_SIEMENS_1214C_FIRMWARE_PRODUCT_EQUIVALENCE"
                    if alias_verified else None
                ),
            )
        if result == INDETERMINATE:
            unknown = True
        else:
            exclusions.append((sw, candidate, reason))
    if unknown:
        sw, candidate, _alias_verified = matching[0]
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


# This is a scope projection, not an applicability verdict. A configuration
# is foreign only if *every* viable NVD logical path is demonstrably outside
# the evaluated hardware. Unverified identity is never evidence of absence.
SCOPE_PERTINENT = "PERTINENT"
SCOPE_FOREIGN = "FOREIGN"
SCOPE_UNCERTAIN = "UNCERTAIN"
SCOPE_OUT_OF_SCOPE = "OUT_OF_SCOPE"
_SCOPE_UNSCOPED = "UNSCOPED"


def _configuration_scope_state(node):
    """Classify a complete evaluated NVD expression, not an isolated CPE.

    MATCHED hardware and installed-software identities can establish a
    relevant path even when their versions are excluded. DISTINCT hardware,
    and documented PLATFORM_DISTINCT software, establish an impossible path.
    Unmatched software-only alternatives are out of the hardware-anchored
    scope, NOT proof that the software is absent. Unverified hardware
    identities and NOT/unknown operators remain uncertain.
    """
    if not isinstance(node, dict):
        return SCOPE_UNCERTAIN
    if node.get("kind") == "CRITERION":
        identity = node.get("identity")
        if node.get("part") == "h":
            if identity == "MATCHED":
                return SCOPE_PERTINENT
            if identity == "DISTINCT":
                return SCOPE_FOREIGN
            return SCOPE_UNCERTAIN
        if node.get("part") in ("a", "o"):
            if identity == "MATCHED":
                return SCOPE_PERTINENT
            if identity == "PLATFORM_DISTINCT":
                return SCOPE_FOREIGN
            return _SCOPE_UNSCOPED
        return SCOPE_UNCERTAIN

    children = node.get("children")
    operator = node.get("operator")
    if (node.get("kind") != "GROUP" or node.get("negate")
            or operator not in ("AND", "OR")
            or not isinstance(children, list) or not children):
        return SCOPE_UNCERTAIN
    states = [_configuration_scope_state(child) for child in children]
    if operator == "AND":
        if SCOPE_FOREIGN in states:
            return SCOPE_FOREIGN
        if SCOPE_UNCERTAIN in states:
            return SCOPE_UNCERTAIN
        if SCOPE_PERTINENT in states:
            return SCOPE_PERTINENT
        return _SCOPE_UNSCOPED
    if SCOPE_PERTINENT in states:
        return SCOPE_PERTINENT
    if all(state == SCOPE_FOREIGN for state in states):
        return SCOPE_FOREIGN
    if SCOPE_UNCERTAIN in states:
        return SCOPE_UNCERTAIN
    return _SCOPE_UNSCOPED


def _has_confirmed_hardware_anchor(node, *, negated=False):
    """Only positive NVD hardware CPE criteria confirmed for this asset.

    Never infer the anchor from a matched firmware/application CPE, a family
    resemblance, or a hardware criterion under NVD NOT. Retain the entire
    NVD expression for later AND/OR evaluation if an anchor exists.
    """
    if not isinstance(node, dict):
        return False
    if node.get("kind") == "CRITERION":
        return bool(
            not negated and node.get("part") == "h"
            and node.get("identity") == "MATCHED"
            and node.get("matched_cpe")
        )
    if node.get("kind") != "GROUP":
        return False
    if node.get("negate"):
        negated = not negated
    return any(
        _has_confirmed_hardware_anchor(child, negated=negated)
        for child in node.get("children", [])
    )


def select_contextual_configurations(evaluated):
    """Return a read-only, index-preserving scope projection over NVD trees.

    The original configurations and their complete evaluated AND/OR/NOT trees
    are never removed, flattened or modified. The contextual result is an
    additional technical projection; analyst verdicts and verified negative
    proof are resolved separately by cve_applicability.
    """
    rows = evaluated.get("configurations", []) if isinstance(evaluated, dict) else []
    projection = {
        "pertinent_indexes": [],
        "foreign_indexes": [],
        "uncertain_indexes": [],
        "out_of_scope_indexes": [],
        "configurations": [],
    }
    reasons = {
        SCOPE_PERTINENT: (
            "Esta configuración contiene un CPE de hardware confirmado "
            "para el activo seleccionado; se evalúan todas sus condiciones."
        ),
        SCOPE_FOREIGN: (
            "Todas las rutas de esta configuración requieren una plataforma "
            "demostradamente distinta o incompatible."
        ),
        SCOPE_UNCERTAIN: (
            "La relación de una condición de hardware o de una ruta lógica "
            "con este equipo todavía no puede verificarse."
        ),
        SCOPE_OUT_OF_SCOPE: (
            "Configuración exclusivamente de software, sin plataforma de "
            "hardware NVD ni identidad CPE de software instalada acreditada. "
            "No forma parte de la evaluación anclada a este hardware; "
            "no constituye una prueba de ausencia de ese software."
        ),
    }
    bucket = {
        SCOPE_PERTINENT: "pertinent_indexes",
        SCOPE_FOREIGN: "foreign_indexes",
        SCOPE_UNCERTAIN: "uncertain_indexes",
        SCOPE_OUT_OF_SCOPE: "out_of_scope_indexes",
    }
    for index, row in enumerate(rows):
        # Product scope is fixed by a verified hardware CPE anchor, not by
        # standalone software matches or uncertainty about other devices.
        # This limits the operative query to the specific hardware the user
        # selected. Non-matching alternatives remain untouched NVD evidence.
        if _has_confirmed_hardware_anchor(row):
            scope = SCOPE_PERTINENT
        else:
            scope = _configuration_scope_state(row)
            if scope in (SCOPE_PERTINENT, _SCOPE_UNSCOPED):
                scope = SCOPE_OUT_OF_SCOPE
        projection[bucket[scope]].append(index)
        projection["configurations"].append({
            "index": index, "position": index + 1,
            "relation": scope, "reason": reasons[scope],
            "technical_result": row.get("result", INDETERMINATE),
        })
    # Evaluate complete NVD conditions exclusively for configurations
    # containing this confirmed hardware CPE. An unanchored unknown platform
    # is irrelevant to the chosen device, not an extra analyst assignment.
    included = projection["pertinent_indexes"]
    contextual = (
        _combine([rows[index]["result"] for index in included], "OR")
        if included else INDETERMINATE
    )
    projection["evaluated_indexes"] = list(included)
    projection["ignored_foreign_indexes"] = list(projection["foreign_indexes"])
    projection["ignored_out_of_scope_indexes"] = list(
        projection["out_of_scope_indexes"]
    )
    projection["scope_basis"] = "CONFIRMED_HARDWARE_CPE_ONLY"
    projection["result"] = contextual
    return projection


def evaluate_configurations(configurations, hardware_cpes, installed_software):
    """Returns annotated original NVD logic; alternatives are OR at CVE level."""
    if not isinstance(configurations, list) or not configurations:
        return {
            "result": INDETERMINATE,
            "configurations": [],
            "contextual_selection": select_contextual_configurations(
                {"configurations": []}
            ),
            "contextual_result": INDETERMINATE,
        }
    rows = [_evaluate_group(config, hardware_cpes, installed_software)
            for config in configurations]
    result = {"result": _combine([row["result"] for row in rows], "OR"),
              "configurations": rows}
    # Preserve the raw NVD evaluation and expose the contextual projection
    # separately, so audit trails can explain both conclusions.
    result["contextual_selection"] = select_contextual_configurations(result)
    result["contextual_result"] = result["contextual_selection"]["result"]
    return result
