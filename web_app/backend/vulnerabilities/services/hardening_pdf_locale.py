"""Spanish presentation of stored OT diagnosis values (no re-assessment)."""

SEVERITY = {
    "CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media",
    "LOW": "Baja", "NONE": "Ninguna", "UNKNOWN": "No determinada",
}
CRITICALITY = SEVERITY
ROLES = {
    "PLC": "PLC", "IO_MODULE": "Módulo de entradas/salidas",
    "SWITCH": "Conmutador de red", "ROUTER": "Enrutador",
    "FIREWALL": "Cortafuegos", "GATEWAY": "Pasarela",
    "HMI": "Interfaz hombre-máquina", "OTHER": "Otro",
}
SOFTWARE_TYPES = {
    "FIRMWARE": "Firmware", "OS": "Sistema operativo",
    "APPLICATION": "Aplicación",
}
CLASSIFICATIONS = {
    "NO_CLASIFICADA": "Sin clasificar",
    "NO_AUTORIZADA": "No autorizada",
    "AUTORIZADA": "Autorizada",
}
ASSESSMENT = {
    "APPLIES": "Aplica", "APPLIES_CONDITIONAL": "Aplicabilidad condicionada",
    "PENDING_REVIEW": "Pendiente de revisión", "NOT_APPLICABLE": "No aplica",
}
EVALUATOR = {
    "SYSTEM": "Sistema (evaluación automática)",
    "ANALYST": "Analista (evaluación humana)",
}
NETWORK_STATUSES = {
    "INSUFFICIENT_ATTRIBUTION_EVIDENCE": "Sin comunicaciones atribuibles verificadas en este corte.",
    "SEARCH_LIMIT_REACHED_NO_ATTRIBUTION": "Búsqueda limitada sin atribución confirmada.",
    "IP_BINDING_LIMIT_REACHED": "Demasiadas IP candidatas: no se realizó atribución.",
    "NOT_COLLECTED": "Atribución de comunicaciones no realizada.",
}
METRIC_LABELS = {
    "attackVector": "Vector de ataque",
    "attackComplexity": "Complejidad del ataque",
    "privilegesRequired": "Privilegios requeridos",
    "userInteraction": "Interacción del usuario",
    "scope": "Alcance",
    "confidentialityImpact": "Impacto en confidencialidad",
    "integrityImpact": "Impacto en integridad",
    "availabilityImpact": "Impacto en disponibilidad",
    "accessVector": "Vector de acceso",
    "accessComplexity": "Complejidad de acceso",
    "authentication": "Autenticación",
}
METRIC_VALUES = {
    "NETWORK": "A través de la red",
    "ADJACENT_NETWORK": "Desde una red adyacente",
    "LOCAL": "Acceso local",
    "PHYSICAL": "Acceso físico",
    "LOW": "Baja",
    "HIGH": "Alta",
    "MEDIUM": "Media",
    "NONE": "No requeridos",
    "REQUIRED": "Requerida",
    "UNCHANGED": "Sin cambios",
    "CHANGED": "Modificado",
    "SINGLE": "Una autenticación",
    "MULTIPLE": "Varias autenticaciones",
    "COMPLETE": "Completo",
    "PARTIAL": "Parcial",
    "USER": "Usuario",
}


def label(value, mapping):
    if value is None or value == "":
        return "No registrado"
    return mapping.get(str(value).upper(), str(value))


def metric_value(key, value):
    if value is None or value == "":
        return "No registrado"
    val = str(value).upper()
    if val == "NONE":
        if key in ("confidentialityImpact", "integrityImpact", "availabilityImpact"):
            return "Sin impacto"
        if key == "userInteraction":
            return "No requerida"
        return "No requeridos"
    if key == "privilegesRequired" and val in ("LOW", "HIGH"):
        return "Bajos" if val == "LOW" else "Altos"
    if key == "authentication" and val == "NONE":
        return "Sin autenticación previa"
    return METRIC_VALUES.get(val, str(value))


def interpret_cvss(cvss):
    """Conservative reading of available base metrics; not an attack path."""
    metrics = cvss.get("metrics") if isinstance(cvss, dict) else None
    if not isinstance(metrics, dict) or not metrics:
        return None
    chunks = []
    vector = metrics.get("attackVector") or metrics.get("accessVector")
    vector_intro = {
        "NETWORK": "a través de la red",
        "ADJACENT_NETWORK": "desde una red adyacente",
        "LOCAL": "con acceso local",
        "PHYSICAL": "con acceso físico",
    }.get(str(vector).upper())
    if vector_intro:
        chunks.append("El vector CVSS describe una posibilidad de ataque " + vector_intro)
    complexity = metrics.get("attackComplexity") or metrics.get("accessComplexity")
    if complexity in ("LOW", "HIGH"):
        chunks.append("con complejidad " + ("baja" if complexity == "LOW" else "alta"))
    privileges = metrics.get("privilegesRequired")
    if privileges == "NONE":
        chunks.append("sin requerir privilegios previos")
    elif privileges in ("LOW", "HIGH"):
        chunks.append("con privilegios " + ("bajos" if privileges == "LOW" else "altos"))
    interaction = metrics.get("userInteraction")
    if interaction == "NONE":
        chunks.append("sin interacción de otra persona")
    elif interaction == "REQUIRED":
        chunks.append("con interacción de otra persona")
    impacts = []
    for key, name in (
        ("confidentialityImpact", "la confidencialidad"),
        ("integrityImpact", "la integridad"),
        ("availabilityImpact", "la disponibilidad"),
    ):
        level = metrics.get(key)
        if level in ("LOW", "HIGH"):
            impacts.append("impacto " + ("bajo" if level == "LOW" else "alto") + " en " + name)
    if not chunks and not impacts:
        return None
    message = ", ".join(chunks).rstrip(".") + "." if chunks else ""
    if impacts:
        message += " El impacto potencial reportado es: " + "; ".join(impacts) + "."
    return message.strip() + (
        " Esto no demuestra que exista una ruta accesible ni que se haya explotado "
        "la vulnerabilidad en este entorno."
    )
