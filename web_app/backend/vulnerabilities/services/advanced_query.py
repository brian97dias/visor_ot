"""Restricted CPE search requests for the existing single-worker NVD queue.

Never accept URLs or arbitrary NVD API arguments from the client. The
hardware identity remains the source of truth for permitted manufacturers.
"""
import re

from .identity import normalized, vendor_variants

MAX_ADVANCED_PAGES = 3
MAX_ADVANCED_START_INDEX = 10000
MAX_KEYWORD_LENGTH = 120

_CPE_PREFIX = re.compile(
    r"^cpe:2\.3:h:([a-z0-9_-]{2,80})(?::([a-z0-9._-]{1,120}\*?))?$"
)
_KEYWORD = re.compile(r"^[\w\s./-]+$", re.UNICODE)


def validate_advanced_query(identity, request):
    """Return a normalized, bounded query or raise ValueError.

    Pure validation shared by HTTP enqueue and worker execution. In particular,
    a CPE prefix must identify HARDWARE from one known vendor alias.
    """
    if not isinstance(request, dict):
        raise ValueError("Proporciona una consulta avanzada válida.")
    allowed = {"strategy", "parameter", "start_index", "max_pages"}
    if set(request) - allowed:
        raise ValueError("La consulta incluye parámetros no admitidos.")
    strategy = request.get("strategy")
    parameter = request.get("parameter")
    start_index = request.get("start_index", 0)
    max_pages = request.get("max_pages", 1)

    if strategy not in ("keywordSearch", "cpeMatchString"):
        raise ValueError("Usa keywordSearch o cpeMatchString.")
    if not isinstance(parameter, str):
        raise ValueError("El parámetro de búsqueda debe ser texto.")
    parameter = parameter.strip()
    if not isinstance(start_index, int) or isinstance(start_index, bool) or not (
        0 <= start_index <= MAX_ADVANCED_START_INDEX and start_index % 100 == 0
    ):
        raise ValueError("start_index debe ser un múltiplo de 100 entre 0 y 10000.")
    if not isinstance(max_pages, int) or isinstance(max_pages, bool) or not 1 <= max_pages <= MAX_ADVANCED_PAGES:
        raise ValueError("max_pages debe estar entre 1 y 3.")
    manufacturer = normalized(identity.get("manufacturer"))
    if not manufacturer:
        raise ValueError("El activo requiere fabricante para consultar NVD.")

    if strategy == "keywordSearch":
        if not 3 <= len(parameter) <= MAX_KEYWORD_LENGTH or not _KEYWORD.fullmatch(parameter):
            raise ValueError("Ingresa entre 3 y 120 caracteres de texto sin URLs ni caracteres especiales.")
        tokens = [
            normalized(token) for token in re.split(r"[\s_/-]+", identity.get("manufacturer", ""))
        ]
        aliases = [normalized(x) for x in vendor_variants(identity.get("manufacturer"))]
        term = normalized(parameter)
        if not any(len(x) >= 4 and x in term for x in tokens + aliases):
            raise ValueError("La búsqueda textual debe incluir el fabricante o una palabra reconocible de su nombre.")
        parameter = " ".join(parameter.split())
    else:
        # CPE name match strings are *prefixes*, not arbitrary URLs or full API
        # queries. The strict grammar also prevents injection of other CPE parts.
        match = _CPE_PREFIX.fullmatch(parameter.lower())
        vendors = {normalized(x) for x in vendor_variants(identity.get("manufacturer"))}
        if not match or normalized(match.group(1)) not in vendors:
            raise ValueError("Utiliza un prefijo CPE de hardware de un fabricante conocido para este activo.")
        parameter = parameter.lower()

    return {
        "strategy": strategy, "parameter": parameter,
        "start_index": start_index, "max_pages": max_pages,
    }
