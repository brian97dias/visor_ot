"""NVD CVE 2.0 client for a single legacy CVE or paginated CPE searches.

All requests (including retries) must pass the existing worker's shared
PublicNvdPacer. This module does not schedule work or write to PostgreSQL.
"""
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .nvd_client import NvdError, _retry_seconds

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPERIMENTAL_CVE_ID = "CVE-2021-33540"


def fetch_cve(cve_id, pacer):
    if cve_id != EXPERIMENTAL_CVE_ID:
        raise ValueError("Esta fase solo permite recuperar CVE-2021-33540.")
    request = Request(
        NVD_CVE_URL + "?" + urlencode({"cveId": cve_id}),
        headers={"User-Agent": "VisorOT-CVE-Research/1.0", "Accept": "application/json"},
    )
    for attempt in range(2):
        # Each attempt (including retries) passes through the shared limiter.
        pacer.pace()
        try:
            with urlopen(request, timeout=20) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code in (429, 500, 502, 503, 504) and attempt == 0:
                pacer.wait(_retry_seconds(error.headers))
                continue
            raise NvdError(f"NVD CVE devolvió HTTP {error.code}.") from error
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            if attempt == 0:
                continue
            raise NvdError(
                f"No fue posible consultar NVD CVE: {type(error).__name__}."
            ) from error
    raise NvdError("NVD CVE no respondió tras los reintentos.")


# Conservative page size; the CVE 2.0 API accepts at most 2,000 per page.
CVE_RESULTS_PAGE_SIZE = 500
CVE_RESULTS_MAX_PAGE_SIZE = 2000


def _validate_page_request(cpe_name, start_index, results_per_page):
    if not isinstance(cpe_name, str):
        raise ValueError("Se requiere un nombre CPE 2.3 oficial.")
    parts = cpe_name.split(":")
    if (len(parts) != 13 or parts[:2] != ["cpe", "2.3"]
            or parts[2] not in ("h", "o", "a")
            or any(parts[i] in ("", "*", "-") for i in (3, 4))):
        raise ValueError("Se requiere un cpeName 2.3 con fabricante y producto concretos.")
    if type(start_index) is not int or start_index < 0:
        raise ValueError("startIndex debe ser un entero no negativo.")
    if (type(results_per_page) is not int
            or not 1 <= results_per_page <= CVE_RESULTS_MAX_PAGE_SIZE):
        raise ValueError("resultsPerPage debe estar entre 1 y 2000.")


def fetch_cves_by_cpe(cpe_name, start_index, pacer, *,
                      results_per_page=CVE_RESULTS_PAGE_SIZE):
    """Get ONE NVD CVE page filtered by an official CPE name.

    Intentionally omits isVulnerable: a hardware CPE may be an NVD platform
    condition (vulnerable:false) for a vulnerable firmware.
    """
    _validate_page_request(cpe_name, start_index, results_per_page)
    request = Request(
        NVD_CVE_URL + "?" + urlencode({
            "cpeName": cpe_name,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }),
        headers={"User-Agent": "VisorOT-CVE-Research/1.0",
                 "Accept": "application/json"},
    )
    for attempt in range(2):
        pacer.pace()
        try:
            with urlopen(request, timeout=20) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code in (429, 500, 502, 503, 504) and attempt == 0:
                pacer.wait(_retry_seconds(error.headers))
                continue
            raise NvdError(f"NVD CVE devolvió HTTP {error.code}.") from error
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            if attempt == 0:
                continue
            raise NvdError(
                f"No fue posible consultar NVD CVE: {type(error).__name__}."
            ) from error
    raise NvdError("NVD CVE no respondió tras los reintentos.")


def validated_cve_page(payload, expected_start_index):
    """Validate the pagination envelope; never accept a short empty error as no CVE."""
    if not isinstance(payload, dict):
        raise NvdError("NVD CVE devolvió una respuesta inválida.")
    total = payload.get("totalResults")
    index = payload.get("startIndex")
    page_size = payload.get("resultsPerPage")
    vulnerabilities = payload.get("vulnerabilities")
    if (type(total) is not int or total < 0
            or type(index) is not int or index != expected_start_index
            or type(page_size) is not int
            or not 1 <= page_size <= CVE_RESULTS_MAX_PAGE_SIZE
            or not isinstance(vulnerabilities, list)):
        raise NvdError("NVD CVE devolvió metadatos de paginación inválidos.")
    if (index > total or len(vulnerabilities) > page_size
            or len(vulnerabilities) > max(0, total - index)
            or (index < total and not vulnerabilities)
            or (total == 0 and index != 0)):
        raise NvdError("La página CVE está vacía, incompleta o excede su total.")
    if any(not isinstance(row, dict) or not isinstance(row.get("cve"), dict)
           for row in vulnerabilities):
        raise NvdError("La página CVE contiene registros sin objeto cve.")
    next_index = index + len(vulnerabilities)
    return {
        "start_index": index,
        "next_start_index": next_index,
        "total_results": total,
        "results_per_page": page_size,
        "records": [row["cve"] for row in vulnerabilities],
        "complete": next_index >= total,
    }


def iter_cve_pages_by_cpe(cpe_name, pacer, *, start_index=0,
                          results_per_page=CVE_RESULTS_PAGE_SIZE,
                          fetcher=fetch_cves_by_cpe):
    """Yield checked pages and resumable next_start_index, not one huge response.

    The caller is responsible for writing each validated page plus checkpoint
    atomically. If totals change mid-traversal, raise rather than certify a
    possibly incomplete search. Zero results is a completed *search*, never a
    claim that an inventoried device is not vulnerable.
    """
    _validate_page_request(cpe_name, start_index, results_per_page)
    current_index = start_index
    expected_total = None
    while True:
        payload = fetcher(
            cpe_name, current_index, pacer, results_per_page=results_per_page
        )
        page = validated_cve_page(payload, current_index)
        if expected_total is None:
            expected_total = page["total_results"]
        elif page["total_results"] != expected_total:
            raise NvdError("El total de CVE cambió durante la paginación.")
        if current_index > expected_total:
            raise NvdError("El checkpoint CVE supera el total actual.")
        if current_index == expected_total and current_index > 0:
            raise NvdError("El checkpoint CVE ya está fuera de la búsqueda.")
        yield page
        if page["complete"]:
            break
        if page["next_start_index"] <= current_index:
            raise NvdError("NVD CVE no avanzó la paginación.")
        current_index = page["next_start_index"]
