"""NVD products API (no API key). All outgoing calls go through one worker."""
import json
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
PAGE_SIZE = 100
MAX_PAGES_PER_STRATEGY = 3
MAX_TOTAL_CANDIDATES = 250


class NvdError(Exception):
    pass


class PublicNvdPacer:
    """Single-worker limiter: ≥7 s between ANY requests and 30 s on startup.

    Cross-worker exclusivity comes from PostgreSQL advisory locking in command.
    """
    def __init__(self, wait=time.sleep, clock=time.monotonic, guard=None):
        self.wait, self.clock = wait, clock
        self.guard = guard
        self.not_before = clock() + 30
        self.last_request = None

    def pace(self):
        if self.guard:
            self.guard()
        target = self.not_before
        if self.last_request is not None:
            target = max(target, self.last_request + 7)
        delay = target - self.clock()
        if delay > 0:
            self.wait(delay)
        if self.guard:
            self.guard()
        self.last_request = self.clock()


def _retry_seconds(headers):
    value = headers.get("Retry-After") if headers else None
    try:
        return min(60, max(0, int(value)))
    except (TypeError, ValueError):
        pass
    if value:
        try:
            timestamp = parsedate_to_datetime(value)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            return min(60, max(0, (timestamp - datetime.now(timezone.utc)).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            pass
    return 15


def fetch_page(strategy, parameter, start_index, pacer, *, results_per_page=PAGE_SIZE):
    if strategy not in ("keywordSearch", "cpeMatchString"):
        raise ValueError("Estrategia de consulta inválida.")
    if type(results_per_page) is not int or not 1 <= results_per_page <= 1000:
        raise ValueError("results_per_page debe estar entre 1 y 1000.")
    params = {strategy: parameter, "startIndex": start_index, "resultsPerPage": results_per_page}
    url = NVD_CPE_URL + "?" + urlencode(params)
    request = Request(url, headers={"User-Agent": "VisorOT-CPE-Research/1.0", "Accept": "application/json"})
    for attempt in range(2):
        pacer.pace()
        try:
            with urlopen(request, timeout=20) as response:
                data = json.load(response)
            if not isinstance(data, dict) or not isinstance(data.get("products"), list):
                raise NvdError("Respuesta NVD sin lista de productos válida.")
            return data
        except HTTPError as error:
            if error.code in (429, 500, 502, 503, 504) and attempt == 0:
                pacer.wait(_retry_seconds(error.headers))
                continue
            raise NvdError(f"NVD devolvió HTTP {error.code}.") from error
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            if attempt == 0:
                continue
            raise NvdError(f"No fue posible consultar NVD: {type(error).__name__}.") from error
    raise NvdError("NVD no respondió tras los reintentos.")
