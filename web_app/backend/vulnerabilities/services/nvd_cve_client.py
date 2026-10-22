"""Single-CVE NVD API 2.0 client; only called behind the existing worker lock.

Shares NvdError, retry policy and the SAME PublicNvdPacer instance used for CPE.
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
