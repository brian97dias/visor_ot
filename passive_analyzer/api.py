from typing import Literal
import json

from fastapi.responses import StreamingResponse


from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from analyzer import analyze_pcap
from catalog import (
    get_pcap_by_id,
    list_pcaps,
)
from output import save_output, load_output, get_analysis_hash
from config import OUTPUT_DIRECTORY
from pcap_identity import get_relative_path
from pcap_identity import get_pcap_id


app = FastAPI(
    title="Visual OT Passive Analyzer",
    version="0.1.0",
)


class PcapSummary(BaseModel):
    id: str
    filename: str
    relative_path: str
    status: Literal[
        "PENDING",
        "ANALYZED",
    ]
    analysis_hash: str | None = None


class PcapListResponse(BaseModel):
    pcaps: list[PcapSummary]


class PcapAnalysisResponse(BaseModel):
    id: str
    filename: str
    status: Literal["ANALYZED"]
    interfaces_detected: int
    communications_detected: int


@app.get(
    "/api/v1/pcaps/",
    response_model=PcapListResponse,
)
def get_pcaps():

    return {
        "pcaps": list_pcaps()
    }


@app.post(
    "/api/v1/pcaps/{pcap_id}/analyze",
    response_model=PcapAnalysisResponse,
)
def analyze_pcap_endpoint(
    pcap_id: str,
):

    pcap_path = get_pcap_by_id(
        pcap_id
    )


    if pcap_path is None:

        raise HTTPException(
            status_code=404,
            detail="El PCAP solicitado no existe.",
        )


    try:

        interfaces, communications = (
            analyze_pcap(
                pcap_path
            )
        )


        save_output(
            pcap_path,
            interfaces,
            communications,
        )


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Ocurrió un error durante "
                "el análisis del PCAP."
            ),
        ) from error


    return {
        "id": get_pcap_id(
            pcap_path
            ),
        "filename": pcap_path.name,
        "status": "ANALYZED",
        "interfaces_detected": len(
            interfaces
        ),
        "communications_detected": len(
            communications
        ),
    }

@app.get(
    "/api/v1/pcaps/{pcap_id}/analysis",
)
def get_pcap_analysis(
    pcap_id: str,
):

    pcap_path = get_pcap_by_id(
        pcap_id
    )


    if pcap_path is None:

        raise HTTPException(
            status_code=404,
            detail="El PCAP solicitado no existe.",
        )


    try:

        analysis = load_output(
            pcap_id
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "No fue posible leer "
                "el resultado del análisis."
            ),
        ) from error


    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "El PCAP todavía no tiene "
                "un análisis disponible."
            ),
        )


    return analysis


@app.get("/api/v1/pcaps/{pcap_id}/analysis/import-manifest")
def get_analysis_import_manifest(pcap_id: str):
    """Lightweight identity and hash for streaming imports."""
    pcap_path = get_pcap_by_id(pcap_id)
    if pcap_path is None:
        raise HTTPException(status_code=404, detail="El PCAP solicitado no existe.")
    output_file = OUTPUT_DIRECTORY / f"{pcap_id}.json"
    if not output_file.is_file():
        raise HTTPException(status_code=404, detail="El análisis no existe.")
    return {
        "schema_version": "0.2",
        "capture": {
            "pcap_id": pcap_id,
            "filename": pcap_path.name,
            "relative_path": get_relative_path(pcap_path),
        },
        "analysis_hash": get_analysis_hash(pcap_id),
    }


@app.get("/api/v1/pcaps/{pcap_id}/analysis/stream")
def stream_analysis_import(pcap_id: str):
    """Stream per-observation NDJSON instead of a giant JSON object."""
    if get_pcap_by_id(pcap_id) is None:
        raise HTTPException(status_code=404, detail="El PCAP solicitado no existe.")
    path = OUTPUT_DIRECTORY / f"{pcap_id}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="El análisis no existe.")
    try:
        import ijson
    except ImportError as error:
        raise HTTPException(
            status_code=503,
            detail="Falta ijson en el entorno del analizador: pip install ijson.",
        ) from error

    def rows():
        for kind, prefix in (("interface", "interfaces.item"),
                             ("communication", "communications.item")):
            with path.open("rb") as handle:
                for item in ijson.items(handle, prefix):
                    yield json.dumps(
                        {"type": kind, "data": item},
                        ensure_ascii=False, separators=(",", ":"),
                    ) + "\n"

    return StreamingResponse(rows(), media_type="application/x-ndjson")


@app.get("/api/v1/pcaps/{pcap_id}/analysis/observations")
def get_analysis_observations(
    pcap_id: str,
    type: Literal["interfaces", "communications"] = "interfaces",
    page: int = Query(default=1, ge=1),
    search: str = Query(default="", max_length=100),
    min_packets: int = Query(default=1, ge=1),
):
    """Paginate a potentially huge file without json.load() or large lists."""
    pcap_path = get_pcap_by_id(pcap_id)
    if pcap_path is None:
        raise HTTPException(status_code=404, detail="El PCAP solicitado no existe.")
    path = OUTPUT_DIRECTORY / f"{pcap_id}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="El análisis no está disponible.")
    try:
        import ijson
    except ImportError as error:
        raise HTTPException(
            status_code=503, detail="Falta ijson en el analizador: pip install ijson."
        ) from error

    needle = search.strip().lower()
    start = (page - 1) * 25
    end = start + 25
    prefix = "interfaces.item" if type == "interfaces" else "communications.item"
    count = 0
    results = []
    from collections import deque
    last_page_rows = deque(maxlen=25)

    # Count all records once when browsing, but keep only the selected page
    # and a 25-row fallback if the user requests a page beyond the end.
    with path.open("rb") as handle:
        for item in ijson.items(handle, prefix):
            if type == "interfaces":
                matched = (
                    not needle
                    or needle in item.get("mac", "").lower()
                    or any(needle in ip.lower() for ip in item.get("ips", []))
                )
            else:
                matched = (
                    (not needle or
                     any(needle in str(item.get(key) or "").lower()
                         for key in ("client_ip", "server_ip",
                                     "transport_protocol", "service"))
                     or (needle.isdecimal()
                         and str(item.get("service_port")) == needle))
                    and item.get("packet_count", 0) >= min_packets
                )
            if not matched:
                continue
            if start <= count < end:
                results.append(item)
            count += 1
            last_page_rows.append(item)

    page_size = 25
    total_pages = max(1, (count + page_size - 1) // page_size)
    current_page = min(page, total_pages)
    if current_page != page:
        tail = count % page_size or (page_size if count else 0)
        results = list(last_page_rows)[-tail:] if tail else []

    # For the summary, count the other array without loading it in RAM.
    other = "communications.item" if type == "interfaces" else "interfaces.item"
    other_count = 0
    with path.open("rb") as handle:
        for _ in ijson.items(handle, other):
            other_count += 1
    return {
        "capture": {
            "pcap_id": pcap_id,
            "filename": pcap_path.name,
            "relative_path": get_relative_path(pcap_path),
        },
        "schema_version": "0.2",
        "interfaces_detected": count if type == "interfaces" and not needle
                               else other_count if type == "communications" else 0,
        "communications_detected": count if type == "communications" and not needle
                                  and min_packets == 1
                                  else other_count if type == "interfaces" else 0,
        "count": count,
        "page": current_page,
        "page_size": page_size,
        "results": results,
    }
