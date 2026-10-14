from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from analyzer import analyze_pcap
from catalog import (
    get_pcap_by_id,
    list_pcaps,
)
from output import save_output, load_output
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

@app.get("/api/v1/pcaps/{pcap_id}/analysis/observations")
def get_analysis_observations(
    pcap_id: str,
    type: Literal["interfaces", "communications"] = "interfaces",
    page: int = Query(default=1, ge=1),
    search: str = Query(default="", max_length=100),
    min_packets: int = Query(default=1, ge=1),
):
    if get_pcap_by_id(pcap_id) is None:
        raise HTTPException(status_code=404, detail="El PCAP solicitado no existe.")
    analysis = load_output(pcap_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="El análisis no está disponible.")

    interfaces = analysis.get("interfaces", [])
    communications = analysis.get("communications", [])
    entries = interfaces if type == "interfaces" else communications
    needle = search.strip().lower()

    if type == "interfaces" and needle:
        entries = [
            item for item in entries
            if needle in item.get("mac", "").lower()
            or any(needle in ip.lower() for ip in item.get("ips", []))
        ]
    elif type == "communications":
        if needle:
            entries = [
                item for item in entries
                if (
                    any(
                        needle in str(item.get(field) or "").lower()
                        for field in (
                            "client_ip", "server_ip", "transport_protocol", "service"
                        )
                    )
                    or (needle.isdecimal() and str(item.get("service_port")) == needle)
                )
            ]
        if min_packets > 1:
            entries = [item for item in entries if item.get("packet_count", 0) >= min_packets]

    page_size = 25
    count = len(entries)
    total_pages = max(1, (count + page_size - 1) // page_size)
    current_page = min(page, total_pages)
    start = (current_page - 1) * page_size

    return {
        "capture": analysis.get("capture"),
        "schema_version": analysis.get("schema_version"),
        "interfaces_detected": len(interfaces),
        "communications_detected": len(communications),
        "count": count,
        "page": current_page,
        "page_size": page_size,
        "results": entries[start:start + page_size],
    }
