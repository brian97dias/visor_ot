from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from analyzer import analyze_pcap
from catalog import (
    get_pcap_by_id,
    list_pcaps,
)
from output import save_output


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
        "id": pcap_path.stem,
        "filename": pcap_path.name,
        "status": "ANALYZED",
        "interfaces_detected": len(
            interfaces
        ),
        "communications_detected": len(
            communications
        ),
    }