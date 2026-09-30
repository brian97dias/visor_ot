from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from catalog import list_pcaps


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


@app.get(
    "/api/v1/pcaps/",
    response_model=PcapListResponse,
)
def get_pcaps():

    return {
        "pcaps": list_pcaps()
    }