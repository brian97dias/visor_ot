import requests

from django.conf import settings

from urllib.parse import quote

class PassiveAnalyzerUnavailable(Exception):
    pass

class PassiveAnalyzerPcapNotFound(
    Exception
):
    pass

def get_pcaps():

    base_url = settings.PASSIVE_ANALYZER_URL.rstrip("/")

    url = f"{base_url}/api/v1/pcaps/"

    try:
        response = requests.get(
            url,
            timeout=5,
        )

        response.raise_for_status()

    except requests.RequestException as error:
        raise PassiveAnalyzerUnavailable(
            "No fue posible comunicarse con el Passive Analyzer."
        ) from error


    try:
        data = response.json()

    except ValueError as error:
        raise PassiveAnalyzerUnavailable(
            "El Passive Analyzer devolvió una respuesta inválida."
        ) from error


    if (
        not isinstance(data, dict)
        or not isinstance(data.get("pcaps"), list)
    ):
        raise PassiveAnalyzerUnavailable(
            "La respuesta del Passive Analyzer "
            "no tiene el formato esperado."
        )



    return data

def analyze_pcap(pcap_id):

    base_url = (
        settings
        .PASSIVE_ANALYZER_URL
        .rstrip("/")
    )


    encoded_pcap_id = quote(
        pcap_id,
        safe="",
    )


    url = (
        f"{base_url}"
        f"/api/v1/pcaps/"
        f"{encoded_pcap_id}"
        f"/analyze"
    )


    try:

        response = requests.post(
            url,
            timeout=300,
        )


    except requests.RequestException as error:

        raise PassiveAnalyzerUnavailable(
            "No fue posible comunicarse "
            "con el Passive Analyzer."
        ) from error


    if response.status_code == 404:

        raise PassiveAnalyzerPcapNotFound(
            "El PCAP solicitado no existe "
            "en el Passive Analyzer."
        )


    try:
        response.raise_for_status()

    except requests.RequestException as error:

        raise PassiveAnalyzerUnavailable(
            "El Passive Analyzer no pudo "
            "completar el análisis."
        ) from error


    try:

        data = response.json()

    except ValueError as error:

        raise PassiveAnalyzerUnavailable(
            "El Passive Analyzer devolvió "
            "una respuesta inválida."
        ) from error


    return data