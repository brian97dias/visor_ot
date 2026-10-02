import requests

from django.conf import settings

from urllib.parse import quote

class PassiveAnalyzerUnavailable(Exception):
    pass

class PassiveAnalyzerPcapNotFound(
    Exception
):
    pass

class PassiveAnalyzerAnalysisNotFound(
    Exception
):
    pass

def get_pcap_analysis(pcap_id):

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
        f"/analysis"
    )


    try:

        response = requests.get(
            url,
            timeout=(5, 30),
        )


    except requests.RequestException as error:

        raise PassiveAnalyzerUnavailable(
            "No fue posible comunicarse "
            "con el Passive Analyzer."
        ) from error


    if response.status_code == 404:

        raise PassiveAnalyzerAnalysisNotFound(
            "El análisis solicitado "
            "no está disponible."
        )


    try:

        response.raise_for_status()

    except requests.RequestException as error:

        raise PassiveAnalyzerUnavailable(
            "El Passive Analyzer no pudo "
            "recuperar el análisis."
        ) from error


    try:

        data = response.json()

    except ValueError as error:

        raise PassiveAnalyzerUnavailable(
            "El Passive Analyzer devolvió "
            "un análisis inválido."
        ) from error


    if (
        not isinstance(data, dict)
        or "capture" not in data
        or "interfaces" not in data
        or "communications" not in data
    ):

        raise PassiveAnalyzerUnavailable(
            "El análisis no tiene "
            "el formato esperado."
        )


    return data

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
            timeout=(5, 900),
        )


    except requests.Timeout as error:

        raise PassiveAnalyzerUnavailable(
            "El Passive Analyzer excedió el tiempo "
            "máximo de procesamiento."
        ) from error

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