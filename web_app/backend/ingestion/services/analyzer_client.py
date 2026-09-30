import requests

from django.conf import settings


class PassiveAnalyzerUnavailable(Exception):
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