"""Validate search modes for the interface inventory only."""

from ipaddress import ip_address

from rest_framework.exceptions import ValidationError


def validate_interface_search(raw_search, match_mode):
    if match_mode not in ("PARTIAL", "EXACT_IP"):
        raise ValidationError({"match_mode": "Usa PARTIAL o EXACT_IP."})

    search = str(raw_search).strip()[:100]
    if match_mode == "EXACT_IP" and search:
        try:
            search = str(ip_address(search))
        except ValueError as error:
            raise ValidationError({
                "search": "La coincidencia exacta requiere una dirección IP completa."
            }) from error

    return search, match_mode
