"""Reusable search criteria for the Communications API and benchmark."""

from ipaddress import ip_address

from django.db.models import Q
from rest_framework.exceptions import ValidationError

from .name_search import device_name_filter


MATCH_MODES = ("PARTIAL", "EXACT_IP")


def build_communication_search_criteria(search, match_mode="PARTIAL"):
    """Preserve generic partial search, or restrict to exact source/dest IP."""
    if match_mode not in MATCH_MODES:
        raise ValidationError({"match_mode": "Elige PARTIAL o EXACT_IP."})

    if match_mode == "EXACT_IP":
        try:
            address = str(ip_address(search.strip()))
        except (ValueError, AttributeError):
            raise ValidationError({
                "search": "Ingresa una dirección IPv4 o IPv6 completa y válida."
            })
        return Q(source_ip=address) | Q(destination_ip=address)

    criteria = (
        Q(source_ip__icontains=search)
        | Q(destination_ip__icontains=search)
        | Q(transport_protocol__icontains=search)
        | Q(service__icontains=search)
    )
    if search.isdecimal():
        criteria |= Q(service_port=int(search))

    by_name = device_name_filter(search)
    if by_name is not None:
        criteria |= by_name

    return criteria
