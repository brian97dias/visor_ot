"""Reusable search criteria for the Communications API and benchmark."""

from django.db.models import Q

from .name_search import device_name_filter


def build_communication_search_criteria(search):
    """Preserve IP, protocol, service and port searches alongside device names."""
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
