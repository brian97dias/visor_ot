"""Consolidate observed MACs into managed network-interface identities.

The PCAP observation is evidence. It must not be modified or removed based on
identity inference; only its optional foreign key is filled.
"""

from dataclasses import dataclass

from django.core.exceptions import ValidationError
from django.db import transaction

from .models import NetworkInterface
from .models.network_interface import normalize_mac


@dataclass
class InterfaceConsolidationStats:
    scanned: int = 0
    created: int = 0
    reused: int = 0
    linked: int = 0
    already_linked: int = 0
    skipped_invalid_mac: int = 0
    conflicting_links: int = 0


@transaction.atomic
def consolidate_interface_observations(observations, *, batch_size=500):
    """Associate persisted InterfaceObservation rows by their canonical MAC.

    - One NetworkInterface per valid unique MAC (including across ingestions).
    - Do not assign hardware, users or manually declared IPs.
    - Never overwrite an observation FK that points to another identity.
    - Invalid/unknown MAC evidence remains stored and unlinked.
    - Repeated execution is idempotent.
    """
    if batch_size < 1:
        raise ValueError("batch_size debe ser mayor que cero.")

    stats = InterfaceConsolidationStats()
    cache = {}
    updates = []

    queryset = observations.only(
        "id", "mac", "network_interface_id"
    ).order_by("id")

    for observation in queryset.iterator(chunk_size=batch_size):
        stats.scanned += 1

        try:
            canonical_mac = normalize_mac(observation.mac)
        except ValidationError:
            stats.skipped_invalid_mac += 1
            continue

        if canonical_mac is None:
            stats.skipped_invalid_mac += 1
            continue

        interface_id = cache.get(canonical_mac)
        if interface_id is None:
            interface, created = NetworkInterface.objects.get_or_create(
                mac=canonical_mac
            )
            interface_id = interface.pk
            cache[canonical_mac] = interface_id
            if created:
                stats.created += 1
            else:
                stats.reused += 1

        if observation.network_interface_id == interface_id:
            stats.already_linked += 1
        elif observation.network_interface_id is not None:
            stats.conflicting_links += 1
        else:
            observation.network_interface_id = interface_id
            updates.append(observation)

        if len(updates) >= batch_size:
            observations.model.objects.bulk_update(
                updates, ["network_interface"], batch_size=batch_size
            )
            stats.linked += len(updates)
            updates.clear()

    if updates:
        observations.model.objects.bulk_update(
            updates, ["network_interface"], batch_size=batch_size
        )
        stats.linked += len(updates)

    return stats
