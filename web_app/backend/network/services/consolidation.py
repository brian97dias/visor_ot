"""Consolidate passive communication evidence without loading whole captures.

The original implementation issued one get_or_create and one save per observed
flow. Large PCAPs can contain hundreds of thousands of observations; process
small batches using bulk inserts, selects and updates instead.
"""
from itertools import islice
from django.db import transaction
from django.db.models import Q
from network.models import Communication

BATCH_SIZE = 100  # Compatible with SQLite's parameter limit in tests.


def _batches(observations, size):
    iterator = (
        observations.iterator(chunk_size=size)
        if hasattr(observations, "iterator")
        else iter(observations)
    )
    while True:
        batch = list(islice(iterator, size))
        if not batch:
            return
        yield batch


def _signature(item):
    return (
        item.client_ip, item.server_ip,
        item.transport_protocol.upper(), item.service_port,
    )


def consolidate_communication_observations(observations, *, batch_size=BATCH_SIZE):
    """Idempotently link persisted observations to canonical communications.

    Preserve an analyst's classification and all existing services. Updates to
    links and rows occur in bounded batches, not one SQL query per observation.
    """
    if not 1 <= batch_size <= 100:
        raise ValueError("batch_size debe estar entre 1 y 100.")

    linked = 0
    created = 0
    for batch in _batches(observations, batch_size):
        unique = {}
        for observation in batch:
            unique.setdefault(_signature(observation), observation)

        condition = Q(pk__isnull=True)
        for src, dst, transport, port in unique:
            condition |= Q(
                source_ip=src, destination_ip=dst,
                transport_protocol=transport, service_port=port,
            )
        existing = {_signature(row): row for row in Communication.objects.filter(condition)}
        missing = [
            Communication(
                source_ip=key[0], destination_ip=key[1],
                transport_protocol=key[2], service_port=key[3],
                service=unique[key].service,
            )
            for key in unique if key not in existing
        ]
        if missing:
            # Ignore conflicts caused by concurrent imports; resolve the
            # canonical IDs with a new SELECT before linking observations.
            Communication.objects.bulk_create(
                missing, batch_size=batch_size, ignore_conflicts=True
            )
            existing = {
                _signature(row): row
                for row in Communication.objects.filter(condition)
            }
            created += len(missing)  # Only used as an informational estimate.

        services_to_update = {}
        links_to_update = []
        for observation in batch:
            communication = existing[_signature(observation)]
            if not communication.service and observation.service:
                communication.service = observation.service
                services_to_update[communication.pk] = communication
            if observation.communication_id != communication.pk:
                observation.communication_id = communication.pk
                links_to_update.append(observation)
        if services_to_update:
            Communication.objects.bulk_update(
                list(services_to_update.values()), ["service"], batch_size=batch_size
            )
        if links_to_update:
            observations_model = batch[0].__class__
            observations_model.objects.bulk_update(
                links_to_update, ["communication"], batch_size=batch_size
            )
            linked += len(links_to_update)

    return {"communications_created": created, "observations_linked": linked}


def consolidate_all_observations():
    from ingestion.models import CommunicationObservation
    return consolidate_communication_observations(
        CommunicationObservation.objects.all()
    )
