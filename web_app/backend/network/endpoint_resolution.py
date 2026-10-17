"""Conservative attribution of communication endpoints to managed OT hardware.

Only active communication and ARP-derived interface observations are considered.
The ARP binding was aggregated over a whole PCAP, not timestamped per packet;
an attribution is therefore supported by capture evidence, not temporal proof.
"""

from collections import defaultdict

from django.core.exceptions import ValidationError

from assets.models.network_interface import normalize_mac
from ingestion.models import (
    CommunicationObservation, Ingestion, InterfaceObservation,
)


def canonical_mac(mac):
    try:
        return normalize_mac(mac)
    except ValidationError:
        return None


def ambiguous_endpoint(ip, evidence, side, ip_bindings):
    """Report candidates without upgrading an ambiguous endpoint to identified.

    Candidates require an IP/MAC ARP binding in the *same active ingestion*
    as a contributing communication observation. Other ARP bindings for that
    IP in that ingestion remain candidates even if the communication observed
    only one of those MACs. No unrelated capture/IP is considered.
    """
    candidates = {}
    for observation in evidence:
        observed = observation.get(side + "_macs")
        if not isinstance(observed, list) or not observed:
            continue
        observed_macs = {canonical_mac(mac) for mac in observed}
        observed_macs.discard(None)
        bindings = ip_bindings.get((observation["ingestion_id"], ip), {})
        if not observed_macs.intersection(bindings):
            continue

        for mac, identity in bindings.items():
            if not mac:
                continue
            interface_id, asset_id, asset_name, role = (
                identity if identity is not None else (None, None, None, None)
            )
            # Retain separate MAC evidence even when two interfaces map to
            # the same asset. Deduplicating the *label* belongs to the UI.
            key = (mac, interface_id, asset_id)
            candidates[key] = {
                "mac": mac,
                "interface_id": interface_id,
                "asset_id": asset_id,
                "asset_name": asset_name,
            }

    return {
        "status": "AMBIGUOUS",
        "identity": None,
        "candidates": [
            candidates[key] for key in sorted(
                candidates,
                key=lambda item: (
                    item[0],
                    item[1] if item[1] is not None else -1,
                    item[2] if item[2] is not None else -1,
                ),
            )
        ],
    }


def resolve_endpoint(ip, evidence, side, ip_bindings):
    """Pure resolver. Missing/contradictory evidence never produces a device name.

    ip_bindings maps (ingestion_id, ip) to {mac: interface identity or None}.
    Identity is a tuple (interface_id, asset_id, asset_name, hardware_role).
    """
    if not evidence:
        return {"status": "UNKNOWN", "identity": None}

    candidates = set()
    for observation in evidence:
        values = observation.get(side + "_macs")
        if not isinstance(values, list) or not values:
            return {"status": "UNKNOWN", "identity": None}

        macs = {canonical_mac(mac) for mac in values}
        if None in macs:
            return {"status": "UNKNOWN", "identity": None}
        if len(macs) != 1:
            return ambiguous_endpoint(ip, evidence, side, ip_bindings)

        mac = next(iter(macs))
        bindings = ip_bindings.get((observation["ingestion_id"], ip), {})

        if len(bindings) > 1:
            return ambiguous_endpoint(ip, evidence, side, ip_bindings)
        if not bindings or mac not in bindings:
            return {"status": "UNKNOWN", "identity": None}

        identity = bindings[mac]
        if identity is None:
            return {"status": "UNKNOWN", "identity": None}

        candidates.add((mac, identity))

    if len(candidates) != 1:
        return ambiguous_endpoint(ip, evidence, side, ip_bindings)

    mac, (interface_id, asset_id, asset_name, role) = next(iter(candidates))
    if asset_id is None:
        return {"status": "UNKNOWN", "identity": None}

    return {
        "status": "IDENTIFIED",
        "identity": {
            "asset_id": asset_id,
            "asset_name": asset_name,
            "role": role,
            "interface_id": interface_id,
            "mac": mac,
            "basis": "ARP_CAPTURE_AND_MANUAL_ASSIGNMENT",
        },
    }


def resolve_communication_endpoints(communications):
    """Enrich only the supplied (usually 25) communications in bulk."""
    items = list(communications)
    if not items:
        return {}

    by_id = {item.id: item for item in items}
    observations = list(
        CommunicationObservation.objects.filter(
            communication_id__in=by_id,
            ingestion__status=Ingestion.Status.ACTIVE,
        ).values(
            "communication_id", "ingestion_id", "client_macs", "server_macs",
        )
    )
    evidence_by_communication = defaultdict(list)
    ingestion_ids = set()
    for observation in observations:
        evidence_by_communication[observation["communication_id"]].append(observation)
        ingestion_ids.add(observation["ingestion_id"])

    bindings = defaultdict(dict)
    if ingestion_ids:
        interface_evidence = (
            InterfaceObservation.objects
            .filter(
                ingestion_id__in=ingestion_ids,
                ingestion__status=Ingestion.Status.ACTIVE,
            )
            .select_related("network_interface__hardware__asset")
        )
        for observation in interface_evidence.iterator(chunk_size=500):
            mac = canonical_mac(observation.mac)
            if mac is None:
                continue

            network_interface = observation.network_interface
            identity = None
            if network_interface is not None:
                hardware = network_interface.hardware
                identity = (
                    network_interface.pk,
                    hardware.asset_id if hardware else None,
                    hardware.asset.name if hardware else None,
                    hardware.role if hardware else None,
                )

            for ip in observation.ips or []:
                if isinstance(ip, str) and ip:
                    key = (observation.ingestion_id, ip)
                    existing = bindings[key].get(mac)
                    if mac in bindings[key] and existing != identity:
                        # Contradictory identities for a MAC in the same capture.
                        bindings[key][mac] = None
                    else:
                        bindings[key][mac] = identity

    output = {}
    for item in items:
        evidence = evidence_by_communication[item.id]
        output[item.id] = {
            "source_resolution": resolve_endpoint(
                item.source_ip, evidence, "client", bindings
            ),
            "destination_resolution": resolve_endpoint(
                item.destination_ip, evidence, "server", bindings
            ),
        }
    return output
