"""Bounded phase-three summary of observed OT communications for hardening.

The ranking is performed by SQL on *active* ingestion observations. Packet
volume is the sum of packet_count, never the number of observation records.
Hardware attribution is optional and must be supported by active capture/ARP
and a current manual interface assignment; IP coincidence is insufficient.
"""
from network.endpoint_resolution import resolve_communication_endpoints
from network.views import get_communications_queryset


# The existing endpoint resolver loads evidence for supplied communications.
# Bound that work; very large flows keep their IPs but no guessed device names.
MAX_RESOLVED_OBSERVATIONS_PER_COMMUNICATION = 1000


def _active_hardware_identity(result, hardware_by_id):
    """Discard unresolved, ambiguous, archived or out-of-scope identities."""
    if not isinstance(result, dict) or result.get("status") != "IDENTIFIED":
        return None
    identity = result.get("identity")
    if not isinstance(identity, dict):
        return None
    hardware = hardware_by_id.get(identity.get("asset_id"))
    if hardware is None:
        return None
    return {
        "id": hardware["id"],
        "name": hardware["name"],
        "interface_id": identity.get("interface_id"),
        "basis": identity.get("basis"),
    }


def collect_top_communications(hardware_by_id):
    """Return at most three globally observed signatures, without DB writes.

    PostgreSQL/SQLite applies SUM, filtering, order and LIMIT before Python
    materializes rows; only the selected signatures enter endpoint resolution.
    """
    communications = list(
        get_communications_queryset()
        .filter(active_evidence_count__gt=0)
        .order_by("-packets_observed", "pk")[:3]
    )
    resolvable = [
        item for item in communications
        if item.active_evidence_count <= MAX_RESOLVED_OBSERVATIONS_PER_COMMUNICATION
    ]
    resolved = resolve_communication_endpoints(resolvable) if resolvable else {}
    output = []
    for item in communications:
        limit_reached = (
            item.active_evidence_count > MAX_RESOLVED_OBSERVATIONS_PER_COMMUNICATION
        )
        endpoints = resolved.get(item.pk, {})
        source = endpoints.get("source_resolution") or {"status": "UNKNOWN"}
        destination = endpoints.get("destination_resolution") or {"status": "UNKNOWN"}
        output.append({
            "id": item.pk,
            "source_ip": item.source_ip,
            "destination_ip": item.destination_ip,
            "transport_protocol": item.transport_protocol,
            "service_port": item.service_port,
            "service": item.service,
            "classification_status": item.status,
            "packets_observed": int(item.packets_observed),
            "first_seen": item.first_seen,
            "last_seen": item.last_seen,
            "source_hardware": _active_hardware_identity(source, hardware_by_id),
            "destination_hardware": _active_hardware_identity(
                destination, hardware_by_id
            ),
            "source_resolution_status": (
                source.get("status") if not limit_reached else "NOT_EVALUATED_VOLUME"
            ),
            "destination_resolution_status": (
                destination.get("status") if not limit_reached else "NOT_EVALUATED_VOLUME"
            ),
            "evidence_scope": "ACTIVE_INGESTIONS",
        })
    return output
