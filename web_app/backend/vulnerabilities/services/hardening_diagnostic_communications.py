"""Bounded attribution-aware communication selection for prioritized hardware.

Only active captures, validated MAC bindings and the pre-existing conservative
endpoint resolver may connect an observed communication to a hardware asset.
SQL performs aggregation and descending packet ranking before Python receives
small candidate batches. A missing result does not imply no network traffic.
"""
from collections import defaultdict
from ipaddress import ip_address

from django.db.models import Q

from ingestion.models import Ingestion, InterfaceObservation
from network.endpoint_resolution import (
    canonical_mac, resolve_communication_endpoints,
)
from network.views import get_communications_queryset

from .hardening_report_communications import (
    MAX_RESOLVED_OBSERVATIONS_PER_COMMUNICATION,
    _active_hardware_identity,
)

PER_HARDWARE_LIMIT = 3
CANDIDATE_BATCH_SIZE = 30
MAX_CANDIDATES_INSPECTED = 300
MAX_IP_BINDINGS = 200


def _capture_bound_ips(hardware_ids):
    """Candidate IPs are never inferred from declared IP alone."""
    ids = set(hardware_ids)
    output = defaultdict(set)
    observations = (
        InterfaceObservation.objects.filter(
            ingestion__status=Ingestion.Status.ACTIVE,
            network_interface__hardware_id__in=ids,
        )
        .select_related("network_interface")
        .order_by("pk")
    )
    for observation in observations.iterator(chunk_size=500):
        interface = observation.network_interface
        if interface is None or interface.hardware_id not in ids:
            continue
        # A stale/mismatched capture MAC must not lead to a device attribution.
        if not interface.mac or canonical_mac(interface.mac) != canonical_mac(
            observation.mac
        ):
            continue
        for value in observation.ips or []:
            if not isinstance(value, str):
                continue
            try:
                ip_address(value)
            except ValueError:
                continue
            output[interface.hardware_id].add(value)
    return output


def collect_prioritized_communications(hardware_by_id, prioritized_ids):
    """Find up to three confidently attributed signatures per hardware.

    A candidate is accepted only after the existing endpoint resolver
    identifies the hardware in active observations. A bounded search can
    be inconclusive and must be reported as such.
    """
    ids = sorted(set(prioritized_ids) & set(hardware_by_id))
    result = {
        hid: {
            "communications": [],
            "status": "INSUFFICIENT_ATTRIBUTION_EVIDENCE",
            "search_limited": False,
        }
        for hid in ids
    }
    if not ids:
        return result

    ips_by_hardware = _capture_bound_ips(ids)
    candidate_ips = set().union(*(ips_by_hardware.get(hid, set()) for hid in ids))
    if not candidate_ips:
        return result
    if len(candidate_ips) > MAX_IP_BINDINGS:
        for hid in ids:
            result[hid]["status"] = "IP_BINDING_LIMIT_REACHED"
            result[hid]["search_limited"] = True
        return result

    candidates_sql = (
        get_communications_queryset()
        .filter(active_evidence_count__gt=0)
        .filter(Q(source_ip__in=candidate_ips) |
                Q(destination_ip__in=candidate_ips))
        .order_by("-packets_observed", "pk")
    )
    complete = False
    for offset in range(0, MAX_CANDIDATES_INSPECTED, CANDIDATE_BATCH_SIZE):
        batch = list(candidates_sql[offset:offset + CANDIDATE_BATCH_SIZE])
        if not batch:
            complete = True
            break
        eligible = [
            item for item in batch
            if item.active_evidence_count <=
            MAX_RESOLVED_OBSERVATIONS_PER_COMMUNICATION
        ]
        resolved = resolve_communication_endpoints(eligible) if eligible else {}
        for item in batch:
            endpoints = resolved.get(item.pk, {})
            for side in ("source", "destination"):
                resolution = endpoints.get(side + "_resolution")
                identity = _active_hardware_identity(resolution, hardware_by_id)
                if identity is None:
                    continue
                hid = identity["id"]
                if hid not in result or len(result[hid]["communications"]) >= PER_HARDWARE_LIMIT:
                    continue
                # Resolution is from active capture+ARP; IP membership adds
                # a conservative prefilter rather than substituting for it.
                if (item.source_ip not in ips_by_hardware.get(hid, ())
                        and item.destination_ip not in ips_by_hardware.get(hid, ())):
                    continue
                if any(row["id"] == item.pk
                       for row in result[hid]["communications"]):
                    continue
                source = endpoints.get("source_resolution") or {"status": "UNKNOWN"}
                dest = endpoints.get("destination_resolution") or {"status": "UNKNOWN"}
                result[hid]["communications"].append({
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
                    "source_hardware": _active_hardware_identity(
                        source, hardware_by_id
                    ),
                    "destination_hardware": _active_hardware_identity(
                        dest, hardware_by_id
                    ),
                    "source_resolution_status": source.get("status"),
                    "destination_resolution_status": dest.get("status"),
                    "evidence_scope": "ACTIVE_INGESTIONS",
                })
        if all(len(result[hid]["communications"]) >= PER_HARDWARE_LIMIT
               for hid in ids):
            complete = True
            break
        if len(batch) < CANDIDATE_BATCH_SIZE:
            complete = True
            break

    for hid in ids:
        entry = result[hid]
        entry["search_limited"] = not complete
        if entry["communications"]:
            entry["status"] = (
                "ATTRIBUTED_PARTIAL_SEARCH" if not complete else "ATTRIBUTED"
            )
        elif not complete:
            entry["status"] = "SEARCH_LIMIT_REACHED_NO_ATTRIBUTION"
    return result
