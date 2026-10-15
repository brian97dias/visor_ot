"""Filter consolidated communications by one or two identified hardware assets.

A match must come from active PCAP evidence with a unique per-capture IP/MAC
binding and the current manual NetworkInterface -> Hardware association.

For two devices, *both* endpoints must match in the SAME communication
observation (A->B or B->A). Every active observation contributing to the
consolidated communication must agree on that direction and MAC pair.
"""

from collections import defaultdict

from django.db.models import Count, F, Q, Subquery
from rest_framework.exceptions import ValidationError

from assets.models import Asset
from ingestion.models import CommunicationObservation, Ingestion, InterfaceObservation

from .name_search import _canonical_mac, unique_name_candidates


def parse_asset_ids(raw):
    """Parse 0–2 distinct IDs without accepting malformed or repeated values."""
    if raw is None or raw == "":
        return ()

    parts = raw.split(",")
    if len(parts) > 2 or any(not part.strip().isdigit() for part in parts):
        raise ValidationError({
            "asset_ids": "Selecciona uno o dos IDs de hardware válidos."
        })
    result = tuple(int(part.strip()) for part in parts)
    if any(value < 1 for value in result) or len(result) != len(set(result)):
        raise ValidationError({
            "asset_ids": "Los IDs deben ser positivos y distintos (máximo dos)."
        })
    return result


def candidate_bindings_for_assets(asset_ids):
    """Return {asset_id: {(mac, ip): set(ingestion_ids)}} for unique active claims."""
    candidates = {asset_id: defaultdict(set) for asset_id in asset_ids}

    assigned = list(
        InterfaceObservation.objects.filter(
            network_interface__hardware__asset_id__in=asset_ids,
            ingestion__status=Ingestion.Status.ACTIVE,
        ).values("network_interface__hardware__asset_id", "ingestion_id", "mac", "ips")
    )
    if not assigned:
        return {asset_id: dict(values) for asset_id, values in candidates.items()}

    ingestions = {row["ingestion_id"] for row in assigned}
    all_rows = list(
        InterfaceObservation.objects.filter(
            ingestion_id__in=ingestions,
            ingestion__status=Ingestion.Status.ACTIVE,
        ).values("ingestion_id", "mac", "ips")
    )
    eligible = unique_name_candidates(assigned, all_rows)

    for row in assigned:
        asset_id = row["network_interface__hardware__asset_id"]
        mac = _canonical_mac(row["mac"])
        if mac is None:
            continue
        for ip in row["ips"] or []:
            if (mac, ip) in eligible and row["ingestion_id"] in eligible[(mac, ip)]:
                candidates[asset_id][(mac, ip)].add(row["ingestion_id"])

    return {asset_id: dict(values) for asset_id, values in candidates.items()}


def group_by_mac(candidates):
    result = defaultdict(lambda: defaultdict(set))
    for (mac, ip), ingestions in candidates.items():
        result[mac][ip].update(ingestions)
    return {mac: dict(ips) for mac, ips in result.items()}


def allowed_observation_clause(source_mac, source_ip, destination_mac,
                               destination_ip, shared_ingestions):
    """Both endpoints must be supported by one and the same capture."""
    return Q(
        client_ip=source_ip,
        client_macs=[source_mac],
        server_ip=destination_ip,
        server_macs=[destination_mac],
        ingestion_id__in=tuple(sorted(shared_ingestions)),
    )


def direction_pairs(source_candidates, destination_candidates):
    """Pure generator of capture-compatible (source, destination) claims."""
    for (src_mac, src_ip), source_ids in source_candidates.items():
        for (dst_mac, dst_ip), destination_ids in destination_candidates.items():
            shared = source_ids & destination_ids
            if shared:
                yield src_mac, src_ip, dst_mac, dst_ip, shared


def _matching_one_asset(candidates):
    matching = Q(pk__in=[])
    for mac, ip_to_ingestions in group_by_mac(candidates).items():
        for ip_field, mac_field in (
            ("client_ip", "client_macs"),
            ("server_ip", "server_macs"),
        ):
            accepted = Q(pk__in=[])
            for ip, ingestion_ids in ip_to_ingestions.items():
                accepted |= Q(**{
                    ip_field: ip,
                    mac_field: [mac],
                    "ingestion_id__in": tuple(ingestion_ids),
                })

            matching_evidence = (
                CommunicationObservation.objects
                .filter(
                    ingestion__status=Ingestion.Status.ACTIVE,
                    communication_id__isnull=False,
                    **{ip_field + "__in": tuple(ip_to_ingestions)},
                )
                .order_by()
                .values("communication_id")
                .annotate(
                    total=Count("pk"),
                    accepted=Count("pk", filter=accepted),
                )
                .filter(total=F("accepted"))
                .values("communication_id")
            )
            matching |= Q(pk__in=Subquery(matching_evidence))
    return matching


def _matching_two_assets(first, second):
    matching = Q(pk__in=[])
    for origins, destinations in ((first, second), (second, first)):
        # Group by exact MAC pair to avoid a subquery for every IP.
        grouped = defaultdict(list)
        for source_mac, source_ip, target_mac, target_ip, shared in direction_pairs(
            origins, destinations
        ):
            grouped[(source_mac, target_mac)].append(
                (source_ip, target_ip, shared)
            )

        for mac_pair, conditions in grouped.items():
            accepted = Q(pk__in=[])
            for source_ip, destination_ip, ingestions in conditions:
                accepted |= allowed_observation_clause(
                    mac_pair[0], source_ip, mac_pair[1], destination_ip,
                    ingestions,
                )

            # Communication groups have fixed client/server IPs. Counting
            # *all active observations* prevents a positive match based on
            # one capture while another active capture contradicts it.
            matched_evidence = (
                CommunicationObservation.objects
                .filter(
                    ingestion__status=Ingestion.Status.ACTIVE,
                    communication_id__isnull=False,
                    client_ip__in=tuple(c[0] for c in conditions),
                    server_ip__in=tuple(c[1] for c in conditions),
                )
                .order_by()
                .values("communication_id")
                .annotate(
                    total=Count("pk"),
                    accepted=Count("pk", filter=accepted),
                )
                .filter(total=F("accepted"))
                .values("communication_id")
            )
            matching |= Q(pk__in=Subquery(matched_evidence))
    return matching


def hardware_participation_filter(asset_ids):
    """Validated, read-only ORM filter; None means no additional filter."""
    if not asset_ids:
        return None

    found = set(
        Asset.objects.filter(
            id__in=asset_ids,
            asset_type=Asset.AssetType.HARDWARE,
            inventory_status=Asset.InventoryStatus.ACTIVE,
            hardware__isnull=False,
        ).values_list("id", flat=True)
    )
    if found != set(asset_ids):
        raise ValidationError({
            "asset_ids": "Selecciona hardware activo que exista en el inventario."
        })

    candidates = candidate_bindings_for_assets(asset_ids)
    if any(not candidates[asset_id] for asset_id in asset_ids):
        return Q(pk__in=[])

    if len(asset_ids) == 1:
        return _matching_one_asset(candidates[asset_ids[0]])

    return _matching_two_assets(candidates[asset_ids[0]], candidates[asset_ids[1]])
