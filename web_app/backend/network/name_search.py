"""Search communications by device name only when endpoint attribution is safe.

A name must not match a communication just because it shares an IP previously
seen on a device. The query requires an active per-capture IP/MAC binding,
an exactly-one-MAC endpoint and no conflicting active communication evidence.

The resolver in endpoint_resolution.py remains the source of display identity.
"""

from collections import defaultdict

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Count, F, Q, Subquery, Value
from django.db.models.functions import Lower, Replace

from assets.models import NetworkInterface
from assets.models.network_interface import normalize_mac
from ingestion.models import CommunicationObservation, Ingestion, InterfaceObservation


def _canonical_mac(value):
    try:
        return normalize_mac(value)
    except DjangoValidationError:
        return None


def unique_name_candidates(matched_observations, all_observations):
    """Return {(mac, ip): {ingestion_ids}} with unique MAC in each capture.

    Pure function, so the no-ambiguity rule can be unit-tested without DB.
    """
    claims = defaultdict(set)
    for row in all_observations:
        mac = _canonical_mac(row["mac"])
        for ip in row["ips"] or []:
            if isinstance(ip, str) and ip:
                claims[(row["ingestion_id"], ip)].add(mac)

    eligible = defaultdict(set)
    for row in matched_observations:
        mac = _canonical_mac(row["mac"])
        if mac is None:
            continue
        for ip in row["ips"] or []:
            key = (row["ingestion_id"], ip)
            if claims.get(key) == {mac}:
                eligible[(mac, ip)].add(row["ingestion_id"])

    return dict(eligible)


def normalize_device_query(text):
    """Ignore spacing/case in inventory name searches (Direct Logic)."""
    return "".join(text.lower().split())


def group_mac_candidates(candidates):
    """Group capture-scoped IP/MAC evidence without changing its provenance.

    Input: {(normalized_mac, ip): {ingestion_id, ...}}
    Output: {normalized_mac: {ip: {ingestion_id, ...}}}
    """
    grouped = defaultdict(lambda: defaultdict(set))
    for (mac, ip), ingestions in candidates.items():
        grouped[mac][ip].update(ingestions)
    return {mac: dict(addresses) for mac, addresses in grouped.items()}


def device_name_filter(search):
    """Return an ORM Q for communications with safely identified name matches.

    Return None if no matching device/capture evidence exists. Results
    remain a queryset filter (never Python post-filtering after pagination).
    """
    token = normalize_device_query(search)
    if not token:
        return None

    # Names such as 'Direct Logic' match 'DirectLogic'. Manufacturer/model
    # matching also helps when the inventory name is abbreviated.
    matched_interfaces = (
        NetworkInterface.objects
        .filter(hardware__isnull=False)
        .annotate(
            normalized_name=Replace(
                Lower("hardware__asset__name"), Value(" "), Value("")
            ),
            normalized_manufacturer=Replace(
                Lower("hardware__manufacturer"), Value(" "), Value("")
            ),
            normalized_model=Replace(
                Lower("hardware__model"), Value(" "), Value("")
            ),
        )
        .filter(
            Q(normalized_name__contains=token)
            | Q(normalized_manufacturer__contains=token)
            | Q(normalized_model__contains=token)
        )
        .values_list("id", flat=True)
    )
    interface_ids = list(matched_interfaces)
    if not interface_ids:
        return None

    matched_rows = list(
        InterfaceObservation.objects
        .filter(
            network_interface_id__in=interface_ids,
            ingestion__status=Ingestion.Status.ACTIVE,
        )
        .values("ingestion_id", "mac", "ips")
    )
    if not matched_rows:
        return None

    ingestion_ids = {row["ingestion_id"] for row in matched_rows}
    all_rows = list(
        InterfaceObservation.objects
        .filter(
            ingestion_id__in=ingestion_ids,
            ingestion__status=Ingestion.Status.ACTIVE,
        )
        .values("ingestion_id", "mac", "ips")
    )
    candidates = unique_name_candidates(matched_rows, all_rows)
    if not candidates:
        return None

    # Group the allowed (capture, IP) associations by MAC. Unlike the old
    # correlated EXISTS chains, every candidate MAC requires at most two
    # grouped subqueries over CommunicationObservation (source/destination).
    # This keeps the number of subqueries independent of the number of IPs.
    groups = group_mac_candidates(candidates)
    matches = Q(pk__in=[])  # Explicitly false if no candidate can match.

    for mac, ip_to_ingestions in groups.items():
        for ip_column, mac_column in (
            ("client_ip", "client_macs"),
            ("server_ip", "server_macs"),
        ):
            accepted = Q(pk__in=[])
            for ip, capture_ids in ip_to_ingestions.items():
                accepted |= Q(**{
                    ip_column: ip,
                    mac_column: [mac],
                    "ingestion_id__in": tuple(capture_ids),
                })

            # The IP is constant per side within a consolidated
            # Communication. Count *all* its active observations and require
            # every one to carry this one MAC, in a capture that supports
            # the same IP/MAC binding. One contradictory observation excludes
            # the communication for this MAC.
            evidence = (
                CommunicationObservation.objects
                .filter(
                    ingestion__status=Ingestion.Status.ACTIVE,
                    communication_id__isnull=False,
                    **{ip_column + "__in": tuple(ip_to_ingestions)},
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

            # Grouped IN-subqueries are computed as sets. They avoid checking
            # EXISTS(valid)/EXISTS(contradictory) for every Communication row.
            matches |= Q(pk__in=Subquery(evidence))

    return matches
