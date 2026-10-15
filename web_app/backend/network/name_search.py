"""Search communications by device name only when endpoint attribution is safe.

A name must not match a communication just because it shares an IP previously
seen on a device. The query requires an active per-capture IP/MAC binding,
an exactly-one-MAC endpoint and no conflicting active communication evidence.

The resolver in endpoint_resolution.py remains the source of display identity.
"""

from collections import defaultdict

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Exists, OuterRef, Q, Value
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


def device_name_filter(search):
    """Return an ORM Q for communications with safely identified name matches.

    Return None if no matching device/capture evidence exists. This is *not*
    an IP substring or a full scan through resolved Python page results.
    """
    token = "".join(search.lower().split())
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

    active_observations = CommunicationObservation.objects.filter(
        communication_id=OuterRef("pk"),
        ingestion__status=Ingestion.Status.ACTIVE,
    )
    matches = Q(pk__in=[])  # Always false, never an unrestricted Q().
    for (mac, ip), ids in candidates.items():
        for endpoint_field, mac_field, ip_field in (
            ("source_ip", "client_macs", "client_ip"),
            ("destination_ip", "server_macs", "server_ip"),
        ):
            required = {
                "ingestion_id__in": tuple(ids),
                mac_field: [mac],
                ip_field: ip,
            }
            valid = active_observations.filter(**required)
            contradictory = active_observations.exclude(**required)
            matches |= (
                Q(**{endpoint_field: ip})
                & Q(Exists(valid))
                & ~Q(Exists(contradictory))
            )

    return matches
