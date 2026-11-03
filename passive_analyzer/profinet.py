"""Conservative PROFINET RT discovery over Ethernet (EtherType 0x8892).

RT has no TCP/UDP port and raw Ethernet frames have no IP addresses.
VISOR OT's current communication schema is IP-based: emit an observation
ONLY when both unicast MACs have unique, mutually consistent IPv4 ARP
bindings in the same PCAP. Unknown/ambiguous L2 traffic is never assigned
an invented IP or a device identity.

Reverse-direction RT frames belong to the same observed Ethernet pair. The
first-seen direction labels the displayed endpoints; it is NOT proof of
PLC/controller versus device/server roles.
"""

from ipaddress import ip_address

from communications import register_communication

PROFINET_ETHERTYPE = 0x8892
RT_CLASS_1_MIN = 0x8000
RT_CLASS_1_MAX = 0xBBFF
ETHERNET_TRANSPORT = "ETHERNET"
NO_TRANSPORT_PORT = 0
RT_SERVICE = "PROFINET RT"
ROLE_SOURCE = "ethernet_first_observed"


def register_profinet_frame(packet, timestamp, pairs):
    """Collect only unicast PROFINET RT Class 1 frames, without IP guessing."""
    from scapy.all import Ether

    ethernet = packet[Ether]
    if int(ethernet.type) != PROFINET_ETHERTYPE:
        return
    source, destination = ethernet.src.lower(), ethernet.dst.lower()
    if source == destination or source == "ff:ff:ff:ff:ff:ff":
        return
    try:
        if int(source.split(":")[0], 16) & 1:
            return
        if int(destination.split(":")[0], 16) & 1:
            return
        payload = bytes(ethernet.payload)
        if len(payload) < 2:
            return
        frame_id = int.from_bytes(payload[:2], "big")
    except (AttributeError, TypeError, ValueError):
        return
    if not RT_CLASS_1_MIN <= frame_id <= RT_CLASS_1_MAX:
        return

    pair_key = frozenset((source, destination))
    if pair_key not in pairs:
        pairs[pair_key] = {
            "source_mac": source,
            "destination_mac": destination,
            "packet_count": 1,
            "first_seen": timestamp,
            "last_seen": timestamp,
        }
    else:
        pairs[pair_key]["packet_count"] += 1
        pairs[pair_key]["last_seen"] = timestamp


def _single_arp_ip(mac, interfaces, ip_to_macs):
    """An Ethernet MAC can be given an IP label only by unambiguous ARP."""
    observed = interfaces.get(mac)
    if not observed:
        return None
    ips = observed.get("ips", set())
    if len(ips) != 1:
        return None
    ip = next(iter(ips))
    try:
        address = ip_address(ip)
    except ValueError:
        return None
    if address.version != 4 or address.is_multicast or address.is_unspecified:
        return None
    if ip_to_macs.get(ip) != {mac}:
        return None
    return ip


def consolidate_profinet_pairs(pairs, interfaces, ip_to_macs, communications):
    """Produce one bidirectional observed relation per safe Ethernet MAC pair.

    The IP-based Django schema uses port 0 solely as a non-TCP/UDP sentinel.
    Identity attribution remains dependent on captured ARP plus the existing
    operator-managed network-interface associations.
    """
    for frame in pairs.values():
        source = _single_arp_ip(frame["source_mac"], interfaces, ip_to_macs)
        destination = _single_arp_ip(
            frame["destination_mac"], interfaces, ip_to_macs
        )
        if source is None or destination is None or source == destination:
            continue
        key = (source, destination, ETHERNET_TRANSPORT, NO_TRANSPORT_PORT)
        register_communication(
            communications=communications,
            client_ip=source,
            server_ip=destination,
            transport_protocol=ETHERNET_TRANSPORT,
            service_port=NO_TRANSPORT_PORT,
            timestamp=frame["first_seen"],
            service=RT_SERVICE,
            role_source=ROLE_SOURCE,
        )
        communication = communications[key]
        communication["packet_count"] = frame["packet_count"]
        communication["first_seen"] = frame["first_seen"]
        communication["last_seen"] = frame["last_seen"]
        communication["client_macs"] = [frame["source_mac"]]
        communication["server_macs"] = [frame["destination_mac"]]
