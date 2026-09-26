def register_interface(
    interfaces,
    mac,
    timestamp,
):
    if mac not in interfaces:
        interfaces[mac] = {
            "mac": mac,
            "ips": set(),
            "first_seen": timestamp,
            "last_seen": timestamp,
        }

    else:
        interfaces[mac]["last_seen"] = timestamp


def register_arp_binding(
    interfaces,
    ip_to_macs,
    mac,
    ip,
    timestamp,
):
    # Un ARP Probe puede utilizar 0.0.0.0 como sender IP.
    # Eso no representa una IP asignada al dispositivo.
    if ip == "0.0.0.0":
        return

    register_interface(
        interfaces,
        mac,
        timestamp,
    )

    interfaces[mac]["ips"].add(ip)

    if ip not in ip_to_macs:
        ip_to_macs[ip] = set()

    ip_to_macs[ip].add(mac)