from scapy.all import IP, TCP, UDP

from config import SERVICE_PORTS


def register_communication(
    communications,
    client_ip,
    server_ip,
    transport_protocol,
    service_port,
    timestamp,
    service=None,
    role_source=None,
):

    key = (
        client_ip,
        server_ip,
        transport_protocol,
        service_port,
    )

    if key not in communications:

        communications[key] = {
            "client_ip": client_ip,
            "server_ip": server_ip,

            # Las MAC se resolverán al terminar de leer
            # todo el PCAP.
            "client_macs": None,
            "server_macs": None,

            "transport_protocol": transport_protocol,

            # Guardamos únicamente el puerto considerado
            # puerto del servicio.
            "service_port": service_port,

            "service": service,

            # Nos dice cómo determinamos quién era servidor.
            # Por ejemplo: tcp_syn o known_service_port.
            "role_source": role_source,

            "packet_count": 1,

            "first_seen": timestamp,
            "last_seen": timestamp,

            # Se determinará al terminar de leer
            # todo el PCAP.
            "network_scope": None,
        }

    else:

        communications[key]["packet_count"] += 1
        communications[key]["last_seen"] = timestamp


def process_tcp(
    packet,
    timestamp,
    communications,
    tcp_flows,
):

    tcp = packet[TCP]

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    src_port = int(tcp.sport)
    dst_port = int(tcp.dport)

    src_endpoint = (src_ip, src_port)
    dst_endpoint = (dst_ip, dst_port)

    # Esta clave identifica la conexión sin importar
    # en qué dirección viaje este paquete.
    flow_key = frozenset({
        src_endpoint,
        dst_endpoint,
    })

    flags = int(tcp.flags)

    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)


    # Vemos el comienzo de la conexión TCP:
    #
    # cliente:52134 --SYN--> servidor:502

    if syn and not ack:

        client_endpoint = src_endpoint
        server_endpoint = dst_endpoint

        tcp_flows[flow_key] = {
            "client": client_endpoint,
            "server": server_endpoint,
            "role_source": "tcp_syn",
        }


    flow = tcp_flows.get(flow_key)


    # Si no vimos el SYN, intentamos orientar
    # la conexión mediante puertos conocidos.

    if flow is None:

        destination_is_service = (
            ("TCP", dst_port) in SERVICE_PORTS
        )

        source_is_service = (
            ("TCP", src_port) in SERVICE_PORTS
        )


        if destination_is_service and not source_is_service:

            flow = {
                "client": src_endpoint,
                "server": dst_endpoint,
                "role_source": "known_service_port",
            }


        elif source_is_service and not destination_is_service:

            flow = {
                "client": dst_endpoint,
                "server": src_endpoint,
                "role_source": "known_service_port",
            }


        else:
            return


        tcp_flows[flow_key] = flow


    client_ip, client_port = flow["client"]
    server_ip, server_port = flow["server"]


    service = SERVICE_PORTS.get(
        ("TCP", server_port)
    )


    register_communication(
        communications=communications,
        client_ip=client_ip,
        server_ip=server_ip,
        transport_protocol="TCP",
        service_port=server_port,
        timestamp=timestamp,
        service=service,
        role_source=flow["role_source"],
    )


def process_udp(
    packet,
    timestamp,
    communications,
):

    udp = packet[UDP]

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    src_port = int(udp.sport)
    dst_port = int(udp.dport)


    destination_is_service = (
        ("UDP", dst_port) in SERVICE_PORTS
    )

    source_is_service = (
        ("UDP", src_port) in SERVICE_PORTS
    )


    if destination_is_service and not source_is_service:

        client_ip = src_ip
        server_ip = dst_ip
        service_port = dst_port


    elif source_is_service and not destination_is_service:

        client_ip = dst_ip
        server_ip = src_ip
        service_port = src_port


    else:
        return


    service = SERVICE_PORTS.get(
        ("UDP", service_port)
    )


    register_communication(
        communications=communications,
        client_ip=client_ip,
        server_ip=server_ip,
        transport_protocol="UDP",
        service_port=service_port,
        timestamp=timestamp,
        service=service,
        role_source="known_service_port",
    )