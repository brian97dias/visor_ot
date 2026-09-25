from datetime import datetime

from scapy.all import PcapReader, Ether, IP, TCP, UDP, ARP


# =========================
# DATOS EN MEMORIA
# =========================

interfaces = {}

# Relación inversa obtenida mediante ARP:
#
# "192.168.88.61": {"00:90:e8:27:8c:37"}
#
ip_to_macs = {}

communications = {}

# Estado temporal para recordar la orientación
# de conexiones TCP.
tcp_flows = {}


PCAP_PATH = "../pcaps/4SICS_Geek_Lounge/4SICS-GeekLounge-151020.pcap"


# Por ahora esta tabla solamente nos ayuda a reconocer
# servicios. NO significa que un puerto pruebe por sí solo
# qué protocolo de aplicación está funcionando.
SERVICE_PORTS = {
    ("TCP", 53): "DNS",
    ("UDP", 53): "DNS",

    ("UDP", 67): "DHCP Server",
    ("UDP", 68): "DHCP Client",

    ("UDP", 123): "NTP",

    ("TCP", 102): "S7",
    ("TCP", 502): "Modbus/TCP",
    ("TCP", 20000): "DNP3",
    ("TCP", 44818): "EtherNet/IP",
}


# =========================
# INTERFACES
# =========================

def register_interface(mac, timestamp):

    if mac not in interfaces:
        interfaces[mac] = {
            "mac": mac,
            "ips": set(),
            "first_seen": timestamp,
            "last_seen": timestamp,
        }

    else:
        interfaces[mac]["last_seen"] = timestamp


def register_arp_binding(mac, ip, timestamp):

    # Un ARP Probe puede utilizar 0.0.0.0 como sender IP.
    # Eso no representa una IP asignada al dispositivo.
    if ip == "0.0.0.0":
        return

    register_interface(mac, timestamp)

    interfaces[mac]["ips"].add(ip)

    if ip not in ip_to_macs:
        ip_to_macs[ip] = set()

    ip_to_macs[ip].add(mac)


# =========================
# COMUNICACIONES
# =========================

def register_communication(
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
        }

    else:

        communications[key]["packet_count"] += 1
        communications[key]["last_seen"] = timestamp


# =========================
# TCP
# =========================

def process_tcp(packet, timestamp):

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


    # -------------------------------------------------
    # CASO IDEAL:
    # vemos el comienzo de la conexión TCP
    #
    # cliente:52134 --SYN--> servidor:502
    # -------------------------------------------------

    if syn and not ack:

        client_endpoint = src_endpoint
        server_endpoint = dst_endpoint

        tcp_flows[flow_key] = {
            "client": client_endpoint,
            "server": server_endpoint,
            "role_source": "tcp_syn",
        }


    # -------------------------------------------------
    # Si ya vimos el SYN anteriormente,
    # conocemos la orientación de la conexión.
    # -------------------------------------------------

    flow = tcp_flows.get(flow_key)


    # -------------------------------------------------
    # FALLBACK:
    #
    # Tal vez el PCAP comenzó cuando la conexión TCP
    # ya estaba establecida y nunca vimos el SYN.
    #
    # En ese caso intentamos orientarla usando
    # un puerto de servicio conocido.
    # -------------------------------------------------

    if flow is None:

        destination_is_service = (
            ("TCP", dst_port) in SERVICE_PORTS
        )

        source_is_service = (
            ("TCP", src_port) in SERVICE_PORTS
        )


        # cliente:ephemeral ---> servidor:service
        if destination_is_service and not source_is_service:

            flow = {
                "client": src_endpoint,
                "server": dst_endpoint,
                "role_source": "known_service_port",
            }


        # servidor:service ---> cliente:ephemeral
        elif source_is_service and not destination_is_service:

            flow = {
                "client": dst_endpoint,
                "server": src_endpoint,
                "role_source": "known_service_port",
            }


        # Si ninguno o ambos parecen puertos de servicio,
        # por ahora NO adivinamos.
        else:
            return


        tcp_flows[flow_key] = flow


    client_ip, client_port = flow["client"]

    server_ip, server_port = flow["server"]


    service = SERVICE_PORTS.get(
        ("TCP", server_port)
    )


    register_communication(
        client_ip=client_ip,
        server_ip=server_ip,
        transport_protocol="TCP",
        service_port=server_port,
        timestamp=timestamp,
        service=service,
        role_source=flow["role_source"],
    )


# =========================
# UDP
# =========================

def process_udp(packet, timestamp):

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


    # -------------------------------------------------
    # UDP no tiene handshake como TCP.
    #
    # Por ahora usamos puertos conocidos para inferir
    # qué extremo ofrece el servicio.
    # -------------------------------------------------

    if destination_is_service and not source_is_service:

        client_ip = src_ip
        server_ip = dst_ip
        service_port = dst_port


    elif source_is_service and not destination_is_service:

        client_ip = dst_ip
        server_ip = src_ip
        service_port = src_port


    else:

        # No tenemos suficiente evidencia para determinar
        # quién ofrece el servicio.
        #
        # Más adelante esto podrá resolverse mediante
        # disectores/protocolo de aplicación.
        return


    service = SERVICE_PORTS.get(
        ("UDP", service_port)
    )


    register_communication(
        client_ip=client_ip,
        server_ip=server_ip,
        transport_protocol="UDP",
        service_port=service_port,
        timestamp=timestamp,
        service=service,
        role_source="known_service_port",
    )


# =========================
# LECTURA DEL PCAP
# =========================

with PcapReader(PCAP_PATH) as pcap:

    for packet in pcap:

        timestamp = datetime.strftime(
            datetime.fromtimestamp(float(packet.time)),
            "%Y-%m-%d %H:%M:%S",
        )


        # Nuestro MVP procesa capturas Ethernet.
        if not packet.haslayer(Ether):
            continue


        # -------------------------------------------------
        # La MAC origen sí nos permite afirmar que una
        # interfaz Ethernet fue observada en este segmento.
        #
        # Pero NO asociamos packet[IP].src con esta MAC.
        # -------------------------------------------------

        register_interface(
            packet[Ether].src,
            timestamp,
        )


        # -------------------------------------------------
        # ARP:
        #
        # aprendemos la asociación declarada
        # MAC <-> IPv4.
        #
        # No necesitamos limitarnos solamente a op == 2.
        # -------------------------------------------------

        if packet.haslayer(ARP):

            arp = packet[ARP]

            register_arp_binding(
                arp.hwsrc,
                arp.psrc,
                timestamp,
            )

            continue


        # -------------------------------------------------
        # Desde aquí solamente analizamos IPv4.
        # -------------------------------------------------

        if not packet.haslayer(IP):
            continue


        # TCP y UDP se procesan por separado porque
        # su forma de determinar cliente/servidor
        # es diferente.

        if packet.haslayer(TCP):

            process_tcp(
                packet,
                timestamp,
            )


        elif packet.haslayer(UDP):

            process_udp(
                packet,
                timestamp,
            )


# =========================
# BACKFILL DE MAC
# =========================

# Ahora ya hemos leído TODOS los ARP del PCAP.
#
# Si una comunicación ocurrió antes del ARP correspondiente,
# aquí podemos completar la MAC posteriormente.

for communication in communications.values():

    client_ip = communication["client_ip"]
    server_ip = communication["server_ip"]


    client_macs = ip_to_macs.get(client_ip)

    if client_macs:
        communication["client_macs"] = sorted(client_macs)


    server_macs = ip_to_macs.get(server_ip)

    if server_macs:
        communication["server_macs"] = sorted(server_macs)


# =========================
# RESULTADOS
# =========================

print(
    f"Interfaces detectadas: {len(interfaces)}"
)

for interface in interfaces.values():
    print(interface)


print(
    f"\nComunicaciones detectadas: {len(communications)}"
)

for communication in communications.values():
    print(communication)