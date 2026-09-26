from datetime import datetime

from scapy.all import (
    PcapReader,
    Ether,
    IP,
    TCP,
    UDP,
    ARP,
)

from interfaces import (
    register_interface,
    register_arp_binding,
)

from communications import (
    process_tcp,
    process_udp,
)

from network import classify_network_scope


def analyze_pcap(pcap_path):

    # =========================
    # ESTADO DEL ANÁLISIS
    # =========================

    interfaces = {}

    # Relación inversa obtenida mediante ARP:
    #
    # "192.168.88.61": {"00:90:e8:27:8c:37"}
    ip_to_macs = {}

    communications = {}

    # Estado temporal utilizado para recordar
    # la orientación de conexiones TCP.
    tcp_flows = {}


    # =========================
    # LECTURA DEL PCAP
    # =========================

    with PcapReader(str(pcap_path)) as pcap:

        for packet in pcap:

            timestamp = datetime.strftime(
                datetime.fromtimestamp(
                    float(packet.time)
                ),
                "%Y-%m-%d %H:%M:%S",
            )


            # Nuestro MVP procesa capturas Ethernet.
            if not packet.haslayer(Ether):
                continue


            # Registramos la MAC origen observada
            # en el segmento Ethernet.
            register_interface(
                interfaces,
                packet[Ether].src,
                timestamp,
            )


            # ARP nos permite obtener evidencia
            # de asociaciones MAC <-> IPv4.
            if packet.haslayer(ARP):

                arp = packet[ARP]

                register_arp_binding(
                    interfaces,
                    ip_to_macs,
                    arp.hwsrc,
                    arp.psrc,
                    timestamp,
                )

                continue


            # Desde aquí solamente analizamos IPv4.
            if not packet.haslayer(IP):
                continue


            if packet.haslayer(TCP):

                process_tcp(
                    packet,
                    timestamp,
                    communications,
                    tcp_flows,
                )


            elif packet.haslayer(UDP):

                process_udp(
                    packet,
                    timestamp,
                    communications,
                )


    # =========================
    # BACKFILL FINAL
    # =========================

    # Ya hemos leído todos los ARP del PCAP.
    # Ahora podemos completar las MAC de las
    # comunicaciones observadas previamente.

    for communication in communications.values():

        client_ip = communication["client_ip"]
        server_ip = communication["server_ip"]


        client_macs = ip_to_macs.get(
            client_ip
        )

        if client_macs:
            communication["client_macs"] = sorted(
                client_macs
            )


        server_macs = ip_to_macs.get(
            server_ip
        )

        if server_macs:
            communication["server_macs"] = sorted(
                server_macs
            )


        communication["network_scope"] = (
            classify_network_scope(
                client_ip,
                server_ip,
                ip_to_macs,
            )
        )


    return interfaces, communications