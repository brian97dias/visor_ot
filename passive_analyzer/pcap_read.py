from datetime import datetime
from scapy.all import PcapReader, Ether, IP, TCP, UDP, ARP
from pathlib import Path
import argparse

from interfaces import (
    register_interface,
    register_arp_binding,
)

from communications import (
    process_tcp,
    process_udp,
)

from network import classify_network_scope
from output import save_output

def parse_arguments():

    parser = argparse.ArgumentParser(
        description="Analizador pasivo de capturas PCAP/PCAPNG"
    )

    parser.add_argument(
        "pcap",
        type=Path,
        help="Ruta al archivo PCAP o PCAPNG que se desea analizar",
    )

    args = parser.parse_args()

    pcap_path = args.pcap.expanduser().resolve()

    if not pcap_path.is_file():
        parser.error(
            f"El archivo no existe o no es accesible: {pcap_path}"
        )

    if pcap_path.suffix.lower() not in {".pcap", ".pcapng"}:
        parser.error(
            "El archivo debe tener extensión .pcap o .pcapng"
        )

    return pcap_path


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


#PCAP_PATH = "../pcaps/4SICS_Geek_Lounge/4SICS-GeekLounge-151020.pcap"
#PCAP_PATH = "../pcaps/Modbus Dataset/benign/central-agent/central-agent-network-capture/veth460b141-normal.pcap"

PCAP_PATH = parse_arguments()

# =========================
# LECTURA DEL PCAP
# =========================

with PcapReader(str(PCAP_PATH)) as pcap:

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
            interfaces,
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
                interfaces,
                ip_to_macs,
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

    communication["network_scope"] = classify_network_scope(
        client_ip,
        server_ip,
        ip_to_macs,
    )


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

output_file = save_output(
        PCAP_PATH,
        interfaces,
        communications,
)

print(
    f"\nObservaciones guardadas en: {output_file}"
)