# Puertos utilizados como evidencia para inferir
# el servicio cuando el protocolo no permite determinar
# directamente la orientación cliente/servidor.
#
# Un puerto conocido NO confirma por sí solo
# el protocolo de aplicación.

import os

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent


PCAP_DIRECTORY = Path(
    os.getenv(
        "PASSIVE_ANALYZER_PCAP_DIR",
        str(PROJECT_DIR / "pcaps"),
    )
).expanduser().resolve()


OUTPUT_DIRECTORY = Path(
    os.getenv(
        "PASSIVE_ANALYZER_OUTPUT_DIR",
        str(BASE_DIR / "output"),
    )
).expanduser().resolve()

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


# Redes que la organización declara explícitamente
# como pertenecientes a su infraestructura.
#
# Por ahora permanece vacío porque el analizador
# puede obtener parte del contexto local mediante ARP.
INTERNAL_NETWORKS = []