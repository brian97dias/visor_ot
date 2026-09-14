from datetime import datetime

from scapy.all import PcapReader, Ether, IP, TCP, UDP


# Guardo las interfaces y comunicaciones detectadas
interfaces = {}
communication = {}
# ../pcaps/Modbus Dataset/benign/central-agent/central-agent-network-capture/veth460b141-normal.pcap
# ../pcaps/4SICS_Geek_Lounge/4SICS-GeekLounge-151020.pcap
PCAP_PATH = "../pcaps/4SICS_Geek_Lounge/4SICS-GeekLounge-151020.pcap"

def register_interface(mac, ip, timestamp):
    # si la mac no está registrada, la agrego al diccionario de interfaces
    if mac not in interfaces:
        interfaces[mac] = {
            "mac": mac,
            "ips": {ip}, # una mac puede puede cambiar de ip, por eso se guarda en un set
            "first_seen": timestamp,
            "last_seen": timestamp,
        }
    else:
        # si la mac ya está registrada, actualizo la información de fecha y si hay una nueva ip, la agrego al set de ips
        interfaces[mac]["ips"].add(ip)
        interfaces[mac]["last_seen"] = timestamp

    return mac # por que retornamos la mac?
    


with PcapReader(PCAP_PATH) as pcap:
    for packet in pcap:

        #if not packet.haslayer(Ether):
        #    continue

        if not packet.haslayer(IP): # si el paquete no tiene capa IP, lo descarto por ahora
            #print(f"Paquete descartado: {packet.summary()}")
            continue

        # Cambio de fecha de UTS a formato leíble 
        timestamp = datetime.strftime(datetime.fromtimestamp(float(packet.time)), "%Y-%m-%d %H:%M:%S")

        source_interface = register_interface(
            packet[Ether].src,
            packet[IP].src,
            timestamp,
        )

        destination_interface = register_interface(
            packet[Ether].dst,
            packet[IP].dst,
            timestamp,
        )

print(f"Interfaces detectadas: {len(interfaces)} y los valores detectados son: {list(interfaces.keys())}"    )
print(interfaces)

