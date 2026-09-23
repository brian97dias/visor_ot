from datetime import datetime

from scapy.all import PcapReader, Ether, IP, TCP, UDP, ARP

# Guardo las interfaces y comunicaciones detectadas
interfaces = {}
communications = {}


# ../pcaps/Modbus Dataset/benign/central-agent/central-agent-network-capture/veth460b141-normal.pcap
# ../pcaps/4SICS_Geek_Lounge/4SICS-GeekLounge-151020.pcap
PCAP_PATH = "../pcaps/4SICS_Geek_Lounge/4SICS-GeekLounge-151020.pcap"

def register_interface(mac, ip, timestamp):
    # si la mac no está registrada, la agrego al diccionario de interfaces
    if mac not in interfaces:
        interfaces[mac] = {
            "mac": mac,
            "ips": {ip}, # una mac puede puede cambiar de ip (por ejemplo un atacante realiando ARP spoofing/poisoning), por eso se guarda en un set
            "first_seen": timestamp,
            "last_seen": timestamp,
        }
    else:
        # si la mac ya está registrada, actualizo la información de fecha y si hay una nueva ip, la agrego al set de ips
        interfaces[mac]["ips"].add(ip)
        interfaces[mac]["last_seen"] = timestamp   


def register_communication(src_ip, dst_ip, timestamp):
    # si la comunicación no está registrada, la agrego al diccionario de comunicaciones
    if (src_ip, dst_ip) not in communications:
        communications[(src_ip, dst_ip)] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "first_seen": timestamp,
            "last_seen": timestamp,
        }
    else:
        # si la comunicación ya está registrada, actualizo la información de fecha
        communications[(src_ip, dst_ip)]["last_seen"] = timestamp

with PcapReader(PCAP_PATH) as pcap:
    for packet in pcap:
        # Cambio de fecha de UTS a formato leíble 
        timestamp = datetime.strftime(datetime.fromtimestamp(float(packet.time)), "%Y-%m-%d %H:%M:%S")

        if not packet.haslayer(Ether):# Solo procesaremos paquetes que tengan capa Ethernet por temas de alcance, si no la tienen, los descartamos
            continue
            
        # si detecta un gratuitous ARP/reply ARP registro la MAC e IP
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            register_interface(
                packet[ARP].hwsrc,# capturo la MAC del paquete ARP
                packet[ARP].psrc, # capturo la IP del paquete ARP
                timestamp
            )
            continue

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            # registro la comunicación entre las interfaces
            register_communication(
                packet[IP].src,
                packet[IP].dst,
                timestamp
            )

        if not packet.haslayer(IP): # si el paquete no tiene capa IP, lo descarto por ahora
           continue

        # source_interface = register_interface(
        #     packet[Ether].src,
        #     packet[IP].src,
        #     timestamp,
        # )

        # destination_interface = register_interface(
        #     packet[Ether].dst,
        #     packet[IP].dst,
        #     timestamp,
        # )

print(f"Interfaces detectadas: {len(interfaces)} y los valores detectados son: {list(interfaces.keys())}"    )
print(interfaces)

