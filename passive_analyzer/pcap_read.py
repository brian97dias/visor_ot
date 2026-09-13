from scapy.all import PcapReader

PCAP_PATH = "../pcaps/4SICS_Geek_Lounge/4SICS-GeekLounge-151020.pcap"

with PcapReader(PCAP_PATH) as pcap:
    first_packet = next(pcap)

print(first_packet.show())