"""Scapy regression: PROFINET RT + S7/Modbus keep the existing JSON contract.

Run from passive_analyzer/: python -m unittest tests_profinet
Does not use real hardware, external networks or require packet transmission.
"""
import tempfile
import unittest
from pathlib import Path

from scapy.all import ARP, Ether, IP, Raw, TCP, wrpcap

from analyzer import analyze_pcap
from output import build_output


MAC_PLC = "00:1c:06:01:d4:23"
MAC_PHOENIX = "00:0e:8c:a3:4e:cf"
IP_PLC = "192.168.88.30"
IP_PHOENIX = "192.168.88.20"


def announce(ip, mac):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst=ip,
    )


def profinet(src, dst, frame_id=0x8000):
    # Raw illustrative RT bytes, not a full PROFINET stack.
    payload = frame_id.to_bytes(2, "big") + b"\x00" * 44
    return Ether(src=src, dst=dst, type=0x8892) / Raw(load=payload)


class ProfinetPassiveTests(unittest.TestCase):
    def capture(self, packets):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        capture = Path(temp.name) / "normal.pcap"
        for index, pkt in enumerate(packets):
            pkt.time = float(100 + index / 10)
        wrpcap(str(capture), packets)
        return analyze_pcap(capture)

    def test_profinet_bidirectional_arp_grounded_pair_and_tcp_kept(self):
        packets = [
            announce(IP_PLC, MAC_PLC),
            announce(IP_PHOENIX, MAC_PHOENIX),
            profinet(MAC_PLC, MAC_PHOENIX),
            profinet(MAC_PHOENIX, MAC_PLC),
            profinet(MAC_PLC, MAC_PHOENIX),
            Ether(src=MAC_PLC, dst=MAC_PHOENIX) / IP(
                src=IP_PLC, dst=IP_PHOENIX
            ) / TCP(sport=42000, dport=102, flags="S"),
            Ether(src=MAC_PLC, dst=MAC_PHOENIX) / IP(
                src=IP_PLC, dst=IP_PHOENIX
            ) / TCP(sport=42001, dport=502, flags="S"),
        ]
        interfaces, communications = self.capture(packets)
        self.assertEqual(len(interfaces), 2)
        self.assertEqual(len(communications), 3)
        ethernet = communications[(IP_PLC, IP_PHOENIX, "ETHERNET", 0)]
        self.assertEqual(ethernet["service"], "PROFINET RT")
        self.assertEqual(ethernet["role_source"], "ethernet_first_observed")
        self.assertEqual(ethernet["packet_count"], 3)
        self.assertEqual(ethernet["client_macs"], [MAC_PLC])
        self.assertEqual(ethernet["server_macs"], [MAC_PHOENIX])
        self.assertEqual(ethernet["network_scope"], "local_segment")
        self.assertEqual(communications[(IP_PLC, IP_PHOENIX, "TCP", 102)]
                         ["service"], "S7")
        self.assertEqual(communications[(IP_PLC, IP_PHOENIX, "TCP", 502)]
                         ["service"], "Modbus/TCP")

    def test_no_arp_no_invented_ip(self):
        _, communications = self.capture([
            profinet(MAC_PLC, MAC_PHOENIX),
            profinet(MAC_PHOENIX, MAC_PLC),
        ])
        self.assertEqual(communications, {})

    def test_ambiguous_arp_binding_skips_instead_of_inventing_endpoints(self):
        _, communications = self.capture([
            announce(IP_PLC, MAC_PLC),
            announce("192.168.88.99", MAC_PLC),
            announce(IP_PHOENIX, MAC_PHOENIX),
            profinet(MAC_PLC, MAC_PHOENIX),
        ])
        self.assertEqual(communications, {})

    def test_one_ip_claimed_by_two_macs_is_ambiguous(self):
        _, communications = self.capture([
            announce(IP_PLC, MAC_PLC),
            announce(IP_PLC, "00:11:22:33:44:55"),
            announce(IP_PHOENIX, MAC_PHOENIX),
            profinet(MAC_PLC, MAC_PHOENIX),
        ])
        self.assertEqual(communications, {})

    def test_other_profinet_frame_type_is_not_rt_class_one(self):
        _, communications = self.capture([
            announce(IP_PLC, MAC_PLC),
            announce(IP_PHOENIX, MAC_PHOENIX),
            profinet(MAC_PLC, MAC_PHOENIX, frame_id=0xFEFE),
        ])
        self.assertEqual(communications, {})

    def test_arp_after_ethernet_frames_resolves_offline(self):
        _, communications = self.capture([
            profinet(MAC_PLC, MAC_PHOENIX),
            profinet(MAC_PHOENIX, MAC_PLC),
            announce(IP_PLC, MAC_PLC),
            announce(IP_PHOENIX, MAC_PHOENIX),
        ])
        self.assertEqual(
            communications[(IP_PLC, IP_PHOENIX, "ETHERNET", 0)]
            ["packet_count"], 2,
        )


if __name__ == "__main__":
    unittest.main()
