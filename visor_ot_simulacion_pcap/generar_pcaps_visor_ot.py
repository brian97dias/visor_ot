#!/usr/bin/env python3
"""Generador reproducible de dos PCAP sintéticos para VISOR OT.

Usa únicamente la biblioteca estándar de Python (no Scapy / no root).
NO transmite paquetes por ninguna interfaz; escribe archivos PCAP offline.

Escenario sintético: dos sistemas OT de preparación/mezcla y transferencia/envasado.
Nombres de activos y de software: exportación Visor_OT_Inventario (6).xlsx.
Direcciones IP/MAC: topología sintética aprobada por el usuario.

Ejecutar:
    python3 generar_pcaps_visor_ot.py
    python3 generar_pcaps_visor_ot.py --output ./salida

Los bytes PROFINET RT se usan como evidencia Ethernet representativa;
no son una emulación completa certificada del protocolo ni del PLC.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import socket
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

SIST_M = "Sistema de preparación y mezcla"
SIST_E = "Sistema de transferencia y envasado"
TZ_CO = timezone(timedelta(hours=-5))

# ACTIVO -> IP, MAC, SOFTWARE INSTALADO, SISTEMAS
# Los IDs y software coinciden con la exportación más reciente del usuario.
DEVICES = {
    "PLC-MEZ-01": ("192.168.88.30", "00:1c:06:01:d4:23", "FW-S7-1200-V4.4.0", [SIST_M]),
    "IO-MEZ-01": ("192.168.88.20", "00:0e:8c:a3:4e:cf", "FW-PHX-ILPN-1.13", [SIST_M]),
    "PLC-TRA-01": ("192.168.88.15", "00:0c:29:51:a9:47", "FW-S7-1200-V4.5.2", [SIST_M, SIST_E]),
    "IO-TRA-01": ("192.168.88.25", "00:0a:dc:64:85:c2", "FW-ADAM-5550", [SIST_M, SIST_E]),
    "PLC-ENV-01": ("192.168.88.85", "28:63:36:89:59:82", "FW-S7-1200-V4.5.0", [SIST_E]),
    "IO-ENV-01": ("192.168.88.105", "00:11:22:7b:c5:50", "FW-PHX-ILPN-1.13", [SIST_E]),
    "GW-CAU-01": ("192.168.88.50", "00:05:e4:01:24:d3", "FW-REDLION-DSP", [SIST_E]),
    "SW-MEZ-01": ("192.168.88.60", "00:90:e8:10:af:c8", "FW-MOXA-EDS508A-3.11", [SIST_M]),
    "SW-ENV-01": ("192.168.88.61", "00:90:e8:27:8c:37", "FW-MOXA-EDS508A-3.10", [SIST_E]),
    "FW-OT-01": ("192.168.88.75", "00:80:63:b5:b6:bb", "FW-TOFINO-EAGLE20", [SIST_M, SIST_E]),
    "HMI-LIN-01": ("192.168.88.52", "28:cf:e9:18:b5:ed", "FW-DELL-7090-1.19.0, SO-UBUNTU-20.04, APP-FUXA-1.1.12", [SIST_M, SIST_E]),
    "ENG-01": ("192.168.88.130", "00:40:9d:28:ee:0d", "FW-LENOVO-M70Q-M2WKT56A, SO-WIN10-22H2, APP-TIA-PORTAL-V16", [SIST_M, SIST_E]),
}

# No es un activo del inventario ni usa una MAC propia en el segmento capturado.
# Tráfico L3 originado fuera de OT y reenviado al segmento OT por FW-OT-01.
EXTERNAL_IP = "192.168.2.64"

# Cada fila: cliente, servidor, TCP puerto, propósito, clasificación prevista del analista.
# No se escribe la clasificación en el PCAP: es contexto de política externa.
NORMAL = [
    ("HMI-LIN-01", "PLC-MEZ-01", 102, "S7 supervisión de mezcla", "AUTORIZADA"),
    ("HMI-LIN-01", "PLC-TRA-01", 102, "S7 supervisión de transferencia", "AUTORIZADA"),
    ("HMI-LIN-01", "PLC-ENV-01", 102, "S7 supervisión de envasado", "AUTORIZADA"),
    ("PLC-TRA-01", "IO-TRA-01", 502, "Modbus TCP transferencia", "AUTORIZADA"),
    ("PLC-ENV-01", "GW-CAU-01", 502, "Modbus TCP lectura de caudal", "AUTORIZADA"),
    ("ENG-01", "IO-MEZ-01", 80, "HTTP administración Phoenix mezcla", "AUTORIZADA"),
    ("ENG-01", "IO-ENV-01", 80, "HTTP administración Phoenix envasado", "AUTORIZADA"),
    ("ENG-01", "SW-MEZ-01", 22, "SSH mantenimiento switch mezcla", "AUTORIZADA"),
    ("ENG-01", "SW-ENV-01", 22, "SSH mantenimiento switch envasado", "AUTORIZADA"),
    ("ENG-01", "FW-OT-01", 443, "HTTPS administración firewall", "AUTORIZADA"),
]
DAY2_EXTRA = [
    ("ENG-01", "PLC-MEZ-01", 102, "S7 mantenimiento programado nuevo", "AUTORIZADA"),
    (EXTERNAL_IP, "PLC-MEZ-01", 102, "S7 desde red cliente no aprobada", "NO_AUTORIZADA"),
    (EXTERNAL_IP, "IO-MEZ-01", 80, "HTTP desde red cliente no aprobada", "NO_AUTORIZADA"),
    (EXTERNAL_IP, "SW-ENV-01", 23, "Telnet desde red cliente no aprobada", "NO_AUTORIZADA"),
]


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def ipv4_bytes(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack("!" + "H" * (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(src: str, dst: str, ethertype: int, payload: bytes) -> bytes:
    frame = mac_bytes(dst) + mac_bytes(src) + struct.pack("!H", ethertype) + payload
    return frame + (b"\x00" * max(0, 60 - len(frame)))  # Ethernet minimum without FCS


def arp_announcement(ip: str, mac: str) -> bytes:
    # ARP reply gratuita, emisor real, sin asignar IP a otro equipo.
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    arp += mac_bytes(mac) + ipv4_bytes(ip)
    arp += b"\x00" * 6 + ipv4_bytes(ip)
    return eth(mac, "ff:ff:ff:ff:ff:ff", 0x0806, arp)


def ip_tcp(src_ip: str, dst_ip: str, sport: int, dport: int,
           seq: int, ack: int, flags: int, payload: bytes, ident: int,
           src_mac: str, dst_mac: str) -> bytes:
    sport, dport = int(sport), int(dport)
    # TCP sin opciones, ventana 8192, checksum correcto con seudocabecera IPv4.
    tcp0 = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                       (5 << 12) | flags, 8192, 0, 0)
    length = len(tcp0) + len(payload)
    pseudo = ipv4_bytes(src_ip) + ipv4_bytes(dst_ip) + struct.pack("!BBH", 0, 6, length)
    tcs = checksum(pseudo + tcp0 + payload)
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                      (5 << 12) | flags, 8192, tcs, 0) + payload
    total_len = 20 + len(tcp)
    ip0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                      0x4000, 64, 6, 0, ipv4_bytes(src_ip), ipv4_bytes(dst_ip))
    ics = checksum(ip0)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                       0x4000, 64, 6, ics, ipv4_bytes(src_ip), ipv4_bytes(dst_ip))
    return eth(src_mac, dst_mac, 0x0800, ipv4 + tcp)


def modbus_request(tx: int) -> bytes:
    # MBAP: TID, protocol=0, length=6, unit=1, function=3, addr=0, qty=2
    return struct.pack("!HHHBBHH", tx, 0, 6, 1, 3, 0, 2)


def modbus_response(tx: int, count: int) -> bytes:
    # MBAP + función 3 + 2 holding registers con valores sintéticos no operativos.
    return struct.pack("!HHHBBBHH", tx, 0, 7, 1, 3, 4, 100 + count, 250 + count)


# Tramas TPKT+COTP+S7 setup (ilustrativas; no PLC real ni sesión verificada).
S7_REQ = bytes.fromhex("0300001902f08032010000000100080000f0000001000101e0")
S7_RESP = bytes.fromhex("0300001b02f080320300000001000800000000f0000001000101e0")


def app_payload(port: int, destination: str, n: int) -> tuple[bytes, bytes]:
    if port == 502:
        return modbus_request(1 + n), modbus_response(1 + n, n)
    if port == 102:
        return S7_REQ, S7_RESP
    if port == 80:
        req = f"GET / HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n".encode("ascii")
        return req, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    if port == 22:
        return b"SSH-2.0-SyntheticClient\r\n", b"SSH-2.0-SyntheticOTDevice\r\n"
    if port == 23:
        return b"\r\n", b"Synthetic Telnet endpoint\r\n"
    # HTTPS: solo handshake TCP, NO pretendemos fabricar TLS válido.
    return b"", b""


def endpoint(name: str) -> tuple[str, str]:
    if name in DEVICES:
        return DEVICES[name][0], DEVICES[name][1]
    if name == EXTERNAL_IP:
        # El segmento OT ve los paquetes reenviados por el firewall; NO ARP del cliente.
        return name, DEVICES["FW-OT-01"][1]
    raise ValueError(f"Extremo desconocido: {name}")


def tcp_session(packets: list, base_ts: float, client: str, server: str,
                port: int, sample_no: int, flow_no: int) -> None:
    cip, cmac = endpoint(client)
    sip, smac = endpoint(server)
    sport = 41000 + flow_no * 100 + sample_no  # diferente por sesión; la app agrega por IP/puerto servicio.
    cseq = 1000000 + flow_no * 100000 + sample_no * 1000
    sseq = 5000000 + flow_no * 100000 + sample_no * 1000
    ident = 1000 + flow_no * 200 + sample_no * 8
    req, res = app_payload(port, sip, sample_no)

    def add(delay: float, src_ip: str, dst_ip: str, sp: int, dp: int,
            seq: int, ack: int, flags: int, payload: bytes,
            srcmac: str, dstmac: str, offset: int) -> None:
        packets.append((base_ts + delay, ip_tcp(src_ip, dst_ip, sp, dp,
                                                 seq, ack, flags, payload,
                                                 ident + offset, srcmac, dstmac)))

    add(0.00, cip, sip, sport, port, cseq, 0, 0x02, b"", cmac, smac, 0)        # SYN
    add(0.03, sip, cip, port, sport, sseq, cseq+1, 0x12, b"", smac, cmac, 1) # SYN+ACK
    add(0.06, cip, sip, sport, port, cseq+1, sseq+1, 0x10, b"", cmac, smac, 2) # ACK
    if req:
        add(0.09, cip, sip, sport, port, cseq+1, sseq+1, 0x18, req, cmac, smac, 3)
        cseq += len(req)
    if res:
        add(0.14, sip, cip, port, sport, sseq+1, cseq+1, 0x18, res, smac, cmac, 4)
        sseq += len(res)
    add(0.18, cip, sip, sport, port, cseq+1, sseq+1, 0x10, b"", cmac, smac, 5)


def pnrt_frame(src: str, dst: str, cycle: int) -> bytes:
    # EtherType 0x8892 = PROFINET; FrameID RT clase 1.
    # Payload de demostración, no una pila completa ni decodificación certificada.
    src_mac = DEVICES[src][1]
    dst_mac = DEVICES[dst][1]
    frame_id = struct.pack("!H", 0x8000)
    user_data = b"\x00" * 40
    trailer = struct.pack("!HBB", cycle & 0xFFFF, 0x00, 0x35)
    return eth(src_mac, dst_mac, 0x8892, frame_id + user_data + trailer)


def local_start(day: int) -> float:
    return datetime(2026, 11, day, 8, 0, 0, tzinfo=TZ_CO).timestamp()


def build_capture(day: int, path: Path) -> dict:
    assert day in (1, 2)
    start = local_start(day)
    packets: list[tuple[float, bytes]] = []
    for i, (asset, (ip, mac, _, _)) in enumerate(DEVICES.items()):
        # Asegura un solo mapeo ARP IP<->MAC por equipo, por día.
        for offset in (0, 7200):
            packets.append((start + offset + i * 0.1, arp_announcement(ip, mac)))

    flows = NORMAL + (DAY2_EXTRA if day == 2 else [])
    for fi, (client, server, port, _, _) in enumerate(flows):
        # 6 sesiones/turno para operación y 1-2 para administración o eventos nuevos.
        runs = 6 if fi < 5 else (2 if fi < 10 else 1)
        for j in range(runs):
            # Eventos extraordinarios hacia mitad del turno del segundo día.
            when = 600 + fi * 10 + j * (1600 if fi < 5 else 4800)
            if fi >= len(NORMAL):
                when = 7800 + (fi - len(NORMAL)) * 120
            tcp_session(packets, start + when, client, server, port, j, fi)

    # Comunicación real de proceso con los Phoenix: PROFINET (no Modbus).
    # Se observarán a nivel Ethernet, pero el analizador actual no la registra como flujo.
    for i in range(16):
        offset = 320 + i * 950
        packets.append((start + offset + 0.1,
                        pnrt_frame("PLC-MEZ-01", "IO-MEZ-01", i)))
        packets.append((start + offset + 0.2,
                        pnrt_frame("IO-MEZ-01", "PLC-MEZ-01", i)))
        packets.append((start + offset + 0.3,
                        pnrt_frame("PLC-ENV-01", "IO-ENV-01", i)))
        packets.append((start + offset + 0.4,
                        pnrt_frame("IO-ENV-01", "PLC-ENV-01", i)))

    packets.sort(key=lambda x: x[0])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        # PCAP estándar, endian little, timestamp en microsegundos, DLT_EN10MB.
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = round((ts - sec) * 1_000_000)
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
    return {"day": day, "interfaces_expected": 12, "flow_keys_expected": len(flows),
            "packets": len(packets), "path": str(path)}


def write_tsv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(headers)
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    out = args.output.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert len(DEVICES) == 12
    assert len({x[0] for x in DEVICES.values()}) == len(DEVICES)
    assert len({x[1] for x in DEVICES.values()}) == len(DEVICES)

    names = (
        "visor_ot_demo_dia1_operacion.pcap",
        "visor_ot_demo_dia2_operacion_y_nuevos_flujos.pcap",
    )
    for day, filename in enumerate(names, start=1):
        summary = build_capture(day, out / filename)
        print(f"Día {day}: {summary['path']} | paquetes={summary['packets']} | "
              f"interfaces={summary['interfaces_expected']} | "
              f"comunicaciones esperadas={summary['flow_keys_expected']}")

    write_tsv(out / "visor_ot_asociaciones_interfaces.tsv",
              ["hardware", "ip", "mac", "software_asociado", "sistemas_ot"],
              [[asset, ip, mac, software, ", ".join(sistemas)]
               for asset, (ip, mac, software, sistemas) in DEVICES.items()])
    flows_all = NORMAL + DAY2_EXTRA
    write_tsv(out / "visor_ot_baseline_comunicaciones.tsv",
              ["origen", "destino", "ip_origen", "ip_destino", "transporte", "puerto_destino",
               "dias", "funcion", "estado_propuesto_por_analista"],
              [[cli, srv, endpoint(cli)[0], endpoint(srv)[0], "TCP", str(port),
                "1, 2" if i < len(NORMAL) else "2", purpose, state]
               for i, (cli, srv, port, purpose, state) in enumerate(flows_all)])
    print(f"Tablas de referencia: {out / 'visor_ot_asociaciones_interfaces.tsv'}")
    print(f"                       {out / 'visor_ot_baseline_comunicaciones.tsv'}")


if __name__ == "__main__":
    main()
