#!/usr/bin/env python3
"""Verificación reproducible de las comunicaciones del laboratorio sintético VISOR OT.

Ejemplo, desde la raíz de visor_ot con el venv de passive_analyzer activado:
    python /ruta/validar_precision_visor_ot.py --repo .

No envía paquetes, no accede a NVD, no altera inventario ni base de datos.
Genera PCAP temporalmente y ejecuta el analizador de la rama presente en el equipo.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PNRT_PAIRS = (("PLC-MEZ-01", "IO-MEZ-01"), ("PLC-ENV-01", "IO-ENV-01"))
TCP_SERVICES = {102: "S7", 502: "Modbus/TCP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS"}


def load_generator(path: Path):
    spec = importlib.util.spec_from_file_location("visor_ot_pcap_generator", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No fue posible cargar el generador: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_communications(generator, day: int):
    flows = list(generator.NORMAL) + (list(generator.DAY2_EXTRA) if day == 2 else [])
    expected = {}
    for client, server, port, _purpose, _policy in flows:
        key = (generator.endpoint(client)[0], generator.endpoint(server)[0], "TCP", int(port))
        expected[key] = TCP_SERVICES.get(port)
    for source, target in PNRT_PAIRS:
        key = (generator.endpoint(source)[0], generator.endpoint(target)[0], "ETHERNET", 0)
        expected[key] = "PROFINET RT"
    return expected


def ratio(n, d):
    return n / d if d else None


def fmt(value):
    return f"{value * 100:.2f}%" if value is not None else "N/A"


def validate_day(generator, analyze_pcap, day: int, folder: Path):
    path = folder / f"dia{day}.pcap"
    info = generator.build_capture(day, path)
    interface_rows, communication_rows = analyze_pcap(path)
    expected = expected_communications(generator, day)
    observed = {
        (row["client_ip"], row["server_ip"], row["transport_protocol"], int(row["service_port"])): row
        for row in communication_rows.values()
    }
    correct, unexpected, omitted = set(observed) & set(expected), set(observed) - set(expected), set(expected) - set(observed)
    true_positive, false_positive, false_negative = len(correct), len(unexpected), len(omitted)
    precision = ratio(true_positive, true_positive + false_positive)
    recall = ratio(true_positive, true_positive + false_negative)
    f1 = ratio(2 * true_positive, 2 * true_positive + false_positive + false_negative)
    expected_macs = {mac.lower() for _, mac, _, _ in generator.DEVICES.values()}
    detected_macs = {mac.lower() for mac in interface_rows}
    arp_matches = sum(1 for ip, mac, _, _ in generator.DEVICES.values()
                      if ip in interface_rows.get(mac.lower(), {}).get("ips", set()))
    wrong_services = [dict(key=list(k), found=observed[k].get("service"), expected=expected[k])
                      for k in sorted(correct) if observed[k].get("service") != expected[k]]
    wrong_syn_orientation = [list(k) for k in sorted(correct)
                             if k[2] == "TCP" and observed[k].get("role_source") != "tcp_syn"]
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "dia": day,
        "paquetes_en_archivo": info["packets"],
        "sha256_pcap": sha,
        "interfaces_esperadas": len(expected_macs),
        "interfaces_observadas": len(detected_macs),
        "interfaces_correctas": len(expected_macs & detected_macs),
        "interfaces_inesperadas": len(detected_macs - expected_macs),
        "asociaciones_arp_correctas": arp_matches,
        "comunicaciones_esperadas": len(expected),
        "comunicaciones_observadas": len(observed),
        "VP": true_positive, "FP": false_positive, "FN": false_negative,
        "precision": precision, "exhaustividad": recall, "f1": f1,
        "servicios_incorrectos": wrong_services,
        "tcp_no_orientadas_por_syn": wrong_syn_orientation,
        "comunicaciones_inesperadas": [list(k) for k in sorted(unexpected)],
        "comunicaciones_omitidas": [list(k) for k in sorted(omitted)],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."), help="Ruta a la raíz del repositorio visor_ot")
    parser.add_argument("--json", type=Path, help="Guardar resultados como JSON sin modificar el repositorio")
    args = parser.parse_args()
    repo = args.repo.resolve()
    gen_path = repo / "visor_ot_simulacion_pcap" / "generar_pcaps_visor_ot.py"
    if not gen_path.is_file():
        raise SystemExit(f"No se encuentra el generador: {gen_path}")
    try:
        import scapy  # noqa: F401
    except ImportError:
        raise SystemExit("Falta Scapy. Activa el entorno virtual de passive_analyzer e instala requirements.txt")
    sys.path.insert(0, str(repo / "passive_analyzer"))
    from analyzer import analyze_pcap
    generator = load_generator(gen_path)
    assert len(generator.DEVICES) == 12, "El inventario de referencia ya no contiene 12 equipos"
    with tempfile.TemporaryDirectory(prefix="visor_ot_validacion_") as tmp:
        results = [validate_day(generator, analyze_pcap, day, Path(tmp)) for day in (1, 2)]
    try:
        revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True,
                                           stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "no_disponible"
    tp, fp, fn = (sum(r[x] for r in results) for x in ("VP", "FP", "FN"))
    data = {"revision_git": revision, "nota": "Resultados exclusivos del escenario sintético generado; no generalizables a tráfico industrial real", "dias": results,
            "global_por_jornada": {"VP": tp, "FP": fp, "FN": fn, "precision": ratio(tp,tp+fp),
                                    "exhaustividad": ratio(tp,tp+fn), "f1": ratio(2*tp,2*tp+fp+fn)}}
    print(f"VISOR OT - Comparación del analizador contra la referencia sintética (Git {revision[:12]})")
    for x in results:
        print(f"Día {x['dia']}: paquetes={x['paquetes_en_archivo']}, interfaces={x['interfaces_observadas']}/{x['interfaces_esperadas']}, ARP={x['asociaciones_arp_correctas']}/12")
        print(f"       comunicaciones={x['comunicaciones_observadas']}/{x['comunicaciones_esperadas']}, VP={x['VP']} FP={x['FP']} FN={x['FN']}")
        print(f"       precisión={fmt(x['precision'])}, exhaustividad={fmt(x['exhaustividad'])}, F1={fmt(x['f1'])}")
        if x["comunicaciones_inesperadas"] or x["comunicaciones_omitidas"]:
            print("       INESPERADAS:",x["comunicaciones_inesperadas"],"OMITIDAS:",x["comunicaciones_omitidas"])
        if x["servicios_incorrectos"] or x["tcp_no_orientadas_por_syn"]:
            print("       ADVERTENCIA: etiquetas incorrectas o TCP sin orientación SYN:",
                  x["servicios_incorrectos"],x["tcp_no_orientadas_por_syn"])
    g=data["global_por_jornada"]
    print(f"GLOBAL (sumando días como casos separados): VP={tp} FP={fp} FN={fn} ")
    print(f"       precisión={fmt(g['precision'])}, exhaustividad={fmt(g['exhaustividad'])}, F1={fmt(g['f1'])}")
    print("NOTA: las 28 relaciones esperadas por jornada incluyen 12 repetidas; el universo distinto es de 16.")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data,indent=2,ensure_ascii=False), encoding="utf-8")
        print(f"Archivo de evidencia: {args.json.resolve()}")

if __name__ == "__main__":
    main()
