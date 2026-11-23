#!/usr/bin/env python3
"""Retira SOLO el resultado JSON del dia 2 en la salida aislada del demo.

El PCAP fisico permanece. La carpeta output original tambien permanece.
Obtener --pcap-id de: python manage.py preparar_demo_plc_mez --json
"""
import argparse
import os
from pathlib import Path
import re

STORAGE = Path.home() / "visor_ot_resguardos_demo"
OUTPUT_DEMO = STORAGE / "output_activo"
CONFIRMATION = "QUITAR_RESULTADO_DIA2"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap-id", required=True,
                        help="ID hex de 16 caracteres mostrado por la vista previa Django.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()

    if not re.fullmatch(r"[a-f0-9]{16}", args.pcap_id):
        parser.error("El PCAP ID debe contener exactamente 16 caracteres hexadecimales.")
    if not os.environ.get("DB_NAME", "").endswith("_demo"):
        parser.error("Primero activa el entorno demo en esta terminal.")
    if OUTPUT_DEMO.is_symlink():
        parser.error("La carpeta output_activo no debe ser un enlace simbolico.")
    actual = os.environ.get("PASSIVE_ANALYZER_OUTPUT_DIR", "")
    if not actual or Path(actual).resolve() != OUTPUT_DEMO.resolve():
        parser.error("PASSIVE_ANALYZER_OUTPUT_DIR no apunta a la copia aislada del demo.")
    if not OUTPUT_DEMO.is_dir():
        parser.error("No existe output_activo. Ejecuta crear-demo primero.")

    analysis = OUTPUT_DEMO / (args.pcap_id + ".json")
    metadata = OUTPUT_DEMO / (args.pcap_id + ".meta.json")
    for path in (analysis, metadata):
        if path.is_symlink():
            parser.error("Se encontro un enlace simbolico inesperado: " + str(path))
        print(("Encontrado: " if path.is_file() else "No existe: ") + str(path))
    if not args.execute:
        print("Vista previa: no se modifico ningun archivo.")
        return
    if args.confirm != CONFIRMATION:
        parser.error("Se requiere --confirm " + CONFIRMATION)
    if not analysis.is_file():
        parser.error("El JSON del dia 2 no existe; revisa el PCAP ID.")
    analysis.unlink()
    metadata.unlink(missing_ok=True)
    print("JSON de la segunda captura retirado de la COPIA del demo.")
    print("PCAP original, salida integral y base PostgreSQL intactos.")


if __name__ == "__main__":
    main()
