#!/usr/bin/env python3
"""Punto de restauracion SOLO de PostgreSQL para ensayos de VISOR OT.

Uso (tras activar_demo.sh):
  python visor_ot_simulacion_pcap/demo_bd.py guardar
  python visor_ot_simulacion_pcap/demo_bd.py estado
  python visor_ot_simulacion_pcap/demo_bd.py restaurar --confirmar
  python visor_ot_simulacion_pcap/demo_bd.py restaurar-integral --confirmar

Ambas restauraciones afectan exclusivamente la base _demo.
No modifica los archivos de passive_analyzer/output ni el respaldo integral.
"""
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from dotenv import dotenv_values


REPO = Path(__file__).resolve().parents[1]
ENV_PATH = REPO / "web_app" / "backend" / ".env"
SNAPSHOT = Path.home() / "visor_ot_resguardos_demo" / "inicio_demo_bd"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9-]*$")


def error(message):
    raise SystemExit("ERROR: " + message)


def configuracion():
    valores = dotenv_values(ENV_PATH) if ENV_PATH.exists() else {}
    original = str(valores.get("DB_NAME") or "").strip()
    demo = os.getenv("DB_NAME", "").strip()
    if not original or not IDENT.fullmatch(original):
        error("DB_NAME de .env no es valido. No se modifica nada.")
    if demo != original + "_demo":
        error("Activa activar_demo.sh en esta terminal. DB_NAME debe ser "
              + original + "_demo; actual: " + (demo or "(sin configurar)"))
    usuario = str(os.getenv("DB_USER") or valores.get("DB_USER") or "").strip()
    if not usuario or not IDENT.fullmatch(usuario):
        error("DB_USER no es valido.")
    return {
        "original": original, "demo": demo,
        "user": usuario,
        "host": str(os.getenv("DB_HOST") or valores.get("DB_HOST") or "127.0.0.1"),
        "port": str(os.getenv("DB_PORT") or valores.get("DB_PORT") or "5432"),
        "password": str(os.getenv("DB_PASSWORD") or valores.get("DB_PASSWORD") or ""),
    }


def comando(config, name):
    if shutil.which(name) is None:
        error("No se encontro el cliente PostgreSQL: " + name)
    return [name, "-h", config["host"], "-p", config["port"], "-U", config["user"]]


def ejecutar(config, args, *, capturar=False):
    env = os.environ.copy()
    env["PGPASSWORD"] = config["password"]
    env["PGCONNECT_TIMEOUT"] = "10"
    try:
        return subprocess.run(
            args, env=env, check=True,
            stdout=subprocess.PIPE if capturar else None,
            stderr=subprocess.PIPE if capturar else None,
            text=capturar,
        )
    except subprocess.CalledProcessError as exc:
        if capturar and exc.stderr:
            print(exc.stderr.strip())
        error("Fallo un comando PostgreSQL. El backup permanece intacto; "
              "comprueba el estado de la base demo.")


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def validar_snapshot(config, *, integral=False):
    carpeta = (SNAPSHOT.parent / "integral") if integral else SNAPSHOT
    manifest = carpeta / "manifest.json"
    dump = carpeta / "database.dump"
    if not manifest.is_file() or not dump.is_file():
        error("No existe el respaldo solicitado: " + str(carpeta))
    try:
        info = json.loads(manifest.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        error("El manifiesto del backup no es legible.")
    esperado = config["original"] if integral else config["demo"]
    checksum = info.get("dump_sha256") if integral else info.get("sha256")
    if info.get("database") != esperado:
        error("El respaldo no pertenece a la base esperada: " + esperado)
    if not checksum or sha256(dump) != checksum:
        error("SHA-256 incorrecto. No se restaurara este archivo.")
    return dump, info


def guardar(config):
    if SNAPSHOT.exists():
        error("Ya existe inicio_demo_bd; no se sobrescribe. "
              "Usa 'restaurar' para regresar al inicio.")
    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporal = Path(tempfile.mkdtemp(prefix=".inicio_demo_bd_", dir=SNAPSHOT.parent))
    try:
        dump = temporal / "database.dump"
        print("Guardando SOLO PostgreSQL:", config["demo"])
        ejecutar(config, comando(config, "pg_dump") + [
            "-d", config["demo"], "-Fc", "-f", str(dump)
        ])
        ejecutar(config, ["pg_restore", "-l", str(dump)], capturar=True)
        info = {
            "database": config["demo"],
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "sha256": sha256(dump),
            "bytes": dump.stat().st_size,
        }
        (temporal / "manifest.json").write_text(
            json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        temporal.rename(SNAPSHOT)
    except Exception:
        shutil.rmtree(temporal, ignore_errors=True)
        raise
    print("Estado inicial guardado:", SNAPSHOT)
    print("No se modificaron archivos del analizador pasivo.")


def restaurar(config, *, integral=False):
    dump, _ = validar_snapshot(config, integral=integral)
    origen = "INTEGRAL" if integral else "INICIO DEL DEMO"
    print("Restaurando", origen, "UNICAMENTE en PostgreSQL:", config["demo"])
    print("Django y el worker NVD deben estar detenidos.")
    ejecutar(config, ["pg_restore",
                      "-h", config["host"], "-p", config["port"],
                      "-U", config["user"], "-d", config["demo"],
                      "--clean", "--if-exists", "--single-transaction",
                      "--exit-on-error", "--no-owner", "--no-acl", str(dump)])
    print("Restauracion finalizada. Base ORIGINAL intacta:", config["original"])
    print("Output de FastAPI SIN MODIFICACIONES.")
    if not integral:
        print("Para repetir el dia 2, borra manualmente los archivos")
        print("79a181a6fcbbf5ae.json y 79a181a6fcbbf5ae.meta.json")
        print("del directorio passive_analyzer/output/.")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("accion", choices=["estado", "guardar", "restaurar", "restaurar-integral"])
    parser.add_argument("--confirmar", action="store_true")
    args = parser.parse_args()
    config = configuracion()
    if args.accion == "estado":
        print("Original (NO se modifica):", config["original"])
        print("Base de ensayo:", config["demo"])
        print("Punto de inicio:", "GUARDADO" if (SNAPSHOT / "manifest.json").exists()
              else "NO CREADO")
        print("Respaldo integral:", "GUARDADO" if (SNAPSHOT.parent / "integral" / "manifest.json").exists()
              else "NO CREADO")
        print("Salida del analizador: por defecto en passive_analyzer/output/")
    elif args.accion == "guardar":
        guardar(config)
    else:
        if not args.confirmar:
            error("La restauracion requiere --confirmar; detente si hay servicios activos.")
        restaurar(config, integral=(args.accion == "restaurar-integral"))


if __name__ == "__main__":
    main()
