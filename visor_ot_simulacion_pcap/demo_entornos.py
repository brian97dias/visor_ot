#!/usr/bin/env python3
"""Resguardos y restauracion de la demo de VISOR OT (PostgreSQL + output FastAPI).

Las operaciones de restauracion SOLO usan una base separada _demo; nunca
restauran ni borran la base original. No guardes los dumps en Git.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

REPO = Path(__file__).resolve().parents[1]
ENV_FILE = REPO / "web_app" / "backend" / ".env"
DEFAULT_OUTPUT = REPO / "passive_analyzer" / "output"
STORAGE = Path.home() / "visor_ot_resguardos_demo"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*$")


def fail(message):
    raise SystemExit("ERROR: " + message)


def config():
    try:
        from dotenv import dotenv_values
    except ImportError:
        fail("Activa primero web_app/backend/.venv (requiere python-dotenv).")
    # Django reads process environment first and loads .env only as fallback.
    # Match that order, rather than insisting that every value is in .env.
    values = dotenv_values(ENV_FILE) if ENV_FILE.is_file() else {}

    def effective(key):
        return os.environ.get(key) or values.get(key) or ""

    name = effective("DB_NAME").strip()
    user = effective("DB_USER").strip()
    missing = [key for key, value in (("DB_NAME", name), ("DB_USER", user)) if not value]
    if missing:
        fail(
            "Configuracion PostgreSQL incompleta: faltan "
            + ", ".join(missing)
            + ". Verifica que Django tenga esas variables en su entorno "
            "o en web_app/backend/.env (no compartas contrasenas)."
        )
    if not IDENT.fullmatch(name) or not IDENT.fullmatch(user):
        fail(
            "DB_NAME o DB_USER contiene caracteres no admitidos. "
            "Solo se permiten letras, numeros y guion bajo."
        )
    if name.endswith("_demo"):
        fail("DB_NAME ya termina en _demo: activa la base ORIGINAL para crear los resguardos.")
    demo = name + "_demo"
    if not IDENT.fullmatch(demo) or len(demo) > 63 or demo == name:
        fail("No se puede construir un nombre seguro para la base demo.")
    return {
        "original": name, "demo": demo, "user": user,
        "host": effective("DB_HOST") or "127.0.0.1",
        "port": effective("DB_PORT") or "5432",
        "password": effective("DB_PASSWORD"),
    }


def pg_env(cfg):
    env = os.environ.copy()
    env["PGPASSWORD"] = cfg["password"]
    env["PGCONNECT_TIMEOUT"] = "10"
    return env


def run(command, cfg, quiet=False):
    for tool in ("psql", "pg_dump", "pg_restore", "createdb"):
        if shutil.which(tool) is None:
            fail("No se encontro " + tool + ". Instala postgresql-client.")
    return subprocess.run(
        command, env=pg_env(cfg), check=True,
        stdout=subprocess.DEVNULL if quiet else None,
    )


def conn(cfg):
    return ["-h", cfg["host"], "-p", str(cfg["port"]), "-U", cfg["user"]]


def database_exists(cfg, database):
    # Database names have already been restricted to safe SQL identifiers.
    query = "SELECT 1 FROM pg_database WHERE datname = '" + database + "';"
    out = subprocess.run(
        ["psql", *conn(cfg), "-d", "postgres", "-At", "-c", query],
        env=pg_env(cfg), capture_output=True, text=True, check=True,
    )
    return out.stdout.strip() == "1"


def hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for piece in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(piece)
    return digest.hexdigest()


def write_snapshot(cfg, label, database, output_dir):
    dest = STORAGE / label
    if dest.exists():
        fail("Ya existe el resguardo " + str(dest) + ". No se sobrescribio.")
    if not output_dir.is_dir():
        fail("No existe el output del analizador: " + str(output_dir))
    STORAGE.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = Path(tempfile.mkdtemp(prefix=".snapshot_", dir=STORAGE))
    try:
        dump = temp / "database.dump"
        print("Resguardando PostgreSQL:", database)
        run(["pg_dump", *conn(cfg), "-d", database, "-Fc", "-f", str(dump)], cfg)
        run(["pg_restore", "-l", str(dump)], cfg, quiet=True)
        print("Resguardando resultados del analizador:", output_dir)
        shutil.copytree(output_dir, temp / "output")
        metadata = {
            "database": database,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "dump_sha256": hash_file(dump),
            "dump_bytes": dump.stat().st_size,
            "source_output": str(output_dir),
        }
        (temp / "manifest.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        temp.rename(dest)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise
    print("Resguardo guardado en:", dest)
    print("SHA-256:", metadata["dump_sha256"])


def read_snapshot(label):
    folder = STORAGE / label
    try:
        meta = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        fail("No existe el resguardo completo: " + str(folder))
    dump = folder / "database.dump"
    if not dump.is_file() or not (folder / "output").is_dir():
        fail("Faltan componentes del resguardo: " + str(folder))
    if hash_file(dump) != meta.get("dump_sha256"):
        fail("El checksum del dump no coincide. Restauracion cancelada.")
    return dump, folder / "output", meta


def activation_file(cfg):
    # Sourcing this file in EVERY backend / worker / analyzer terminal keeps
    # the lab database and isolated analyzer output consistently selected.
    file = STORAGE / "activar_demo.sh"
    content = (
        "#!/usr/bin/env bash\n"
        "# Usar: source ~/visor_ot_resguardos_demo/activar_demo.sh\n"
        "export DB_NAME=" + shlex.quote(cfg["demo"]) + "\n"
        "export PASSIVE_ANALYZER_OUTPUT_DIR=" +
        shlex.quote(str(STORAGE / "output_activo")) + "\n"
        "echo 'VISOR OT DEMO: DB_NAME='\"$DB_NAME\"\n"
    )
    file.write_text(content, encoding="utf-8")
    file.chmod(0o600)


def replace_output(snapshot_output):
    dest = STORAGE / "output_activo"
    # This path is fixed below the backup folder, never the repo output.
    if dest.is_symlink():
        fail("output_activo no puede ser un enlace simbolico.")
    pending = Path(tempfile.mkdtemp(prefix=".output_", dir=STORAGE))
    try:
        shutil.copytree(snapshot_output, pending / "output")
        if dest.exists():
            shutil.rmtree(dest)
        (pending / "output").rename(dest)
    finally:
        shutil.rmtree(pending, ignore_errors=True)


def restore_snapshot(cfg, label, create_only=False):
    dump, output, meta = read_snapshot(label)
    expected = cfg["original"] if label == "integral" else cfg["demo"]
    if meta.get("database") != expected:
        fail("El resguardo pertenece a otra base: " + str(meta.get("database")))
    demo = cfg["demo"]
    exists = database_exists(cfg, demo)
    if create_only and exists:
        fail("La base demo ya existe. Usa restaurar-integral-demo --confirmar.")
    if not exists:
        print("Creando base separada:", demo)
        try:
            run(["createdb", *conn(cfg), "-O", cfg["user"], demo], cfg)
        except subprocess.CalledProcessError:
            fail("El usuario no pudo crear la base demo; verifica el privilegio CREATEDB.")
    print("Restaurando SOLO en:", demo)
    run([
        "pg_restore", *conn(cfg), "-d", demo, "--clean", "--if-exists",
        "--single-transaction", "--exit-on-error", "--no-owner",
        "--no-acl", str(dump),
    ], cfg)
    replace_output(output)
    activation_file(cfg)
    print("Base original intacta:", cfg["original"])
    print("Salida aislada:", STORAGE / "output_activo")
    print("En cada terminal de Django, worker y analizador:")
    print("  source " + str(STORAGE / "activar_demo.sh"))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("accion", choices=(
        "estado", "resguardar-integral", "crear-demo",
        "guardar-inicio-demo", "restaurar-inicio-demo",
        "restaurar-integral-demo",
    ))
    parser.add_argument("--confirmar", action="store_true",
                        help="Confirma restauracion sobre la base demo existente.")
    parser.add_argument("--output-origen", type=Path, default=DEFAULT_OUTPUT,
                        help="Carpeta output real para el resguardo integral.")
    args = parser.parse_args()
    cfg = config()
    if args.accion == "estado":
        print("Base INTEGRA (nunca se restaura automaticamente):", cfg["original"])
        print("Base de ensayo:", cfg["demo"])
        for label in ("integral", "inicio_demo"):
            print(label + ":", "Guardado" if (STORAGE / label / "manifest.json").exists()
                  else "No existe")
        print("Output aislado:", STORAGE / "output_activo")
        print("Carpeta privada:", STORAGE)
        return
    if args.accion == "resguardar-integral":
        write_snapshot(cfg, "integral", cfg["original"], args.output_origen.resolve())
    elif args.accion == "crear-demo":
        restore_snapshot(cfg, "integral", create_only=True)
    elif args.accion == "guardar-inicio-demo":
        if not database_exists(cfg, cfg["demo"]):
            fail("Primero crea la base demo.")
        write_snapshot(cfg, "inicio_demo", cfg["demo"], STORAGE / "output_activo")
    elif args.accion in ("restaurar-inicio-demo", "restaurar-integral-demo"):
        if not args.confirmar:
            fail("Restauracion cancelada: requiere --confirmar. Deten los servicios primero.")
        label = "inicio_demo" if args.accion == "restaurar-inicio-demo" else "integral"
        restore_snapshot(cfg, label)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        fail("Fallo PostgreSQL (codigo " + str(error.returncode) +
             "). No se ha tocado la base integral.")
