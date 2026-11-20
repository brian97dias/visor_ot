#!/usr/bin/env python3
"""Mide lecturas concurrentes contra una instancia local de VISOR OT.

Desde la raíz del repositorio, con Django y PostgreSQL en ejecución y con
datos de laboratorio en el inventario y el catálogo CVE:

    python3 visor_ot_simulacion_pcap/prueba_concurrencia_visor_ot.py \
        --revision "$(git rev-parse HEAD)" \
        --output "$HOME/resultados_concurrencia_visor_ot.json"

Cada cliente realiza una lectura por vez con una nueva conexión HTTP.
La autenticación y el calentamiento quedan fuera de la medición.
El informe JSON contiene métricas agregadas y conteos, sin credenciales,
tokens ni registros del inventario o del catálogo.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from getpass import getpass
from http.client import HTTPConnection, HTTPException
import json
from math import ceil
from pathlib import Path
from threading import Barrier
from time import perf_counter, sleep


HOST = "127.0.0.1"
LOGIN = "/api/auth/login/"
ENDPOINTS = {
    "inventario": ("/api/assets/", "assets"),
    "catalogo_cve": ("/api/vulnerabilities/cves/", "results"),
}


def request(port, timeout, route, *, token=None, credentials=None):
    headers = {"Accept": "application/json"}
    body = None
    method = "GET"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if credentials is not None:
        method = "POST"
        headers["Content-Type"] = "application/json"
        body = json.dumps(credentials)

    connection = HTTPConnection(HOST, port, timeout=timeout)
    try:
        connection.request(method, route, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.getheader("Content-Type", ""), response.read()
    finally:
        connection.close()


def login(port, timeout, credentials):
    status, _, body = request(port, timeout, LOGIN, credentials=credentials)
    if status != 200:
        raise ValueError(f"Inicio de sesión rechazado (HTTP {status})")
    token = json.loads(body).get("access")
    if not isinstance(token, str) or not token:
        raise ValueError("El inicio de sesión no devolvió un token de acceso")
    return token


def warmup(port, timeout, route, key, token):
    status, _, body = request(port, timeout, route, token=token)
    if status != 200:
        raise ValueError(f"{route} devolvió HTTP {status} en la solicitud previa")
    data = json.loads(body)
    rows = data.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{route} no devolvió la lista esperada '{key}'")
    if not rows:
        raise ValueError(f"{route} devolvió una lista vacía. Carga datos de laboratorio.")
    return {
        "registros_en_respuesta": len(rows),
        "total_reportado": data.get("count", len(rows)),
    }


def measure(port, timeout, route, token, clients, seconds):
    started = 0.0

    def start_clock():
        nonlocal started
        started = perf_counter()

    start = Barrier(clients, action=start_clock)

    def read_repeatedly():
        latencies = []
        errors = Counter()
        start.wait()
        deadline = started + seconds
        while perf_counter() < deadline:
            before = perf_counter()
            try:
                status, content_type, _ = request(port, timeout, route, token=token)
                if status != 200:
                    errors[f"HTTP {status}"] += 1
                elif not content_type.lower().startswith("application/json"):
                    errors["Tipo de contenido inesperado"] += 1
                else:
                    latencies.append((perf_counter() - before) * 1000)
            except TimeoutError:
                errors["Tiempo de espera agotado"] += 1
            except (OSError, HTTPException) as exc:
                errors[type(exc).__name__] += 1
        return latencies, errors

    latencies = []
    errors = Counter()
    with ThreadPoolExecutor(max_workers=clients) as pool:
        futures = [pool.submit(read_repeatedly) for _ in range(clients)]
        for future in futures:
            client_latencies, client_errors = future.result()
            latencies.extend(client_latencies)
            errors.update(client_errors)
    elapsed = perf_counter() - started

    latencies.sort()
    success = len(latencies)
    error_count = sum(errors.values())
    total = success + error_count
    return {
        "duracion_real_segundos": round(elapsed, 3),
        "solicitudes": total,
        "respuestas_ok": success,
        "errores": error_count,
        "errores_por_tipo": dict(errors),
        "porcentaje_error": round(100 * error_count / total, 2) if total else None,
        "respuestas_ok_por_segundo": round(success / elapsed, 2),
        "p50_ms": round(latencies[ceil(0.50 * success) - 1], 2) if success else None,
        "p95_ms": round(latencies[ceil(0.95 * success) - 1], 2) if success else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000, help="Puerto local de Django")
    parser.add_argument("--seconds", type=int, default=30, choices=range(1, 121),
                        metavar="1-120", help="Ventana de envío por nivel y repetición")
    parser.add_argument("--repetitions", type=int, default=2, choices=range(1, 6),
                        metavar="1-5", help="Repeticiones por nivel y operación")
    parser.add_argument("--revision", default="sin registrar", help="Commit del código probado")
    parser.add_argument("--output", type=Path, default=Path("resultados_concurrencia_visor_ot.json"))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port debe estar entre 1 y 65535")
    if args.output.exists():
        parser.error(f"El archivo {args.output} ya existe. Usa --output con otro nombre.")

    credentials = {
        "username": input("Usuario de VISOR OT: ").strip(),
        "password": getpass("Contraseña de VISOR OT: "),
    }
    timeout = 20
    report = {
        "inicio_utc": datetime.now(timezone.utc).isoformat(),
        "backend": f"http://{HOST}:{args.port}",
        "revision": args.revision,
        "segundos_por_ronda": args.seconds,
        "timeout_socket_segundos": timeout,
        "repeticiones_por_nivel": args.repetitions,
        "completo": False,
        "rondas": [],
    }
    try:
        token = login(args.port, timeout, credentials)
        report["datos"] = {
            name: warmup(args.port, timeout, route, key, token)
            for name, (route, key) in ENDPOINTS.items()
        }
        with args.output.open("x", encoding="utf-8") as output:
            try:
                for repetition in range(1, args.repetitions + 1):
                    for name, (route, key) in ENDPOINTS.items():
                        for clients in (1, 5, 10):
                            token = login(args.port, timeout, credentials)
                            warmup(args.port, timeout, route, key, token)
                            print(f"Ronda {repetition} · {name} · {clients} clientes", flush=True)
                            metrics = measure(args.port, timeout, route, token, clients, args.seconds)
                            report["rondas"].append({
                                "repeticion": repetition,
                                "operacion": name,
                                "ruta": route,
                                "clientes": clients,
                                **metrics,
                            })
                            sleep(1)
                report["completo"] = True
            finally:
                json.dump(report, output, ensure_ascii=False, indent=2)
                output.write("\n")
    except (OSError, HTTPException, ValueError, AttributeError) as exc:
        parser.exit(1, f"Prueba interrumpida: {exc}\n")
    except KeyboardInterrupt:
        parser.exit(130, "Prueba interrumpida por el usuario.\n")
    print(f"Resultados guardados en {args.output.resolve()}")


if __name__ == "__main__":
    main()
