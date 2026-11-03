"""Read-only phase and SQL profiler for the CVE catalogue HTTP view.

It executes the real Django/DRF view with an authenticated APIRequestFactory
request, including JSON rendering, without a server, NVD calls or DB writes.
Never enable this as an endpoint: it is an operator-only CLI diagnostic.
"""
from collections import defaultdict
from contextlib import ExitStack
from statistics import median
from time import perf_counter
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIRequestFactory, force_authenticate

from users.models import User
from vulnerabilities import cve_catalogue_views
from vulnerabilities.services import cve_catalogue_status, cve_technical_status


class PhaseTimer:
    """Nested instrumentation: inclusive and exclusive wall times per call."""

    def __init__(self):
        self.events = []
        self.stack = []

    def wrap(self, name, fn):
        def measured(*args, **kwargs):
            frame = {
                "name": name,
                "begin": perf_counter(),
                "children_ms": 0.0,
                "query_start": len(connection.queries_log),
            }
            self.stack.append(frame)
            try:
                return fn(*args, **kwargs)
            finally:
                elapsed = (perf_counter() - frame["begin"]) * 1000
                self.stack.pop()
                self.events.append({
                    "name": name,
                    "milliseconds": elapsed,
                    "exclusive_ms": max(0.0, elapsed - frame["children_ms"]),
                    "queries": len(connection.queries_log) - frame["query_start"],
                })
                if self.stack:
                    self.stack[-1]["children_ms"] += elapsed
        return measured

    def grouped(self):
        groups = defaultdict(lambda: {
            "calls": 0, "milliseconds": 0.0, "exclusive_ms": 0.0,
            "queries": 0,
        })
        for event in self.events:
            group = groups[event["name"]]
            group["calls"] += 1
            group["milliseconds"] += event["milliseconds"]
            group["exclusive_ms"] += event["exclusive_ms"]
            group["queries"] += event["queries"]
        return groups


class Command(BaseCommand):
    help = (
        "Mide GET /api/vulnerabilities/cves/ por fases y consultas SQL "
        "en la base actual, sin modificar datos ni consultar NVD."
    )

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True,
                            help="Usuario ANALYST/ADMIN existente; no requiere clave")
        parser.add_argument("--runs", type=int, default=2,
                            help="Repeticiones de la petición (por defecto 2)")
        parser.add_argument("--q", default="", help="Texto del buscador")
        parser.add_argument("--status", default="ALL",
                            help="Filtro de aplicabilidad (por defecto ALL)")
        parser.add_argument("--severity", default="ALL",
                            help="Filtro de severidad (por defecto ALL)")
        parser.add_argument("--page", type=int, default=1)
        parser.add_argument("--page-size", type=int, default=15)
        parser.add_argument("--slow-sql", type=int, default=3,
                            help="Número de consultas SQL más lentas a mostrar")

    def handle(self, *args, **options):
        if not 1 <= options["runs"] <= 10:
            raise CommandError("--runs debe estar entre 1 y 10.")
        if not 0 <= options["slow_sql"] <= 10:
            raise CommandError("--slow-sql debe estar entre 0 y 10.")
        user = get_user_model().objects.filter(
            username=options["username"], is_active=True,
            role__in=(User.Role.ADMIN, User.Role.ANALYST, User.Role.OPERATOR),
        ).first()
        if user is None:
            raise CommandError("El usuario indicado no existe o está inactivo.")
        filters = {
            "page": options["page"],
            "page_size": options["page_size"],
        }
        for key in ("q", "status", "severity"):
            val = options[key]
            if val and val != "ALL":
                filters[key] = val

        self.stdout.write("Medición de lectura del catálogo CVE (sin llamadas NVD)")
        self.stdout.write("Ruta: GET /api/vulnerabilities/cves/")
        self.stdout.write(f"Parámetros: {filters}")
        self.stdout.write(
            "Los tiempos incluyen la vista y serialización JSON en Django; "
            "no incluyen navegador, red ni renderizado React."
        )
        durations = []
        for number in range(1, options["runs"] + 1):
            timer = PhaseTimer()
            tracked = (
                (cve_catalogue_views, "related_assets_for_cves",
                 "proyeccion_hardware_cve"),
                (cve_catalogue_views, "catalogue_statuses",
                 "estados_historial"),
                (cve_catalogue_views, "_catalogue_summaries",
                 "recalculo_indicadores"),
                (cve_catalogue_views, "_cve_ids_for_evaluated_asset_name",
                 "busqueda_por_activo"),
                (cve_catalogue_views, "_catalogue_applicability",
                 "aplicabilidad_agregada"),
                (cve_technical_status, "_context", "consultar_inventario"),
                (cve_technical_status, "evaluate_configurations",
                 "evaluacion_nvd"),
                (cve_technical_status, "_scoped_status_with_current_audits",
                 "estado_por_hardware"),
                (cve_technical_status, "_current_linked_installation",
                 "software_evaluado"),
                (cve_catalogue_status, "_is_current",
                 "verificar_historial_vigente"),
            )
            request = APIRequestFactory().get(
                "/api/vulnerabilities/cves/", data=filters,
            )
            force_authenticate(request, user=user)
            with ExitStack() as stack:
                with CaptureQueriesContext(connection) as queries:
                    for module, name, label in tracked:
                        fn = getattr(module, name)
                        stack.enter_context(patch.object(
                            module, name, timer.wrap(label, fn),
                        ))
                    started = perf_counter()
                    response = cve_catalogue_views.CveCatalogueView.as_view()(request)
                    response.render()  # Include JSON serialization in timing.
                    duration_ms = (perf_counter() - started) * 1000
                    # Snapshot before CaptureQueriesContext exits.
                    statements = list(queries)
            if response.status_code != 200:
                raise CommandError(
                    f"La vista devolvió HTTP {response.status_code}: "
                    f"{str(response.data)[:300]}"
                )
            durations.append(duration_ms)
            self.stdout.write(
                f"\nEjecución {number}: {duration_ms:.1f} ms | "
                f"{len(statements)} consultas SQL | "
                f"{len(response.rendered_content)} bytes JSON | "
                f"{response.data['count']} evaluaciones filtradas | "
                f"{response.data['summary']['total']} CVE oficiales"
            )
            self.stdout.write(
                "Fases (tiempo acumulado; SQL incluido; las fases anidadas "
                "no deben sumarse):"
            )
            groups = timer.grouped()
            for label, stat in sorted(
                groups.items(), key=lambda item: -item[1]["milliseconds"]
            ):
                self.stdout.write(
                    f"  {label:30s} "
                    f"{stat['milliseconds']:9.1f} ms | "
                    f"{stat['calls']:4d} llamadas | "
                    f"{stat['queries']:5d} SQL"
                )
            nested = (
                groups.get("proyeccion_hardware_cve", {}).get("milliseconds", 0)
                + groups.get("estados_historial", {}).get("milliseconds", 0)
                + groups.get("recalculo_indicadores", {}).get("exclusive_ms", 0)
            )
            passes = groups.get("proyeccion_hardware_cve", {}).get("calls", 0)
            self.stdout.write(
                f"Nota: se observaron {passes} "
                f"{'pasada' if passes == 1 else 'pasadas'} "
                "de proyección hardware-CVE."
            )
            self.stdout.write(
                f"Tiempo fuera de fases principales (aprox.): "
                f"{max(0, duration_ms - nested):.1f} ms"
            )
            if options["slow_sql"]:
                self.stdout.write("SQL más lento (texto truncado):")
                for sql in sorted(
                    statements,
                    key=lambda statement: float(statement.get("time", 0)),
                    reverse=True,
                )[:options["slow_sql"]]:
                    normalized = " ".join(sql.get("sql", "").split())
                    self.stdout.write(
                        f"  {float(sql.get('time', 0))*1000:.1f} ms "
                        f"{normalized[:180]}"
                    )
        self.stdout.write(
            f"\nMediana de {len(durations)} ejecución(es): "
            f"{median(durations):.1f} ms. Sin escrituras de aplicación."
        )
