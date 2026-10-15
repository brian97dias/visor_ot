"""Read-only timings for a real communication search on PostgreSQL.

Run:
  python manage.py benchmark_communication_search --search "dire"
  python manage.py benchmark_communication_search --search "dire" --explain

The optional EXPLAIN ANALYZE executes another SELECT; use it intentionally.
"""

from time import perf_counter

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.db import connection

from network.endpoint_resolution import resolve_communication_endpoints
from network.name_search import device_name_filter
from network.views import get_communications_queryset


def build_search_criteria(search):
    criteria = (
        Q(source_ip__icontains=search)
        | Q(destination_ip__icontains=search)
        | Q(transport_protocol__icontains=search)
        | Q(service__icontains=search)
    )
    if search.isdecimal():
        criteria |= Q(service_port=int(search))

    name_filter = device_name_filter(search)
    if name_filter is not None:
        criteria |= name_filter

    return criteria


class Command(BaseCommand):
    help = "Mide una búsqueda real de Comunicaciones sin modificar PostgreSQL."

    def add_arguments(self, parser):
        parser.add_argument("--search", default="dire")
        parser.add_argument("--min-packets", type=int, default=1)
        parser.add_argument("--page-size", type=int, default=25)
        parser.add_argument(
            "--explain", action="store_true",
            help="Ejecutar EXPLAIN ANALYZE BUFFERS de la consulta de la página.",
        )

    def handle(self, *args, **options):
        search = options["search"].strip()[:100]
        min_packets = options["min_packets"]
        page_size = options["page_size"]

        if not search:
            self.stderr.write("Indica una búsqueda no vacía.")
            return
        if min_packets < 0 or page_size < 1 or page_size > 100:
            self.stderr.write("Parámetros inválidos.")
            return

        t0 = perf_counter()
        criteria = build_search_criteria(search)
        t1 = perf_counter()

        queryset = get_communications_queryset().filter(
            active_evidence_count__gt=0
        ).filter(criteria)
        if min_packets:
            queryset = queryset.filter(packets_observed__gte=min_packets)

        count = queryset.count()
        t2 = perf_counter()

        page_query = queryset.order_by("id")[:page_size]
        rows = list(page_query)
        t3 = perf_counter()

        resolution = resolve_communication_endpoints(rows)
        t4 = perf_counter()

        self.stdout.write(f"Consulta: {search!r}")
        self.stdout.write(f"Coincidencias: {count}; filas recibidas: {len(rows)}")
        self.stdout.write(f"Preparación de criterios: {(t1-t0)*1000:.1f} ms")
        self.stdout.write(f"Conteo PostgreSQL: {(t2-t1)*1000:.1f} ms")
        self.stdout.write(f"Página PostgreSQL: {(t3-t2)*1000:.1f} ms")
        self.stdout.write(f"Enriquecimiento: {(t4-t3)*1000:.1f} ms")
        self.stdout.write(f"Total: {(t4-t0)*1000:.1f} ms")

        if options["explain"]:
            self.stdout.write(self.style.WARNING(
                "EXPLAIN ANALYZE ejecutará nuevamente la consulta de la página."
            ))
            if connection.vendor != "postgresql":
                self.stdout.write(self.style.WARNING(
                    "El detalle BUFFERS está pensado para PostgreSQL."
                ))
            self.stdout.write(page_query.explain(
                analyze=True,
                buffers=connection.vendor == "postgresql",
            ))
