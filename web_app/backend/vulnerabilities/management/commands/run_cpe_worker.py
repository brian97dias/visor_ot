"""Single-process, PostgreSQL-locked NVD worker for CPE and CVE."""
import time

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone

from vulnerabilities.models import CpeSearchRun, CpeQuerySnapshot, Cve
from vulnerabilities.services.cpe_search import execute_run
from vulnerabilities.services.external_cpe import EXTERNAL_CPE_TRIGGER, execute_external_cpe
from vulnerabilities.services.cpe_catalogue import (
    execute_catalogue_snapshot, recover_interrupted_catalogue_snapshots,
)
from vulnerabilities.services.nvd_client import PublicNvdPacer
from vulnerabilities.services.worker_lock import ADVISORY_LOCK_ID
from vulnerabilities.services.cve_ingestion import execute_cve_fetch


def dispatch_cpe_run(run, pacer):
    """Use one global worker for automatic searches and verified UUID requests."""
    if run.trigger == EXTERNAL_CPE_TRIGGER:
        return execute_external_cpe(run, pacer)
    return execute_run(run, pacer)


def asset_run_precedes_snapshot(run, snapshot):
    """Fair scheduling except for a run blocked on catalogue completion."""
    if run is None:
        return False
    if snapshot is None:
        return True
    waiting = bool(
        run.queries and run.queries[-1].get("status") == "WAITING_CATALOGUE"
    )
    return not waiting and run.created_at <= snapshot.created_at


def oldest_work_kind(run, snapshot, cve):
    """Respect existing run/snapshot ordering and share their NVD pace with CVE."""
    if asset_run_precedes_snapshot(run, snapshot):
        previous = ("ASSET", run.created_at)
    elif snapshot is not None:
        previous = ("SNAPSHOT", snapshot.created_at)
    else:
        previous = None
    if cve is not None and (previous is None or cve.queued_at <= previous[1]):
        return "CVE"
    return previous[0] if previous else None


class Command(BaseCommand):
    help = "Procesa búsquedas CPE, catálogos y recuperación CVE con un lock NVD global."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Procesa como máximo un trabajo y termina.")
        parser.add_argument("--poll-seconds", type=float, default=2)

    def handle(self, *args, **options):
        if connection.vendor != "postgresql":
            raise CommandError("El trabajador NVD requiere PostgreSQL para su lock global.")
        if options["poll_seconds"] < 0.5:
            raise CommandError("--poll-seconds debe ser al menos 0.5")
        connection.ensure_connection()
        session = connection.connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s)", [ADVISORY_LOCK_ID])
            locked = cursor.fetchone()[0]
        if not locked:
            raise CommandError("Ya existe otro trabajador NVD en ejecución.")
        self.stdout.write("Worker CPE activo. Espera inicial de seguridad: 30 s antes de consultar NVD.")
        def require_lock():
            if connection.connection is not session or connection.connection.closed:
                raise CommandError("Se perdió el lock de PostgreSQL: consulta NVD cancelada.")

        pacer = PublicNvdPacer(guard=require_lock)
        try:
            recover_interrupted_catalogue_snapshots()
            # After crashes never present abandoned RUNNING results as live.
            CpeSearchRun.objects.filter(status=CpeSearchRun.Status.RUNNING).update(
                status=CpeSearchRun.Status.FAILED,
                error_message="El trabajador se interrumpió. Solicita una nueva búsqueda.",
                finished_at=timezone.now(),
            )
            Cve.objects.filter(fetch_status=Cve.FetchStatus.RUNNING).update(
                fetch_status=Cve.FetchStatus.FAILED,
                fetch_error="Worker NVD interrumpido; vuelve a encolar el CVE.",
                finished_at=timezone.now(),
            )
            while True:
                # A lost/reopened PostgreSQL session also loses its advisory lock.
                # Stop rather than risk issuing requests without exclusivity.
                if connection.connection is not session or connection.connection.closed:
                    raise CommandError("Se perdió la sesión de bloqueo NVD; reinicia el trabajador.")
                run = CpeSearchRun.objects.filter(
                    status=CpeSearchRun.Status.QUEUED
                ).order_by("created_at", "pk").first()
                snapshot = CpeQuerySnapshot.objects.filter(
                    status__in=(
                        CpeQuerySnapshot.Status.QUEUED,
                        CpeQuerySnapshot.Status.INCOMPLETE,
                    )
                ).select_related("cache").order_by("created_at", "pk").first()
                cve = Cve.objects.filter(
                    fetch_status=Cve.FetchStatus.QUEUED
                ).order_by("queued_at", "pk").first()
                # One PostgreSQL lock and one pacer for CPE and CVE HTTP calls.
                kind = oldest_work_kind(run, snapshot, cve)
                if kind == "ASSET":
                    self.stdout.write(f"Buscando CPE: trabajo #{run.pk}, activo #{run.asset_id}")
                    dispatch_cpe_run(run, pacer)
                    self.stdout.write(f"Trabajo #{run.pk}: {run.status}, {len(run.candidates)} candidatos")
                elif kind == "SNAPSHOT":
                    self.stdout.write(
                        f"Recuperando catálogo: snapshot #{snapshot.pk}, "
                        f"{snapshot.cache.strategy}={snapshot.cache.parameter} "
                        f"desde startIndex={snapshot.next_start_index}"
                    )
                    result = execute_catalogue_snapshot(snapshot, pacer)
                    self.stdout.write(
                        f"Snapshot #{snapshot.pk}: {result.status}, "
                        f"{result.unique_products_count} productos, "
                        f"checkpoint={result.next_start_index}"
                    )
                elif kind == "CVE":
                    self.stdout.write(f"Recuperando CVE: {cve.cve_id}")
                    result = execute_cve_fetch(cve, pacer)
                    self.stdout.write(
                        f"CVE {result.cve_id}: {result.fetch_status}"
                        + (f" — {result.fetch_error}" if result.fetch_error else "")
                    )
                if options["once"]:
                    break
                if kind is None:
                    time.sleep(options["poll_seconds"])
        except KeyboardInterrupt:
            self.stdout.write("Trabajador detenido. Trabajos pendientes conservados.")
        finally:
            if connection.connection is session and not connection.connection.closed:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_unlock(%s)", [ADVISORY_LOCK_ID])
