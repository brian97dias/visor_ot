"""Queue a reusable NVD CPE catalogue traversal for the singleton worker.

Example:
python manage.py enqueue_cpe_catalogue --strategy cpeMatchString \
    --parameter 'cpe:2.3:h:phoenix_contact'
"""
from django.core.management.base import BaseCommand, CommandError
from vulnerabilities.services.cpe_catalogue import (
    enqueue_catalogue_query, retry_failed_snapshot,
)


class Command(BaseCommand):
    help = "Encola la recuperación compartida de NVD sin tocar decisiones de activos."

    def add_arguments(self, parser):
        parser.add_argument("--strategy", choices=["keywordSearch", "cpeMatchString"])
        parser.add_argument("--parameter")
        parser.add_argument("--page-size", type=int, default=500)
        parser.add_argument("--force", action="store_true", help="Crear otra versión aunque el caché sea reciente.")
        parser.add_argument("--resume", type=int, help="Reanudar manualmente un fallo transitorio por ID de snapshot.")

    def handle(self, *args, **options):
        try:
            if options["resume"] is not None:
                if options["strategy"] or options["parameter"] or options["force"]:
                    raise ValueError("--resume no se combina con --strategy, --parameter o --force.")
                snapshot = retry_failed_snapshot(options["resume"])
                reused = True
            else:
                if not options["strategy"] or not options["parameter"]:
                    raise ValueError("Indica --strategy y --parameter; o bien --resume <ID>.")
                snapshot, reused = enqueue_catalogue_query(
                    options["strategy"], options["parameter"],
                    force=options["force"], page_size=options["page_size"],
                )
        except (ValueError, TypeError) as error:
            raise CommandError(str(error)) from error
        self.stdout.write(
            f"Snapshot #{snapshot.pk} · {snapshot.status} · "
            f"{'Reutilizado/reanudado' if reused else 'Nuevo'} · "
            f"startIndex={snapshot.next_start_index}. "
            "El worker run_cpe_worker ejecutará las solicitudes NVD."
        )
