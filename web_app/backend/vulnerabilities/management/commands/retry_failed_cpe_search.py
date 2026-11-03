"""Explicit retry of a failed CPE asset discovery after a transient NVD error."""
from django.core.management.base import BaseCommand, CommandError
from django.db import OperationalError
from rest_framework.exceptions import ValidationError

from vulnerabilities.models import CpeSearchRun
from vulnerabilities.services.cpe_search import retry_failed_cpe_search


class Command(BaseCommand):
    help = (
        "Reanuda un trabajo CPE manual fallido por FETCH_FAILED sin repetir "
        "las consultas completadas. No confirma ningún CPE."
    )

    def add_arguments(self, parser):
        parser.add_argument("run_id", type=int, help="ID del trabajo fallido")
        parser.add_argument(
            "--execute", action="store_true",
            help="Confirma la reactivación; sin este flag muestra vista previa.",
        )

    def handle(self, *args, **options):
        run_id = options["run_id"]
        run = CpeSearchRun.objects.filter(pk=run_id).first()
        if run is None:
            raise CommandError(f"No existe el trabajo CPE #{run_id}.")
        last = (run.queries or [])[-1:] or []
        snapshot_id = last[0].get("snapshot_id") if last else None
        self.stdout.write(
            f"Trabajo #{run.pk}, activo #{run.asset_id}, "
            f"estado {run.status}, consultas registradas {len(run.queries or [])}, "
            f"snapshot final #{snapshot_id or 'sin snapshot'}"
        )
        if not options["execute"]:
            self.stdout.write(
                "VISTA PREVIA: no se modificó la base de datos. "
                "Usa --execute para reanudar solo si la identidad y el "
                "error son recuperables."
            )
            return
        try:
            retry_failed_cpe_search(run_id)
        except (ValidationError, ValueError, OperationalError) as error:
            raise CommandError(f"No se pudo reactivar: {error}") from error
        self.stdout.write(self.style.SUCCESS(
            f"Trabajo #{run_id} reactivado en QUEUED. "
            "Su snapshot se recuperará desde el checkpoint persistido."
        ))
