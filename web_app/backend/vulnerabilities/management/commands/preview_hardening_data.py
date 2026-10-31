"""Inspect Phase 2 report data in JSON without generating a PDF or writing DB."""
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from rest_framework.exceptions import ValidationError

from vulnerabilities.services.hardening_report_data import collect_hardening_report_data


# Anchor the generated file to the project, never to the working directory
# or to a machine-wide temporary folder.
DEFAULT_OUTPUT_FILE = (
    Path(__file__).resolve().parents[2] / "output" / "visor_ot_hardening_data.json"
)


class Command(BaseCommand):
    help = "Genera el JSON de hardening dentro del proyecto (sin PDF ni cambios en BD)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--output", default=None,
            help="Ruta de salida alternativa; por defecto vulnerabilities/output/.",
        )
        parser.add_argument(
            "--stdout", action="store_true",
            help="Muestra el JSON en la terminal en lugar de crear un archivo.",
        )

    def handle(self, *args, **options):
        if options["stdout"] and options["output"]:
            raise CommandError("Usa --stdout o --output, pero no ambos.")
        try:
            data = collect_hardening_report_data()
        except ValidationError as error:
            raise CommandError(
                "Inventario incompleto: ejecuta python manage.py "
                "audit_inventory_integrity para identificar qué corregir."
            ) from error

        output = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        if options["stdout"]:
            self.stdout.write(output.rstrip("\n"))
            return

        target = Path(options["output"]) if options["output"] else DEFAULT_OUTPUT_FILE
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(output, encoding="utf-8")
        except OSError as error:
            raise CommandError(f"No se pudo escribir el JSON: {error}") from error
        self.stdout.write(self.style.SUCCESS(f"Datos guardados en {target}"))
