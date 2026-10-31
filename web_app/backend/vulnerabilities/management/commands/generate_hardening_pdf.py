"""Render a PDF using the current inventory or a saved schema-v1 JSON cut."""
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from django.core.management.base import BaseCommand, CommandError
from rest_framework.exceptions import ValidationError

from vulnerabilities.services.hardening_report_data import collect_hardening_report_data
from vulnerabilities.services.hardening_pdf import render_hardening_pdf


DEFAULT_OUTPUT_FILE = (
    Path(__file__).resolve().parents[2] / "output" / "visor_ot_hardening_report.pdf"
)


class Command(BaseCommand):
    help = "Genera el PDF de diagnóstico OT desde el inventario actual o JSON previo."

    def add_arguments(self, parser):
        parser.add_argument(
            "--output", default=None,
            help="Ruta PDF (por defecto vulnerabilities/output/).",
        )
        parser.add_argument(
            "--input-json", dest="input_json", default=None,
            help="Usa un corte JSON existente sin acceder a la base de datos.",
        )
        parser.add_argument(
            "--legacy", action="store_true",
            help="Conserva el PDF anterior de inventario para comparación.",
        )

    def handle(self, *args, **options):
        if options["input_json"]:
            try:
                with open(options["input_json"], encoding="utf-8") as source:
                    data = json.load(source)
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise CommandError(f"No se pudo leer el JSON: {error}") from error
        else:
            try:
                data = collect_hardening_report_data()
            except ValidationError as error:
                raise CommandError(
                    "Inventario incompleto: ejecuta "
                    "python manage.py audit_inventory_integrity."
                ) from error

        target = Path(options["output"]) if options["output"] else DEFAULT_OUTPUT_FILE
        temporary = None
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            # Atomic output: never replace a valid PDF if rendering fails.
            with NamedTemporaryFile(
                mode="w+b", prefix=".hardening-", suffix=".pdf.tmp",
                dir=target.parent, delete=False,
            ) as stream:
                temporary = Path(stream.name)
                render_hardening_pdf(data, stream, legacy=options["legacy"])
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except (OSError, ValueError) as error:
            raise CommandError(f"No se pudo generar el PDF: {error}") from error
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        self.stdout.write(self.style.SUCCESS(f"PDF guardado en {target}"))
