"""Inspect Phase 2 report data in JSON without generating a PDF or writing DB."""
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from rest_framework.exceptions import ValidationError

from vulnerabilities.services.hardening_report_data import collect_hardening_report_data


class Command(BaseCommand):
    help = "Muestra el JSON del informe de hardening (sin PDF ni modificaciones)."

    def add_arguments(self, parser):
        parser.add_argument("--output", default=None, help="Ruta de archivo JSON opcional.")

    def handle(self, *args, **options):
        try:
            data = collect_hardening_report_data()
        except ValidationError as error:
            raise CommandError(
                "Inventario incompleto: ejecuta python manage.py "
                "audit_inventory_integrity para identificar qué corregir."
            ) from error
        output = json.dumps(data, ensure_ascii=False, indent=2)
        if options["output"]:
            target = Path(options["output"])
            try:
                target.write_text(output + "\n", encoding="utf-8")
            except OSError as error:
                raise CommandError(f"No se pudo escribir el JSON: {error}") from error
            self.stdout.write(self.style.SUCCESS(f"Datos guardados en {target}"))
        else:
            self.stdout.write(output)
