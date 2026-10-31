"""Read-only inspection of legacy inventory before generating reports."""
import json

from django.core.management.base import BaseCommand, CommandError

from assets.inventory_integrity import inventory_integrity_issues


class Command(BaseCommand):
    help = "Lista datos obligatorios faltantes sin alterar el inventario existente."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true",
                            help="Muestra los errores en JSON.")
        parser.add_argument("--strict", action="store_true",
                            help="Devuelve un error si hay datos incompletos.")

    def handle(self, *args, **options):
        problems = inventory_integrity_issues()
        if options["json"]:
            self.stdout.write(json.dumps(
                {"valid": not problems, "issues": problems},
                ensure_ascii=False, indent=2,
            ))
        else:
            if problems:
                self.stdout.write(f"Hay {len(problems)} problema(s) por corregir:")
                for item in problems:
                    self.stdout.write(
                        f"  {item['entity']} #{item['id']} "
                        f"({item['field']}): {item['message']}"
                    )
            else:
                self.stdout.write(self.style.SUCCESS(
                    "Inventario activo completo para el informe."
                ))
        if options["strict"] and problems:
            raise CommandError("El inventario requiere regularización.")
