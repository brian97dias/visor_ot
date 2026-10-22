"""Explicit phase-1 CVE retrieval request; the locked NVD worker does the I/O."""
from django.core.management.base import BaseCommand

from vulnerabilities.services.cve_ingestion import (
    enqueue_experimental_cve, find_experimental_configuration,
)


class Command(BaseCommand):
    help = "Encola únicamente CVE-2021-33540, sin consultar NVD desde este comando."

    def add_arguments(self, parser):
        parser.add_argument(
            "--refresh", action="store_true",
            help="Solicitar nueva recuperación de un CVE anteriormente completado.",
        )

    def handle(self, *args, **options):
        cve, reused = enqueue_experimental_cve(refresh=options["refresh"])
        if cve.fetch_status == cve.FetchStatus.COMPLETED:
            scenario = find_experimental_configuration(cve.configurations)
            self.stdout.write(
                f"{cve.cve_id}: ya recuperado; configuración experimental "
                f"en posición NVD {scenario['position']}."
            )
        else:
            self.stdout.write(
                f"{cve.cve_id}: estado {cve.fetch_status}; "
                f"{'solicitud anterior reutilizada' if reused else 'nuevo trabajo en cola'}. "
                "El worker NVD procesará la solicitud."
            )
