"""Import large PCAP observations synchronously from terminal, not browser."""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from ingestion.services.json_importer import ImportValidationError, import_analysis
from ingestion.services.analyzer_client import (
    PassiveAnalyzerAnalysisNotFound,
    PassiveAnalyzerUnavailable,
)


class Command(BaseCommand):
    help = "Importa un análisis PCAP a Visor OT por streaming y lotes."

    def add_arguments(self, parser):
        parser.add_argument("pcap_id", help="PCAP ID del Passive Analyzer")
        parser.add_argument("--username", required=True,
                            help="Usuario activo ADMIN o ANALYST que realiza la importación")

    def handle(self, *args, **options):
        user = get_user_model().objects.filter(
            username=options["username"], is_active=True
        ).first()
        if user is None or user.role not in ("ADMIN", "ANALYST"):
            raise CommandError("Se requiere un usuario activo ADMIN o ANALYST.")
        self.stdout.write("Importando observaciones en lotes. No abras el JSON en el editor.")
        try:
            ingestion, status = import_analysis(options["pcap_id"], user)
        except (
            ImportValidationError,
            PassiveAnalyzerAnalysisNotFound,
            PassiveAnalyzerUnavailable,
        ) as error:
            raise CommandError(str(error)) from error
        self.stdout.write(self.style.SUCCESS(
            f"{status}: ingesta #{ingestion.pk}, "
            f"{ingestion.interfaces_detected} interfaces y "
            f"{ingestion.communications_detected} comunicaciones."
        ))
