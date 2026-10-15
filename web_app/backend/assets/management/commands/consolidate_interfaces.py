"""Backfill interface inventory identities from already imported PCAP evidence."""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from assets.interface_consolidation import consolidate_interface_observations
from ingestion.models import Ingestion, InterfaceObservation


class Command(BaseCommand):
    help = (
        "Consolida las MAC de InterfaceObservation existentes sin borrar "
        "evidencia ni asignar automáticamente hardware."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--ingestion-id",
            type=int,
            help="Procesar únicamente las observaciones de una ingesta.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=500,
            help="Tamaño de lote para actualizar vínculos (por defecto: 500).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Mostrar los cambios previstos sin guardarlos.",
        )

    def handle(self, *args, **options):
        ingestion_id = options["ingestion_id"]
        batch_size = options["batch_size"]
        dry_run = options["dry_run"]

        if batch_size < 1:
            raise CommandError("--batch-size debe ser mayor que cero.")
        if ingestion_id is not None and ingestion_id < 1:
            raise CommandError("--ingestion-id debe ser positivo.")

        queryset = InterfaceObservation.objects.all()

        if ingestion_id is not None:
            if not Ingestion.objects.filter(pk=ingestion_id).exists():
                raise CommandError(f"No existe la ingesta #{ingestion_id}.")
            queryset = queryset.filter(ingestion_id=ingestion_id)

        with transaction.atomic():
            stats = consolidate_interface_observations(
                queryset, batch_size=batch_size
            )
            if dry_run:
                transaction.set_rollback(True)

        self.stdout.write(
            self.style.WARNING("SIMULACIÓN: no se guardaron cambios")
            if dry_run else self.style.SUCCESS("Consolidación finalizada")
        )
        self.stdout.write(f"Observaciones recorridas: {stats.scanned}")
        self.stdout.write(f"Interfaces nuevas: {stats.created}")
        self.stdout.write(f"Interfaces existentes reutilizadas: {stats.reused}")
        self.stdout.write(f"Observaciones vinculadas: {stats.linked}")
        self.stdout.write(f"Vínculos ya existentes: {stats.already_linked}")
        self.stdout.write(f"MAC desconocidas o inválidas: {stats.skipped_invalid_mac}")
        self.stdout.write(f"Conflictos sin modificar: {stats.conflicting_links}")

        if stats.conflicting_links:
            self.stderr.write(self.style.WARNING(
                "Se conservaron los vínculos conflictivos para revisión manual."
            ))
