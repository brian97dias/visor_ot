"""Inspect stored NVD products versus candidate suggestions for one hardware.

Purely read-only. It never sends NVD requests, starts worker jobs, or changes
catalogue records and analyst decisions.
"""
from django.core.management.base import BaseCommand, CommandError
from assets.models import Asset
from vulnerabilities.models import CpeQuerySnapshot
from vulnerabilities.services.cpe_catalogue_matching import (
    ALLOWED_VIEWS, browse_catalogue, summarize_catalogue,
)
from vulnerabilities.services.identity import hardware_identity


class Command(BaseCommand):
    help = "Clasifica el catálogo NVD recuperado para un activo sin modificarlo."

    def add_arguments(self, parser):
        parser.add_argument("--snapshot", type=int, required=True)
        parser.add_argument("--asset", type=int, required=True)
        parser.add_argument("--view", choices=ALLOWED_VIEWS, default="ALL")
        parser.add_argument("--limit", type=int, default=25)
        parser.add_argument("--after", type=int, default=0)
        parser.add_argument("--no-summary", action="store_true")

    def handle(self, *args, **options):
        try:
            asset = Asset.objects.select_related("hardware").get(pk=options["asset"])
            snapshot = CpeQuerySnapshot.objects.select_related("cache").get(
                pk=options["snapshot"]
            )
            identity = hardware_identity(asset)
            page = browse_catalogue(
                snapshot, identity, view=options["view"],
                limit=options["limit"], after_id=options["after"],
            )
            summary = None if options["no_summary"] else summarize_catalogue(snapshot, identity)
        except (Asset.DoesNotExist, CpeQuerySnapshot.DoesNotExist) as error:
            raise CommandError("El activo o la recuperación NVD no existen.") from error
        except (ValueError, AttributeError) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(
            f"Catálogo snapshot #{snapshot.pk} | {snapshot.cache.strategy}: "
            f"{snapshot.cache.parameter} | estado={snapshot.status} | "
            f"cobertura_completa={page['coverage_complete']}"
        )
        if not page["coverage_complete"]:
            self.stdout.write(self.style.WARNING(
                "Catálogo parcial/no finalizado: cero candidatos NO significa ausencia de CPE."
            ))
        if summary is not None:
            self.stdout.write(
                f"Registros guardados={summary['examined']} | "
                f"candidatos sugeridos={summary['candidate_count']} | "
                f"excluidos de sugerencias={summary['excluded_count']} | "
                f"coincidencias técnicas suficientes={summary['pertinent_count']}"
            )
            self.stdout.write(f"Exclusiones: {summary['classification_counts']}")
        self.stdout.write(f"Vista={page['view']} | elementos={len(page['items'])}")
        for item in page["items"]:
            self.stdout.write(
                f"#{item['evidence_id']} [{item['classification']}] "
                f"{item['cpe_name_id']} | {item['title'][:85]} | "
                f"coincidencia={item['match_level'] or 'NO_APLICA'}"
            )
        if page["next_after"] is not None:
            self.stdout.write(
                f"Más registros: ejecuta de nuevo con --after {page['next_after']}"
            )
