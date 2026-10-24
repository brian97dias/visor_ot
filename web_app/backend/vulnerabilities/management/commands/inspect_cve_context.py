"""Inspect persisted CVE evidence for one hardware without network or writes.

Examples:
    python manage.py inspect_cve_context --hardware 10
    python manage.py inspect_cve_context --hardware 10 --cve CVE-2021-44695 --json

This audit is a technical comparison of stored NVD alternatives, NOT an
automatic human applicability decision or a new NVD discovery.
"""
import json

from django.core.management.base import BaseCommand, CommandError
from django.http import Http404
from rest_framework.exceptions import NotFound, ValidationError

from assets.models import Hardware
from vulnerabilities.models import AssetCveAssessment, AssetCveFinding, Cve
from vulnerabilities.services.cve_general_assessment import general_assessment_context


def inspect_hardware_cves(hardware_id, cve_id=None):
    """Build a deterministic, read-only report from existing discoveries."""
    related = set(AssetCveFinding.objects.filter(
        hardware_id=hardware_id
    ).values_list("cve_id", flat=True))
    related.update(AssetCveAssessment.objects.filter(
        hardware_id=hardware_id
    ).values_list("cve_id", flat=True))
    cves = Cve.objects.filter(
        pk__in=related, fetch_status=Cve.FetchStatus.COMPLETED
    ).order_by("cve_id")
    if cve_id:
        cves = cves.filter(cve_id=cve_id)
    rows = []
    for cve in cves:
        info = general_assessment_context(cve.cve_id, hardware_id)
        technical = info["technical_summary"]
        human = info["assessment_summary"]
        rows.append({
            "cve_id": cve.cve_id,
            "technical_result": technical["result"],
            "total_configurations": technical["total"],
            "compatible": technical["compatible_count"],
            "excluded": technical["excluded_count"],
            "indeterminate": technical["indeterminate_count"],
            "compatible_positions": technical["compatible_positions"],
            "analyst_status": human["status"],
            "analyst_confirmed": human["confirmed_configurations"],
            "analyst_stale": human["stale_configurations"],
        })
    return {"hardware_id": hardware_id, "analyzed": len(rows), "results": rows}


class Command(BaseCommand):
    help = "Audita CVE ya recuperados para un hardware sin modificar la base de datos."

    def add_arguments(self, parser):
        parser.add_argument("--hardware", type=int, required=True)
        parser.add_argument("--cve", type=str)
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **options):
        hardware_id = options["hardware"]
        if hardware_id < 1 or not Hardware.objects.filter(pk=hardware_id).exists():
            raise CommandError("El hardware solicitado no existe.")
        try:
            report = inspect_hardware_cves(hardware_id, options["cve"])
        except (Http404, NotFound, ValidationError, ValueError, AttributeError) as error:
            raise CommandError("No se pudo interpretar el inventario o las condiciones NVD.") from error
        if options["json"]:
            self.stdout.write(json.dumps(report, ensure_ascii=False, indent=2))
            return
        self.stdout.write(
            f"Hardware #{hardware_id} | CVE recuperados relacionados: {report['analyzed']}"
        )
        if not report["analyzed"]:
            self.stdout.write("No hay CVE relacionados recuperados para este filtro.")
        for row in report["results"]:
            self.stdout.write(
                f"{row['cve_id']} | técnico={row['technical_result']} | "
                f"alternativas={row['total_configurations']} "
                f"(coinciden={row['compatible']}, excluidas={row['excluded']}, "
                f"por_verificar={row['indeterminate']}) | "
                f"configuraciones_compatibles={row['compatible_positions']} | "
                f"analista={row['analyst_status']}"
            )
