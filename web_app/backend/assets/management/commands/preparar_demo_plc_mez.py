"""Construir el estado inicial del demo, solo en una copia PostgreSQL *_demo.

Vista previa por defecto. La ejecucion requiere confirmacion explicita.
NO borra el catalogo compartido CPE/CVE, software, sistemas ni el PCAP.
"""
import json
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q

from assets.models import (
    Asset, Hardware, NetworkInterface, SoftwareInstallation, SystemMembership,
)
from ingestion.models import Ingestion, InterfaceObservation, CommunicationObservation
from network.models import Communication
from vulnerabilities.models import (
    AssetCpe, AssetCpeDecision, AssetCveAssessment, AssetCveFinding,
    Cpe, CpeSearchRun, CveDiscoveryRun,
)


PLC_NAME = "PLC-MEZ-01"
DAY_ONE = "visor_ot_demo_dia1_operacion.pcap"
DAY_TWO = "visor_ot_demo_dia2_operacion_y_nuevos_flujos.pcap"
CONFIRMATION = "PREPARAR_DEMO_PLC_MEZ_01"


def inspect():
    db = str(settings.DATABASES["default"].get("NAME") or "")
    if settings.DATABASES["default"].get("ENGINE") != "django.db.backends.postgresql":
        raise CommandError("Este comando requiere PostgreSQL.")
    if not db.endswith("_demo"):
        raise CommandError(
            "PROTECCION: DB_NAME debe terminar en _demo. "
            "No se modifica la base original."
        )
    try:
        plc = Asset.objects.get(name=PLC_NAME, asset_type=Asset.AssetType.HARDWARE)
        hw = Hardware.objects.get(asset=plc)
    except (Asset.DoesNotExist, Asset.MultipleObjectsReturned, Hardware.DoesNotExist):
        raise CommandError("Debe existir un unico hardware PLC-MEZ-01.")
    first = list(Ingestion.objects.filter(filename=DAY_ONE))
    second = list(Ingestion.objects.filter(filename=DAY_TWO))
    if len(first) != 1 or len(second) != 1:
        raise CommandError(
            "Se requieren exactamente dos ingestas: una del dia 1 y una del dia 2."
        )
    day1, day2 = first[0], second[0]
    if (Ingestion.objects.count() != 2
            or day1.status != Ingestion.Status.ACTIVE
            or day2.status != Ingestion.Status.ACTIVE):
        raise CommandError("Se encontraron ingestas adicionales o excluidas. Revisar antes.")
    n1 = CommunicationObservation.objects.filter(ingestion=day1).count()
    n2 = CommunicationObservation.objects.filter(ingestion=day2).count()
    i1 = InterfaceObservation.objects.filter(ingestion=day1).count()
    i2 = InterfaceObservation.objects.filter(ingestion=day2).count()
    if (n1, n2, i1, i2) != (12, 16, 12, 12):
        raise CommandError(
            "Las observaciones no corresponden al escenario esperado "
            f"(comunicaciones {n1}/{n2}; interfaces {i1}/{i2})."
        )
    if Hardware.objects.count() != 12:
        raise CommandError("El laboratorio no tiene 12 hardware; no se prepara automaticamente.")
    day2_ids = set(CommunicationObservation.objects.filter(
        ingestion=day2).values_list("communication_id", flat=True))
    day1_ids = set(CommunicationObservation.objects.filter(
        ingestion=day1).values_list("communication_id", flat=True))
    if None in day2_ids or None in day1_ids:
        raise CommandError("Hay observaciones sin consolidar; detener la preparacion.")
    exclusive = sorted(day2_ids - day1_ids)
    if len(exclusive) != 4:
        raise CommandError(
            "Se esperaban cuatro comunicaciones exclusivas del dia 2; "
            f"se obtuvieron {len(exclusive)}."
        )
    if Communication.objects.count() != 16:
        raise CommandError("Se esperaban 16 comunicaciones consolidadas en la base.")
    runs = list(CpeSearchRun.objects.filter(asset=plc).values_list("pk", flat=True))
    cpe_references = Cpe.objects.filter(references_source_run_id__in=runs).count()
    # CVE discoveries can span several hardware. Only single-PLC jobs can
    # be removed; multi-asset jobs are shared and must be kept.
    solo_discoveries = []
    shared_discoveries = []
    for record in CveDiscoveryRun.objects.all().only("pk", "selected_hardware_ids"):
        identifiers = record.selected_hardware_ids or []
        if str(hw.pk) not in [str(value) for value in identifiers]:
            continue
        if len(identifiers) == 1:
            solo_discoveries.append(record.pk)
        else:
            shared_discoveries.append(record.pk)
    return {
        "database": db,
        "plc_asset_id": plc.pk,
        "day2_ingestion_id": day2.pk,
        "day2_pcap_id": day2.pcap_id,
        "day2_relative_path": day2.relative_path,
        "communications_day1": n1,
        "communications_day2": n2,
        "exclusive_communication_ids": exclusive,
        "network_interfaces_to_unlink": NetworkInterface.objects.filter(hardware=hw).count(),
        "software_installation_history_to_remove": SoftwareInstallation.objects.filter(hardware=hw).count(),
        "system_membership_history_to_remove": SystemMembership.objects.filter(hardware=hw).count(),
        "cpe_associations_to_remove": AssetCpe.objects.filter(asset=plc).count(),
        "cpe_search_runs_to_remove": len(runs),
        "cpe_catalogue_references_to_detach": cpe_references,
        "cve_findings_to_remove": AssetCveFinding.objects.filter(hardware=hw).count(),
        "cve_assessments_to_remove": AssetCveAssessment.objects.filter(hardware=hw).count(),
        "solo_cve_discovery_runs_to_remove": solo_discoveries,
        "shared_cve_discovery_runs_retained": shared_discoveries,
    }


def apply_preview(preview):
    with transaction.atomic():
        # Reinspect after locks. Foreign key failures roll the entire change back.
        asset = Asset.objects.select_for_update().get(pk=preview["plc_asset_id"])
        if asset.name != PLC_NAME:
            raise CommandError("El PLC cambio de identidad; operacion cancelada.")
        hw = Hardware.objects.select_for_update().get(asset=asset)
        day2 = Ingestion.objects.select_for_update().get(pk=preview["day2_ingestion_id"])
        if day2.pcap_id != preview["day2_pcap_id"]:
            raise CommandError("La identidad del PCAP cambio; operacion cancelada.")
        current = inspect()
        if current != preview:
            raise CommandError("La base cambio desde la vista previa; no se modifico nada.")

        # First free PROTECT relations to PLC, preserving shared catalog entries.
        AssetCveAssessment.objects.filter(hardware=hw).delete()
        AssetCveFinding.objects.filter(hardware=hw).delete()
        for run_id in preview["solo_cve_discovery_runs_to_remove"]:
            still_used = AssetCveFinding.objects.filter(
                Q(first_discovery_run_id=run_id) | Q(last_discovery_run_id=run_id)
            ).exists()
            if still_used:
                raise CommandError(
                    "Una busqueda CVE del PLC pertenece tambien a otro equipo. "
                    "No se borrara."
                )
            CveDiscoveryRun.objects.filter(pk=run_id).delete()

        cpe_links = AssetCpe.objects.filter(asset=asset)
        AssetCpeDecision.objects.filter(association__in=cpe_links).delete()
        cpe_links.delete()
        runs = CpeSearchRun.objects.filter(asset=asset)
        # Official CPEs can be shared. Keep the catalogue but detach nullable
        # references to a soon-to-be-removed PLC-specific search history.
        Cpe.objects.filter(references_source_run__in=runs).update(
            references_source_run=None)
        runs.delete()

        SoftwareInstallation.objects.filter(hardware=hw).delete()
        SystemMembership.objects.filter(hardware=hw).delete()
        NetworkInterface.objects.filter(hardware=hw).update(
            hardware=None, identified_by=None, identified_at=None)
        asset.delete()

        # Drop only the second capture's imported evidence, then remove
        # consolidated communication rows that existed ONLY in that capture.
        day2.delete()
        exclusive = preview["exclusive_communication_ids"]
        if CommunicationObservation.objects.filter(
                communication_id__in=exclusive).exists():
            raise CommandError("Persisten evidencias compartidas inesperadas.")
        Communication.objects.filter(pk__in=exclusive).delete()

        # All these checks are within the same transaction.
        if Asset.objects.filter(name=PLC_NAME, asset_type=Asset.AssetType.HARDWARE).exists():
            raise CommandError("El PLC no fue retirado.")
        if Ingestion.objects.filter(pk=preview["day2_ingestion_id"]).exists():
            raise CommandError("La ingesta del dia 2 no fue retirada.")
        if (Hardware.objects.count() != 11
                or Ingestion.objects.count() != 1
                or Communication.objects.count() != 12):
            raise CommandError("Conteos finales inesperados; transaccion revertida.")
        remaining = Ingestion.objects.get()
        if remaining.filename != DAY_ONE or remaining.status != Ingestion.Status.ACTIVE:
            raise CommandError("Se altero la ingesta del dia 1; transaccion revertida.")


class Command(BaseCommand):
    help = "Vista previa o preparacion selectiva del PLC-MEZ-01 en PostgreSQL *_demo."

    def add_arguments(self, parser):
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--confirm", default="")
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **opts):
        preview = inspect()
        if opts["json"]:
            self.stdout.write(json.dumps(preview, ensure_ascii=False, indent=2))
        else:
            for key, value in preview.items():
                self.stdout.write(f"{key}: {value}")
        if not opts["execute"]:
            self.stdout.write(self.style.WARNING(
                "SOLO VISTA PREVIA: no se ha borrado ningun registro."
            ))
            return
        if opts["confirm"] != CONFIRMATION:
            raise CommandError("Se requiere --confirm " + CONFIRMATION)
        apply_preview(preview)
        self.stdout.write(self.style.SUCCESS(
            "DEMO PREPARADA EN POSTGRESQL: 11 hardware, 1 ingesta y "
            "12 comunicaciones. El output FastAPI se prepara por separado."
        ))
