from django.db import transaction

from ingestion.models import (
    CommunicationObservation,
    Ingestion,
    InterfaceObservation,
)

from .analyzer_client import (
    get_pcap_analysis,
    get_pcap_import_manifest,
    stream_pcap_analysis,
)
from network.services.consolidation import (
    consolidate_communication_observations,
)

from assets.interface_consolidation import consolidate_interface_observations

import hashlib
import json

SUPPORTED_SCHEMA_VERSION = "0.2"


class ImportValidationError(Exception):
    pass


def calculate_analysis_hash(analysis,):

    canonical_json = json.dumps(
        analysis,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()

def validate_analysis(
    analysis,
    expected_pcap_id,
):

    schema_version = analysis.get(
        "schema_version"
    )

    if schema_version != SUPPORTED_SCHEMA_VERSION:

        raise ImportValidationError(
            f"Schema no soportado: "
            f"{schema_version}."
        )


    capture = analysis.get(
        "capture"
    )

    if not isinstance(capture, dict):

        raise ImportValidationError(
            "El análisis no contiene "
            "información válida de captura."
        )


    if (
        capture.get("pcap_id")
        != expected_pcap_id
    ):

        raise ImportValidationError(
            "El PCAP ID del análisis "
            "no coincide con el solicitado."
        )


    interfaces = analysis.get(
        "interfaces"
    )

    communications = analysis.get(
        "communications"
    )


    if not isinstance(interfaces, list):

        raise ImportValidationError(
            "La lista de interfaces "
            "no es válida."
        )


    if not isinstance(
        communications,
        list,
    ):

        raise ImportValidationError(
            "La lista de comunicaciones "
            "no es válida."
        )


    return (
        capture,
        interfaces,
        communications,
    )


IMPORT_BATCH_SIZE = 100  # Small enough for SQLite test limits and PostgreSQL.


def _make_interface(ingestion, item):
    return InterfaceObservation(
        ingestion=ingestion,
        mac=item["mac"], ips=item.get("ips", []),
        first_seen=item["first_seen"], last_seen=item["last_seen"],
    )


def _make_communication(ingestion, item):
    return CommunicationObservation(
        ingestion=ingestion,
        client_ip=item["client_ip"],
        server_ip=item["server_ip"],
        client_macs=item.get("client_macs"),
        server_macs=item.get("server_macs"),
        transport_protocol=item["transport_protocol"],
        service_port=item["service_port"],
        service=item.get("service"),
        role_source=item.get("role_source"),
        packet_count=item["packet_count"],
        first_seen=item["first_seen"],
        last_seen=item["last_seen"],
        network_scope=item.get("network_scope"),
    )


def _persist_communication_batch(rows):
    """Store and consolidate one bounded batch, never 500k ORM instances."""
    if not rows:
        return
    created = CommunicationObservation.objects.bulk_create(
        rows, batch_size=IMPORT_BATCH_SIZE
    )
    if any(row.pk is None for row in created):
        raise ImportValidationError(
            "La base de datos no devolvió identificadores de observaciones."
        )
    consolidate_communication_observations(
        created, batch_size=IMPORT_BATCH_SIZE
    )
    rows.clear()


def _persist_interface_batch(rows):
    if not rows:
        return
    InterfaceObservation.objects.bulk_create(
        rows, batch_size=IMPORT_BATCH_SIZE
    )
    rows.clear()


def import_analysis(pcap_id, user):
    """Import a validated analyzer stream with bounded RAM and atomic writes.

    Crucially, this never calls get_pcap_analysis (which downloads a huge JSON)
    or builds a list of all communication ORM objects.
    """
    manifest = get_pcap_import_manifest(pcap_id)
    capture = manifest.get("capture")
    analysis_hash = manifest.get("analysis_hash")
    if manifest.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise ImportValidationError("Schema del análisis no soportado.")
    if not isinstance(capture, dict) or capture.get("pcap_id") != pcap_id:
        raise ImportValidationError("La identidad del PCAP no coincide.")
    if not isinstance(analysis_hash, str) or len(analysis_hash) != 64:
        raise ImportValidationError("El análisis no tiene hash válido.")
    if not capture.get("filename") or not capture.get("relative_path"):
        raise ImportValidationError("Faltan los datos de la captura.")

    with transaction.atomic():
        existing = (
            Ingestion.objects.select_for_update()
            .filter(pcap_id=pcap_id, analysis_hash=analysis_hash).first()
        )
        if existing:
            if existing.status == Ingestion.Status.ACTIVE:
                return existing, "ALREADY_IMPORTED"
            Ingestion.objects.filter(
                pcap_id=pcap_id, status=Ingestion.Status.ACTIVE
            ).exclude(pk=existing.pk).update(status=Ingestion.Status.EXCLUDED)
            existing.status = Ingestion.Status.ACTIVE
            existing.save(update_fields=["status"])
            # Original observation evidence is preserved; links were saved
            # during the initial import and do not need to be recomputed.
            return existing, "REACTIVATED"

        Ingestion.objects.filter(
            pcap_id=pcap_id, status=Ingestion.Status.ACTIVE
        ).update(status=Ingestion.Status.EXCLUDED)
        ingestion = Ingestion.objects.create(
            pcap_id=pcap_id, analysis_hash=analysis_hash,
            filename=capture["filename"],
            relative_path=capture["relative_path"],
            schema_version=manifest["schema_version"], imported_by=user,
            status=Ingestion.Status.ACTIVE,
            interfaces_detected=0, communications_detected=0,
        )

        interfaces = []
        communications = []
        interface_count = 0
        communication_count = 0
        seen_communications = False
        try:
            with stream_pcap_analysis(pcap_id) as lines:
                for line in lines:
                    if not line:
                        continue
                    if len(line) > 65536:
                        raise ImportValidationError(
                            "Una observación excede el tamaño permitido."
                        )
                    item = json.loads(line)
                    if not isinstance(item, dict) or not isinstance(item.get("data"), dict):
                        raise ImportValidationError("Registro del análisis inválido.")
                    kind, data = item.get("type"), item["data"]
                    if kind == "interface":
                        if seen_communications:
                            raise ImportValidationError(
                                "Las interfaces deben preceder a las comunicaciones."
                            )
                        interfaces.append(_make_interface(ingestion, data))
                        interface_count += 1
                        if len(interfaces) >= IMPORT_BATCH_SIZE:
                            _persist_interface_batch(interfaces)
                    elif kind == "communication":
                        if not seen_communications:
                            seen_communications = True
                            _persist_interface_batch(interfaces)
                            consolidate_interface_observations(
                                InterfaceObservation.objects.filter(ingestion=ingestion)
                            )
                        communications.append(_make_communication(ingestion, data))
                        communication_count += 1
                        if len(communications) >= IMPORT_BATCH_SIZE:
                            _persist_communication_batch(communications)
                    else:
                        raise ImportValidationError("Tipo de observación desconocido.")
        except (ValueError, TypeError, KeyError, UnicodeError) as error:
            raise ImportValidationError(
                "El analizador envió una observación inválida; la importación "
                "se ha revertido."
            ) from error

        _persist_interface_batch(interfaces)
        if not seen_communications:
            consolidate_interface_observations(
                InterfaceObservation.objects.filter(ingestion=ingestion)
            )
        _persist_communication_batch(communications)

        # Detect analysis replacements during long imports and roll back if
        # the immutable identity changed while the file was being read.
        after = get_pcap_import_manifest(pcap_id)
        if after.get("analysis_hash") != analysis_hash:
            raise ImportValidationError(
                "El análisis cambió durante la importación. Reintenta."
            )
        ingestion.interfaces_detected = interface_count
        ingestion.communications_detected = communication_count
        ingestion.save(update_fields=["interfaces_detected", "communications_detected"])
        return ingestion, "CREATED"
