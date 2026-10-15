from django.db import transaction

from ingestion.models import (
    CommunicationObservation,
    Ingestion,
    InterfaceObservation,
)

from .analyzer_client import get_pcap_analysis
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


def import_analysis(
    pcap_id,
    user,
):

    # La llamada HTTP al Passive Analyzer
    # ocurre fuera de la transacción.
    analysis = get_pcap_analysis(
        pcap_id
    )


    (
        capture,
        interfaces,
        communications,
    ) = validate_analysis(
        analysis,
        pcap_id,
    )


    analysis_hash = (
        calculate_analysis_hash(
            analysis
        )
    )


    with transaction.atomic():

        # Bloqueamos las ingestas de este PCAP
        # mientras decidimos qué hacer.
        existing_ingestion = (
            Ingestion.objects
            .select_for_update()
            .filter(
                pcap_id=pcap_id,
                analysis_hash=analysis_hash,
            )
            .first()
        )


        # CASO 1 y 2:
        # ya conocemos exactamente este análisis.
        if existing_ingestion:

            # Vínculos de interfaces de importaciones antiguas o repetidas.
            consolidate_interface_observations(
                existing_ingestion.interface_observations.all()
            )

            consolidate_communication_observations(
                existing_ingestion
                .communication_observations
                .all()
            )


            if (
                existing_ingestion.status
                == Ingestion.Status.ACTIVE
            ):

                return (
                    existing_ingestion,
                    "ALREADY_IMPORTED",
                )


            # El mismo análisis existe,
            # pero estaba excluido.
            Ingestion.objects.filter(
                pcap_id=pcap_id,
                status=Ingestion.Status.ACTIVE,
            ).exclude(
                pk=existing_ingestion.pk
            ).update(
                status=Ingestion.Status.EXCLUDED
            )


            existing_ingestion.status = (
                Ingestion.Status.ACTIVE
            )

            existing_ingestion.save(
                update_fields=[
                    "status",
                ]
            )


            return (
                existing_ingestion,
                "REACTIVATED",
            )

        # CASO 3:
        # mismo PCAP, pero análisis distinto.
        #
        # Primero excluimos la versión activa
        # anterior para respetar la restricción
        # unique_active_ingestion_per_pcap.
        Ingestion.objects.filter(
            pcap_id=pcap_id,
            status=Ingestion.Status.ACTIVE,
        ).update(
            status=Ingestion.Status.EXCLUDED
        )


        ingestion = (
            Ingestion.objects.create(
                pcap_id=pcap_id,
                analysis_hash=analysis_hash,

                filename=capture[
                    "filename"
                ],

                relative_path=capture[
                    "relative_path"
                ],

                schema_version=analysis[
                    "schema_version"
                ],

                imported_by=user,

                status=(
                    Ingestion.Status.ACTIVE
                ),

                interfaces_detected=len(
                    interfaces
                ),

                communications_detected=len(
                    communications
                ),
            )
        )


        InterfaceObservation.objects.bulk_create([
            InterfaceObservation(
                ingestion=ingestion,

                mac=item[
                    "mac"
                ],

                ips=item.get(
                    "ips",
                    [],
                ),

                first_seen=item[
                    "first_seen"
                ],

                last_seen=item[
                    "last_seen"
                ],
            )

            for item in interfaces
        ], batch_size=500)

        # Consolida a partir de las filas persistidas para obtener los IDs.
        # Mantener la operación dentro de la misma transacción de importación.
        consolidate_interface_observations(
            InterfaceObservation.objects.filter(ingestion=ingestion)
        )

        communication_observations = [
            CommunicationObservation(
                ingestion=ingestion,

                client_ip=item[
                    "client_ip"
                ],

                server_ip=item[
                    "server_ip"
                ],

                client_macs=item.get(
                    "client_macs"
                ),

                server_macs=item.get(
                    "server_macs"
                ),

                transport_protocol=item[
                    "transport_protocol"
                ],

                service_port=item[
                    "service_port"
                ],

                service=item.get(
                    "service"
                ),

                role_source=item.get(
                    "role_source"
                ),

                packet_count=item[
                    "packet_count"
                ],

                first_seen=item[
                    "first_seen"
                ],

                last_seen=item[
                    "last_seen"
                ],

                network_scope=item.get(
                    "network_scope"
                ),
            )

            for item in communications
        ]


        created_observations = (
            CommunicationObservation.objects
            .bulk_create(
                communication_observations
            )
        )


        consolidate_communication_observations( created_observations)

        return (
            ingestion,
            "CREATED",
        )