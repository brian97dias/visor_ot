from rest_framework import serializers

from .models import (
    CommunicationObservation,
    Ingestion,
    InterfaceObservation,
)


class InterfaceObservationSerializer(
    serializers.ModelSerializer
):

    class Meta:
        model = InterfaceObservation

        fields = [
            "id",
            "mac",
            "ips",
            "first_seen",
            "last_seen",
        ]


class CommunicationObservationSerializer(
    serializers.ModelSerializer
):

    class Meta:
        model = CommunicationObservation

        fields = [
            "id",
            "client_ip",
            "server_ip",
            "client_macs",
            "server_macs",
            "transport_protocol",
            "service_port",
            "service",
            "role_source",
            "packet_count",
            "first_seen",
            "last_seen",
            "network_scope",
        ]


class IngestionListSerializer(
    serializers.ModelSerializer
):

    imported_by = serializers.CharField(
        source="imported_by.username",
        read_only=True,
    )


    class Meta:
        model = Ingestion

        fields = [
            "id",
            "pcap_id",
            "filename",
            "relative_path",
            "schema_version",
            "imported_at",
            "imported_by",
            "status",
            "interfaces_detected",
            "communications_detected",
        ]


class IngestionDetailSerializer(
    IngestionListSerializer
):

    interfaces = (
        InterfaceObservationSerializer(
            source="interface_observations",
            many=True,
            read_only=True,
        )
    )

    communications = (
        CommunicationObservationSerializer(
            source="communication_observations",
            many=True,
            read_only=True,
        )
    )


    class Meta(
        IngestionListSerializer.Meta
    ):

        fields = (
            IngestionListSerializer
            .Meta
            .fields
            + [
                "interfaces",
                "communications",
            ]
        )