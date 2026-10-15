from rest_framework import serializers

from ingestion.models import (
    CommunicationObservation,
)

from .models import Communication


class CommunicationEvidenceSerializer(
    serializers.ModelSerializer
):

    ingestion_id = serializers.IntegerField(
        source="ingestion.id",
        read_only=True,
    )

    ingestion_filename = serializers.CharField(
        source="ingestion.filename",
        read_only=True,
    )

    ingestion_status = serializers.CharField(
        source="ingestion.status",
        read_only=True,
    )


    class Meta:

        model = CommunicationObservation

        fields = [
            "id",
            "ingestion_id",
            "ingestion_filename",
            "ingestion_status",
            "packet_count",
            "first_seen",
            "last_seen",
            "client_macs",
            "server_macs",
            "role_source",
            "network_scope",
        ]


class CommunicationListSerializer(
    serializers.ModelSerializer
):

    source_resolution = serializers.SerializerMethodField()
    destination_resolution = serializers.SerializerMethodField()

    def get_source_resolution(self, obj):
        return self.context.get("endpoint_resolutions", {}).get(
            obj.id, {}
        ).get("source_resolution", {"status": "UNKNOWN", "identity": None})

    def get_destination_resolution(self, obj):
        return self.context.get("endpoint_resolutions", {}).get(
            obj.id, {}
        ).get("destination_resolution", {"status": "UNKNOWN", "identity": None})

    active_evidence_count = (
        serializers.IntegerField(
            read_only=True,
        )
    )

    packets_observed = (
        serializers.IntegerField(
            read_only=True,
        )
    )

    first_seen = serializers.CharField(
        read_only=True,
        allow_null=True,
    )

    last_seen = serializers.CharField(
        read_only=True,
        allow_null=True,
    )


    class Meta:

        model = Communication

        fields = [
            "id",
            "source_ip",
            "destination_ip",
            "source_resolution",
            "destination_resolution",
            "transport_protocol",
            "service_port",
            "service",
            "status",
            "active_evidence_count",
            "packets_observed",
            "first_seen",
            "last_seen",
        ]


class CommunicationDetailSerializer(
    CommunicationListSerializer
):

    evidences = serializers.SerializerMethodField()

    classified_by = serializers.CharField(
        source="classified_by.username",
        read_only=True,
        allow_null=True,
    )


    class Meta(
        CommunicationListSerializer.Meta
    ):

        fields = (
            CommunicationListSerializer
            .Meta
            .fields
            + [
                "classified_by",
                "classified_at",
                "evidences",
            ]
        )


    def get_evidences(
        self,
        obj,
    ):

        observations = (
            obj.observations
            .select_related(
                "ingestion"
            )
            .order_by(
                "first_seen"
            )
        )


        return (
            CommunicationEvidenceSerializer(
                observations,
                many=True,
            ).data
        )


class CommunicationClassificationSerializer(
    serializers.Serializer
):

    status = serializers.ChoiceField(
        choices=Communication.Status.choices
    )