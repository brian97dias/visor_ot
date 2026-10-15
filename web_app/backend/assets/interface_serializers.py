from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .models import Hardware, NetworkInterface
from .models.network_interface import normalize_mac


class InterfaceHardwareSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)

    class Meta:
        model = Hardware
        fields = ("asset", "asset_name", "role", "manufacturer", "model")


class NetworkInterfaceReadSerializer(serializers.ModelSerializer):
    hardware = InterfaceHardwareSerializer(read_only=True)
    created_by = serializers.SlugRelatedField(
        slug_field="username", read_only=True,
    )
    identified_by = serializers.SlugRelatedField(
        slug_field="username", read_only=True,
    )
    is_identified = serializers.BooleanField(read_only=True)
    observed_ips = serializers.SerializerMethodField()
    observation_count = serializers.IntegerField(read_only=True)
    active_observation_count = serializers.IntegerField(read_only=True)
    has_active_evidence = serializers.BooleanField(read_only=True)

    class Meta:
        model = NetworkInterface
        fields = (
            "id",
            "mac",
            "declared_ip",
            "observed_ips",
            "hardware",
            "is_identified",
            "observation_count",
            "active_observation_count",
            "has_active_evidence",
            "created_at",
            "created_by",
            "identified_at",
            "identified_by",
        )

    def get_observed_ips(self, obj):
        # Prefetched observations avoid one database request per interface.
        observed = getattr(obj, "prefetched_observations", [])
        return sorted({
            ip
            for observation in observed
            for ip in (observation.ips or [])
            if isinstance(ip, str) and ip
        })


class InterfaceObservationDetailSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    mac = serializers.CharField()
    ips = serializers.ListField(child=serializers.CharField())
    first_seen = serializers.CharField()
    last_seen = serializers.CharField()
    ingestion_id = serializers.IntegerField()
    ingestion_filename = serializers.CharField(source="ingestion.filename")
    ingestion_status = serializers.CharField(source="ingestion.status")
    imported_at = serializers.DateTimeField(source="ingestion.imported_at")


class NetworkInterfaceCreateSerializer(serializers.Serializer):
    """Only identity claims. Hardware assignment is a separate, later workflow."""

    mac = serializers.CharField(
        required=False, allow_null=True, allow_blank=True, max_length=17,
    )
    declared_ip = serializers.IPAddressField(
        required=False, allow_null=True, allow_blank=True,
    )

    def validate(self, attrs):
        try:
            mac = normalize_mac(attrs.get("mac"))
        except DjangoValidationError as error:
            raise serializers.ValidationError({"mac": error.messages}) from error

        declared_ip = attrs.get("declared_ip") or None

        if not mac and not declared_ip:
            raise serializers.ValidationError({
                "non_field_errors": [
                    "Se necesita al menos una MAC o una IP declarada."
                ]
            })

        if mac and NetworkInterface.objects.filter(mac__iexact=mac).exists():
            raise serializers.ValidationError({
                "mac": ["Esta MAC ya está registrada. Usa la interfaz existente."]
            })

        return {"mac": mac, "declared_ip": declared_ip}
