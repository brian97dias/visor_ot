"""Separate operational system fields from server-managed identity and auditing."""
from rest_framework import serializers

from .models import OTSystem
from .inventory_integrity import has_valid_criticality


class OTSystemReadSerializer(serializers.ModelSerializer):
    created_by = serializers.SlugRelatedField(read_only=True, slug_field="username")
    updated_by = serializers.SlugRelatedField(read_only=True, slug_field="username")
    archived_by = serializers.SlugRelatedField(read_only=True, slug_field="username")

    class Meta:
        model = OTSystem
        fields = (
            "id", "name", "description", "criticality",
            "criticality_justification", "impact", "status",
            "created_at", "updated_at", "created_by", "updated_by",
            "archived_at", "archived_by",
        )


class OTSystemListSerializer(OTSystemReadSerializer):
    """Read-only aggregates, intentionally absent from the detail contract."""
    hardware_count = serializers.IntegerField(read_only=True)
    software_count = serializers.IntegerField(read_only=True)

    class Meta(OTSystemReadSerializer.Meta):
        fields = OTSystemReadSerializer.Meta.fields + (
            "hardware_count", "software_count",
        )


class OTSystemWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTSystem
        fields = (
            "name", "description", "criticality",
            "criticality_justification", "impact",
        )

    def to_internal_value(self, data):
        if hasattr(data, "keys"):
            forbidden = set(data.keys()) - set(self.fields)
            if forbidden:
                raise serializers.ValidationError({
                    "non_field_errors": "Campos no permitidos: " + ", ".join(sorted(forbidden))
                })
        return super().to_internal_value(data)

    def validate(self, attrs):
        if (self.instance is None or "criticality" in attrs) and not (
            has_valid_criticality(attrs.get("criticality"))
        ):
            raise serializers.ValidationError({
                "criticality": "Selecciona Baja, Media o Alta."
            })
        return attrs

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("El nombre del sistema es obligatorio.")
        return value
