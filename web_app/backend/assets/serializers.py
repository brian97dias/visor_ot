from rest_framework import serializers

from .models import Asset, Hardware


class HardwareSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hardware
        fields = (
            "manufacturer",
            "model",
            "role",
            "serial_number",
            "physical_location",
        )


class AssetReadSerializer(serializers.ModelSerializer):
    hardware = HardwareSerializer(read_only=True)
    created_by = serializers.SlugRelatedField(
        read_only=True, slug_field="username"
    )
    updated_by = serializers.SlugRelatedField(
        read_only=True, slug_field="username"
    )

    class Meta:
        model = Asset
        fields = (
            "id",
            "name",
            "description",
            "asset_type",
            "criticality",
            "impact",
            "replacement_cost",
            "replacement_currency",
            "hardware",
            "created_at",
            "updated_at",
            "created_by",
            "updated_by",
        )


def validate_replacement_fields(attrs, instance=None):
    cost = attrs.get(
        "replacement_cost",
        instance.replacement_cost if instance else None,
    )
    currency = attrs.get(
        "replacement_currency",
        instance.replacement_currency if instance else "",
    )

    if cost is None and currency:
        raise serializers.ValidationError({
            "replacement_cost": "Indica un costo o deja también la moneda vacía."
        })
    if cost is not None and not currency:
        raise serializers.ValidationError({
            "replacement_currency": "Indica la moneda del costo de reposición."
        })


class AssetCreateSerializer(serializers.ModelSerializer):
    hardware = HardwareSerializer(required=True)

    class Meta:
        model = Asset
        fields = (
            "name",
            "description",
            "asset_type",
            "criticality",
            "impact",
            "replacement_cost",
            "replacement_currency",
            "hardware",
        )

    def validate(self, attrs):
        if attrs["asset_type"] != Asset.AssetType.HARDWARE:
            raise serializers.ValidationError({
                "asset_type": "Por ahora solo se permite registrar HARDWARE."
            })
        validate_replacement_fields(attrs)
        return attrs


class AssetUpdateSerializer(serializers.ModelSerializer):
    hardware = HardwareSerializer(required=False)

    class Meta:
        model = Asset
        fields = (
            "name",
            "description",
            "criticality",
            "impact",
            "replacement_cost",
            "replacement_currency",
            "hardware",
        )

    def validate(self, attrs):
        if "asset_type" in self.initial_data:
            raise serializers.ValidationError({
                "asset_type": "El tipo de activo no se puede modificar."
            })
        validate_replacement_fields(attrs, instance=self.instance)
        return attrs
