from rest_framework import serializers

from .models import Asset, Hardware, Software
from .interface_serializers import NetworkInterfaceCreateSerializer


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


class SoftwareSerializer(serializers.ModelSerializer):
    """Technical software identity. Installations are managed in increment 3."""

    class Meta:
        model = Software
        fields = ("software_type", "manufacturer", "product", "version")


class AssetReadSerializer(serializers.ModelSerializer):
    hardware = HardwareSerializer(read_only=True)
    software = SoftwareSerializer(read_only=True)
    created_by = serializers.SlugRelatedField(
        read_only=True, slug_field="username"
    )
    updated_by = serializers.SlugRelatedField(
        read_only=True, slug_field="username"
    )
    archived_by = serializers.SlugRelatedField(
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
            "inventory_status",
            "archived_at",
            "archived_by",
            "hardware",
            "software",
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


class InterfaceAssignmentSerializer(serializers.Serializer):
    """An optional interface selection when creating a hardware asset."""

    mode = serializers.ChoiceField(choices=("EXISTING", "MANUAL"))
    interface_id = serializers.IntegerField(min_value=1, required=False)
    mac = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    declared_ip = serializers.IPAddressField(
        required=False, allow_blank=True, allow_null=True
    )

    def validate(self, attrs):
        if attrs["mode"] == "EXISTING":
            if "interface_id" not in attrs or "mac" in attrs or "declared_ip" in attrs:
                raise serializers.ValidationError(
                    "EXISTING requiere únicamente interface_id."
                )
        else:
            if "interface_id" in attrs:
                raise serializers.ValidationError(
                    "MANUAL requiere MAC y/o IP, no interface_id."
                )
            manual = NetworkInterfaceCreateSerializer(data={
                "mac": attrs.get("mac"),
                "declared_ip": attrs.get("declared_ip"),
            })
            manual.is_valid(raise_exception=True)
            attrs.update(manual.validated_data)
        return attrs


class AssetCreateSerializer(serializers.ModelSerializer):
    hardware = HardwareSerializer(required=False)
    software = SoftwareSerializer(required=False)
    interface_assignment = InterfaceAssignmentSerializer(required=False)

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
            "software",
            "interface_assignment",
        )

    def validate(self, attrs):
        kind = attrs.get("asset_type")
        if kind == Asset.AssetType.HARDWARE:
            if "hardware" not in attrs:
                raise serializers.ValidationError({
                    "hardware": "Indica los datos del hardware."
                })
            if "software" in self.initial_data:
                raise serializers.ValidationError({
                    "software": "No envíes datos de software para un hardware."
                })
        elif kind == Asset.AssetType.SOFTWARE:
            if "software" not in attrs:
                raise serializers.ValidationError({
                    "software": "Indica el tipo y producto del software."
                })
            if ("hardware" in self.initial_data
                    or "interface_assignment" in self.initial_data):
                raise serializers.ValidationError({
                    "software": "Una variante de software no registra hardware ni interfaces directamente."
                })
        else:
            raise serializers.ValidationError({"asset_type": "Tipo de activo inválido."})
        validate_replacement_fields(attrs)
        return attrs


class AssetUpdateSerializer(serializers.ModelSerializer):
    hardware = HardwareSerializer(required=False)
    software = SoftwareSerializer(required=False)

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
            "software",
        )

    def validate(self, attrs):
        if "asset_type" in self.initial_data:
            raise serializers.ValidationError({
                "asset_type": "El tipo de activo no se puede modificar."
            })
        if self.instance is not None:
            kind = self.instance.asset_type
            if kind == Asset.AssetType.HARDWARE and "software" in self.initial_data:
                raise serializers.ValidationError({
                    "software": "No puedes editar Software desde un activo Hardware."
                })
            if kind == Asset.AssetType.SOFTWARE and "hardware" in self.initial_data:
                raise serializers.ValidationError({
                    "hardware": "No puedes editar Hardware desde un activo Software."
                })
        validate_replacement_fields(attrs, instance=self.instance)
        return attrs
