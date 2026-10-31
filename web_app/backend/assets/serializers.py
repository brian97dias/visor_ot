from rest_framework import serializers

from .models import Asset, Hardware, Software, SoftwareInstallation
from .interface_serializers import NetworkInterfaceCreateSerializer
from .inventory_integrity import has_valid_criticality


class HardwareSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hardware
        fields = (
            "manufacturer",
            "model",
            "cpu_model",
            "role",
            "serial_number",
            "physical_location",
        )

    def validate(self, attrs):
        if ("role" in attrs and attrs["role"] != Hardware.Role.PLC
                and attrs.get("cpu_model")):
            raise serializers.ValidationError({
                "cpu_model": "El modelo de CPU solo se registra para hardware con rol PLC."
            })
        return attrs


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


class AssetListReadSerializer(AssetReadSerializer):
    """Inventory-only aggregates, not persisted fields on Asset."""

    software_count = serializers.IntegerField(read_only=True)
    interface_count = serializers.IntegerField(read_only=True)
    system_count = serializers.IntegerField(read_only=True)
    hardware_count = serializers.IntegerField(read_only=True)

    class Meta(AssetReadSerializer.Meta):
        fields = AssetReadSerializer.Meta.fields + (
            "software_count", "interface_count", "hardware_count", "system_count",
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
    hardware_asset_id = serializers.IntegerField(min_value=1, required=False, write_only=True)
    system_ids = serializers.ListField(child=serializers.IntegerField(min_value=1), required=False, allow_empty=True, write_only=True)

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
            "hardware_asset_id",
            "system_ids",
        )

    def validate(self, attrs):
        if not self.context.get("import_preview_existing"):
            if not has_valid_criticality(attrs.get("criticality")):
                raise serializers.ValidationError({
                    "criticality": "Selecciona Baja, Media o Alta."
                })
        kind = attrs.get("asset_type")
        if kind == Asset.AssetType.HARDWARE:
            if "hardware" not in attrs:
                raise serializers.ValidationError({
                    "hardware": "Indica los datos del hardware."
                })
            details = attrs["hardware"]
            for field in ("manufacturer", "model", "role"):
                if (not self.context.get("import_preview_existing")
                        and not (details.get(field) or "").strip()):
                    raise serializers.ValidationError({
                        "hardware": {field: "Campo obligatorio para hardware activo."}
                    })
            if not self.context.get("import_preview"):
                systems = attrs.get("system_ids", [])
                if not systems:
                    raise serializers.ValidationError({
                        "system_ids": "Asocia al menos un sistema OT activo."
                    })
                from .models import OTSystem
                valid = OTSystem.objects.filter(
                    pk__in=systems, status=OTSystem.Status.ACTIVE
                ).count()
                if valid != len(set(systems)):
                    raise serializers.ValidationError({
                        "system_ids": "Selecciona únicamente sistemas OT activos."
                    })
            if "software" in self.initial_data:
                raise serializers.ValidationError({
                    "software": "No envíes datos de software para un hardware."
                })
            if "hardware_asset_id" in self.initial_data:
                raise serializers.ValidationError({
                    "hardware_asset_id": "La instalación inicial solo corresponde a Software."
                })
        elif kind == Asset.AssetType.SOFTWARE:
            if "software" not in attrs:
                raise serializers.ValidationError({
                    "software": "Indica el tipo y producto del software."
                })
            if ("hardware" in self.initial_data
                    or "interface_assignment" in self.initial_data
                    or "system_ids" in self.initial_data):
                raise serializers.ValidationError({
                    "software": "Una variante de software no registra hardware ni interfaces directamente."
                })
        else:
            raise serializers.ValidationError({"asset_type": "Tipo de activo inválido."})
        if "system_ids" in attrs:
            if len(attrs["system_ids"]) != len(set(attrs["system_ids"])):
                raise serializers.ValidationError({"system_ids": "No repitas un sistema."})
        validate_replacement_fields(attrs)
        return attrs


class AssetUpdateSerializer(serializers.ModelSerializer):
    hardware = HardwareSerializer(required=False)
    software = SoftwareSerializer(required=False)
    correction_reason = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=1000,
    )
    confirm_shared_correction = serializers.BooleanField(write_only=True, required=False)
    software_change_type = serializers.ChoiceField(
        choices=("CORRECTION", "UPGRADE"), write_only=True, required=False,
    )

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
            "correction_reason",
            "confirm_shared_correction",
            "software_change_type",
        )

    def validate(self, attrs):
        if "criticality" in attrs and not has_valid_criticality(attrs["criticality"]):
            raise serializers.ValidationError({
                "criticality": "Selecciona Baja, Media o Alta."
            })
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
            if kind == Asset.AssetType.HARDWARE and any(key in self.initial_data for key in (
                "correction_reason", "confirm_shared_correction", "software_change_type"
            )):
                raise serializers.ValidationError({
                    "software": "Las correcciones de Software no aplican a Hardware."
                })
            if kind == Asset.AssetType.SOFTWARE and "hardware" in self.initial_data:
                raise serializers.ValidationError({
                    "hardware": "No puedes editar Hardware desde un activo Software."
                })
        if (self.instance is not None
                and self.instance.asset_type == Asset.AssetType.HARDWARE
                and "hardware" in attrs):
            data = attrs["hardware"]
            role = data.get("role", self.instance.hardware.role)
            cpu_model = data.get("cpu_model", self.instance.hardware.cpu_model)
            if role != Hardware.Role.PLC and cpu_model:
                raise serializers.ValidationError({
                    "hardware": {
                        "cpu_model": "El modelo de CPU solo se registra para hardware con rol PLC."
                    }
                })
        validate_replacement_fields(attrs, instance=self.instance)
        return attrs

class HardwareSoftwareAssignSerializer(serializers.Serializer):
    software_asset_id = serializers.IntegerField(min_value=1)


class SoftwareInstallationReadSerializer(serializers.ModelSerializer):
    software_asset_id = serializers.IntegerField(source="software_id", read_only=True)
    name = serializers.CharField(source="software.asset.name", read_only=True)
    inventory_status = serializers.CharField(
        source="software.asset.inventory_status", read_only=True
    )
    software = SoftwareSerializer(read_only=True)

    class Meta:
        model = SoftwareInstallation
        fields = (
            "id", "software_asset_id", "name", "inventory_status",
            "software", "registered_at",
        )



class SoftwareHardwareAssignSerializer(serializers.Serializer):
    hardware_asset_id = serializers.IntegerField(min_value=1)


class SoftwareHardwareInstallationReadSerializer(serializers.ModelSerializer):
    hardware_asset_id = serializers.IntegerField(source="hardware_id", read_only=True)
    hardware_name = serializers.CharField(source="hardware.asset.name", read_only=True)
    hardware_role = serializers.CharField(source="hardware.role", read_only=True)
    manufacturer = serializers.CharField(source="hardware.manufacturer", read_only=True)
    model = serializers.CharField(source="hardware.model", read_only=True)
    inventory_status = serializers.CharField(
        source="hardware.asset.inventory_status", read_only=True
    )

    class Meta:
        model = SoftwareInstallation
        fields = (
            "id", "hardware_asset_id", "hardware_name", "hardware_role",
            "manufacturer", "model", "inventory_status", "registered_at",
        )
