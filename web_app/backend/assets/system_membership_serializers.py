"""Read shape for both directions, including inactive membership history."""
from rest_framework import serializers

from .models import SystemMembership


class SystemMembershipReadSerializer(serializers.ModelSerializer):
    system_id = serializers.IntegerField(read_only=True)
    system_name = serializers.CharField(source="system.name", read_only=True)
    system_status = serializers.CharField(source="system.status", read_only=True)
    hardware_asset_id = serializers.IntegerField(source="hardware_id", read_only=True)
    hardware_name = serializers.CharField(source="hardware.asset.name", read_only=True)
    hardware_role = serializers.CharField(source="hardware.role", read_only=True)
    manufacturer = serializers.CharField(source="hardware.manufacturer", read_only=True)
    model = serializers.CharField(source="hardware.model", read_only=True)
    hardware_status = serializers.CharField(
        source="hardware.asset.inventory_status", read_only=True,
    )
    registered_by = serializers.SlugRelatedField(read_only=True, slug_field="username")
    unlinked_by = serializers.SlugRelatedField(read_only=True, slug_field="username")

    class Meta:
        model = SystemMembership
        fields = (
            "id", "system_id", "system_name", "system_status",
            "hardware_asset_id", "hardware_name", "hardware_role",
            "manufacturer", "model", "hardware_status",
            "registered_at", "registered_by", "unlinked_at", "unlinked_by",
        )


class HardwareMembershipAssignSerializer(serializers.Serializer):
    hardware_asset_id = serializers.IntegerField(min_value=1)


class SystemMembershipAssignSerializer(serializers.Serializer):
    system_id = serializers.IntegerField(min_value=1)
