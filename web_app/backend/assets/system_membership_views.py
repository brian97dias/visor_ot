"""Symmetric system <-> hardware association API with read-only history."""
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Asset, OTSystem, SystemMembership
from .permissions import SystemPermission
from .system_membership_services import (
    associate_hardware_to_system, unlink_hardware_from_system,
)
from .system_membership_serializers import (
    HardwareMembershipAssignSerializer, SystemMembershipAssignSerializer,
    SystemMembershipReadSerializer,
)


def memberships():
    return SystemMembership.objects.select_related(
        "system", "hardware__asset", "registered_by", "unlinked_by",
    ).order_by("hardware__asset__name", "system__name", "id")


def hardware_asset_or_404(asset_id):
    return get_object_or_404(
        Asset, pk=asset_id, asset_type=Asset.AssetType.HARDWARE,
    )


def results_and_history(rows):
    # Both current memberships and audit history are exposed read-only.
    serialized = SystemMembershipReadSerializer(rows, many=True).data
    return {
        "results": [row for row in serialized if row["unlinked_at"] is None],
        "history": [row for row in serialized if row["unlinked_at"] is not None],
    }


class SystemHardwareView(APIView):
    permission_classes = [IsAuthenticated, SystemPermission]

    def get(self, request, system_id):
        get_object_or_404(OTSystem, pk=system_id)
        return Response(results_and_history(memberships().filter(system_id=system_id)))

    def post(self, request, system_id):
        get_object_or_404(OTSystem, pk=system_id)
        if set(request.data.keys()) != {"hardware_asset_id"}:
            raise ValidationError({"hardware_asset_id": "Indica únicamente hardware_asset_id."})
        serializer = HardwareMembershipAssignSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        hardware_asset_or_404(serializer.validated_data["hardware_asset_id"])
        row = associate_hardware_to_system(
            system_id=system_id,
            hardware_asset_id=serializer.validated_data["hardware_asset_id"],
            user=request.user,
        )
        return Response(
            SystemMembershipReadSerializer(memberships().get(pk=row.pk)).data,
            status=status.HTTP_201_CREATED,
        )


class SystemHardwareUnlinkView(APIView):
    permission_classes = [IsAuthenticated, SystemPermission]

    def delete(self, request, system_id, membership_id):
        get_object_or_404(OTSystem, pk=system_id)
        get_object_or_404(SystemMembership, pk=membership_id, system_id=system_id)
        unlink_hardware_from_system(
            membership_id=membership_id, system_id=system_id, user=request.user,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class HardwareSystemsView(APIView):
    permission_classes = [IsAuthenticated, SystemPermission]

    def get(self, request, asset_id):
        hardware_asset_or_404(asset_id)
        return Response(results_and_history(memberships().filter(hardware_id=asset_id)))

    def post(self, request, asset_id):
        hardware_asset_or_404(asset_id)
        if set(request.data.keys()) != {"system_id"}:
            raise ValidationError({"system_id": "Indica únicamente system_id."})
        serializer = SystemMembershipAssignSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        get_object_or_404(OTSystem, pk=serializer.validated_data["system_id"])
        row = associate_hardware_to_system(
            system_id=serializer.validated_data["system_id"],
            hardware_asset_id=asset_id, user=request.user,
        )
        return Response(
            SystemMembershipReadSerializer(memberships().get(pk=row.pk)).data,
            status=status.HTTP_201_CREATED,
        )


class HardwareSystemUnlinkView(APIView):
    permission_classes = [IsAuthenticated, SystemPermission]

    def delete(self, request, asset_id, membership_id):
        hardware_asset_or_404(asset_id)
        get_object_or_404(SystemMembership, pk=membership_id, hardware_id=asset_id)
        unlink_hardware_from_system(
            membership_id=membership_id, hardware_asset_id=asset_id, user=request.user,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
