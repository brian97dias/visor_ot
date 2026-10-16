"""Current installed software for a hardware asset (increment 3 groundwork)."""

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from users.models import User

from .models import Asset, SoftwareInstallation
from .serializers import (
    HardwareSoftwareAssignSerializer, SoftwareInstallationReadSerializer,
)
from .software_services import associate_software, unlink_software


class SoftwareInstallationPermission(BasePermission):
    def has_permission(self, request, view):
        role = getattr(request.user, "role", None)
        if request.method in SAFE_METHODS:
            return role in (User.Role.ADMIN, User.Role.OPERATOR, User.Role.ANALYST)
        return role in (User.Role.ADMIN, User.Role.OPERATOR)


def hardware_asset_or_404(asset_id):
    return get_object_or_404(
        Asset, pk=asset_id, asset_type=Asset.AssetType.HARDWARE
    )


def active_installations(hardware_id):
    return (
        SoftwareInstallation.objects.filter(
            hardware_id=hardware_id, unlinked_at__isnull=True
        )
        .select_related("software__asset", "registered_by")
        .order_by("software__asset__name", "id")
    )


class HardwareSoftwareInstallationView(APIView):
    permission_classes = [IsAuthenticated, SoftwareInstallationPermission]

    def get(self, request, asset_id):
        hardware_asset_or_404(asset_id)
        rows = active_installations(asset_id)
        return Response({
            "results": SoftwareInstallationReadSerializer(rows, many=True).data
        })

    def post(self, request, asset_id):
        hardware_asset_or_404(asset_id)
        if set(request.data.keys()) != {"software_asset_id"}:
            raise ValidationError({
                "software_asset_id": "Indica únicamente software_asset_id."
            })
        serializer = HardwareSoftwareAssignSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        row = associate_software(
            software_id=serializer.validated_data["software_asset_id"],
            hardware_asset_id=asset_id,
            user=request.user,
        )
        return Response(
            SoftwareInstallationReadSerializer(
                SoftwareInstallation.objects.select_related(
                    "software__asset"
                ).get(pk=row.pk)
            ).data,
            status=status.HTTP_201_CREATED,
        )


class HardwareSoftwareUnlinkView(APIView):
    permission_classes = [IsAuthenticated, SoftwareInstallationPermission]

    def delete(self, request, asset_id, installation_id):
        hardware_asset_or_404(asset_id)
        installation = get_object_or_404(
            SoftwareInstallation, pk=installation_id, hardware_id=asset_id,
        )
        unlink_software(installation_id=installation.pk, user=request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)



class SoftwareHistoryView(APIView):
    permission_classes = [IsAuthenticated, SoftwareInstallationPermission]

    def get(self, request, asset_id):
        """Installation history and technical correction audit, read-only."""
        from .models import Software, SoftwareCorrection

        sw = get_object_or_404(
            Software.objects.select_related("asset"),
            pk=asset_id,
            asset__asset_type=Asset.AssetType.SOFTWARE,
        )
        installations = SoftwareInstallation.objects.filter(
            software=sw
        ).select_related("hardware__asset", "registered_by", "unlinked_by")
        corrections = SoftwareCorrection.objects.filter(
            software=sw
        ).select_related("changed_by")
        return Response({
            "software_asset_id": asset_id,
            "active_installation_count": installations.filter(
                unlinked_at__isnull=True
            ).count(),
            "installation_history_count": installations.count(),
            "installations": [
                {
                    "id": row.id,
                    "hardware_asset_id": row.hardware_id,
                    "hardware_name": row.hardware.asset.name,
                    "identity_snapshot": row.identity_snapshot,
                    "registered_at": row.registered_at,
                    "registered_by": row.registered_by.username,
                    "unlinked_at": row.unlinked_at,
                    "unlinked_by": row.unlinked_by.username if row.unlinked_by else None,
                }
                for row in installations
            ],
            "corrections": [
                {
                    "id": change.id,
                    "changed_at": change.changed_at,
                    "changed_by": change.changed_by.username,
                    "reason": change.reason,
                    "identity_before": change.identity_before,
                    "identity_after": change.identity_after,
                    "affected_active_installations": change.affected_active_installations,
                }
                for change in corrections
            ],
        })
