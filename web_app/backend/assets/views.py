from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Asset
from .asset_excel import export_inventory_workbook
from .permissions import AssetPermission, AssetArchivePermission
from .serializers import (
    AssetCreateSerializer,
    AssetReadSerializer,
    AssetListReadSerializer,
    AssetUpdateSerializer,
)
from .software_services import register_installed_software_asset, update_software_asset
from .services import (
    register_hardware_asset,
    update_hardware_asset,
    change_inventory_status,
)


def asset_queryset():
    return Asset.objects.select_related(
        "hardware",
        "software",
        "created_by",
        "updated_by",
    )


def asset_list_queryset():
    """Attach current relationship counts to a single inventory queryset.

    Using distinct counts avoids multiplying software and interface rows
    for hardware that has several of each. Archived related assets remain
    counted while their association is still active; only an explicit
    unlink removes a SoftwareInstallation from these summaries.
    """
    return asset_queryset().annotate(
        software_count=Count(
            "hardware__software_installations",
            filter=Q(hardware__software_installations__unlinked_at__isnull=True),
            distinct=True,
        ),
        interface_count=Count("hardware__network_interfaces", distinct=True),
        system_count=Count(
            "hardware__system_memberships__system_id",
            filter=Q(hardware__system_memberships__unlinked_at__isnull=True),
            distinct=True,
        ),
        hardware_count=Count(
            "software__installations",
            filter=Q(software__installations__unlinked_at__isnull=True),
            distinct=True,
        ),
    )


class AssetListCreateView(APIView):
    permission_classes = [IsAuthenticated, AssetPermission]

    def get(self, request):
        inventory_status = request.query_params.get("inventory_status", "ACTIVE")
        allowed = {
            Asset.InventoryStatus.ACTIVE,
            Asset.InventoryStatus.ARCHIVED,
            "ALL",
        }
        if inventory_status not in allowed:
            raise ValidationError({
                "inventory_status": "Usa ACTIVE, ARCHIVED o ALL."
            })

        assets = asset_list_queryset()
        if inventory_status != "ALL":
            assets = assets.filter(inventory_status=inventory_status)

        return Response({
            "assets": AssetListReadSerializer(assets, many=True).data,
        })

    def post(self, request):
        serializer = AssetCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if serializer.validated_data["asset_type"] == Asset.AssetType.SOFTWARE:
            asset = register_installed_software_asset(
                data=serializer.validated_data,
                user=request.user,
            )
        else:
            asset = register_hardware_asset(
                data=serializer.validated_data,
                user=request.user,
            )
        return Response(
            AssetReadSerializer(asset).data,
            status=status.HTTP_201_CREATED,
        )


class AssetDetailView(APIView):
    permission_classes = [IsAuthenticated, AssetPermission]

    def get(self, request, asset_id):
        asset = get_object_or_404(asset_queryset(), pk=asset_id)
        return Response(AssetReadSerializer(asset).data)

    def patch(self, request, asset_id):
        asset = get_object_or_404(asset_queryset(), pk=asset_id)
        serializer = AssetUpdateSerializer(
            asset,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)

        if asset.asset_type == Asset.AssetType.SOFTWARE:
            asset = update_software_asset(
                asset_id=asset.pk,
                data=serializer.validated_data,
                user=request.user,
            )
        else:
            asset = update_hardware_asset(
                asset=asset,
                data=serializer.validated_data,
                user=request.user,
            )
        return Response(AssetReadSerializer(asset).data)


class AssetArchiveView(APIView):
    permission_classes = [IsAuthenticated, AssetArchivePermission]

    def post(self, request, asset_id):
        asset = get_object_or_404(asset_queryset(), pk=asset_id)
        asset = change_inventory_status(
            asset=asset,
            new_status=Asset.InventoryStatus.ARCHIVED,
            user=request.user,
        )
        return Response(AssetReadSerializer(asset).data)


class AssetRestoreView(APIView):
    permission_classes = [IsAuthenticated, AssetArchivePermission]

    def post(self, request, asset_id):
        asset = get_object_or_404(asset_queryset(), pk=asset_id)
        asset = change_inventory_status(
            asset=asset,
            new_status=Asset.InventoryStatus.ACTIVE,
            user=request.user,
            system_ids=request.data.get("system_ids"),
        )
        return Response(AssetReadSerializer(asset).data)



class AssetExportExcelView(APIView):
    """Read-only export of all Hardware and Software assets, archived included."""
    permission_classes = [IsAuthenticated, AssetPermission]

    def get(self, request):
        assets = asset_queryset().order_by("asset_type", "name", "id")
        workbook = export_inventory_workbook(assets.iterator(chunk_size=1000))
        filename = f"Visor_OT_Inventario_{timezone.localdate():%Y%m%d}.xlsx"
        response = HttpResponse(
            workbook,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Content-Length"] = len(workbook)
        response["Cache-Control"] = "no-store"
        return response
