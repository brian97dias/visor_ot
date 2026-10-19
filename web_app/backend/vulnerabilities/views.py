"""HTTP endpoints only enqueue or read persisted NVD search runs."""
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from rest_framework.response import Response
from rest_framework.views import APIView

from assets.models import Asset
from users.models import User
from vulnerabilities.models import CpeSearchRun
from .services.cpe_search import create_run, serialize_run


class CpeSearchPermission(BasePermission):
    def has_permission(self, request, view):
        role = getattr(request.user, "role", None)
        if request.method in SAFE_METHODS:
            return role in (User.Role.ADMIN, User.Role.ANALYST, User.Role.OPERATOR)
        return request.method == "POST" and role in (User.Role.ADMIN, User.Role.ANALYST)


def hardware_or_404(asset_id):
    return get_object_or_404(
        Asset.objects.select_related("hardware"),
        pk=asset_id, asset_type=Asset.AssetType.HARDWARE
    )


class CpeSearchStartView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def post(self, request, asset_id):
        asset = hardware_or_404(asset_id)
        if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
            raise ValidationError({"asset": "Solo se buscan CPE de hardware activo."})
        if set(request.data) - {"scope"}:
            raise ValidationError({"scope": "Solo se admite el campo scope."})
        scope = request.data.get("scope", "SPECIFIC")
        if scope not in CpeSearchRun.Scope.values:
            raise ValidationError({"scope": "Usa SPECIFIC o BROAD."})
        run = create_run(asset.pk, request.user, scope)
        return Response({"run_id": run.pk, "status": run.status}, status=status.HTTP_202_ACCEPTED)


class CpeSearchLatestView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id):
        hardware_or_404(asset_id)
        run = CpeSearchRun.objects.filter(asset_id=asset_id).first()
        if run is None:
            return Response({"run": None})
        return Response({"run": serialize_run(run)})


class CpeSearchDetailView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id, run_id):
        hardware_or_404(asset_id)
        run = get_object_or_404(
            CpeSearchRun.objects.select_related("asset__hardware"),
            pk=run_id, asset_id=asset_id
        )
        return Response({"run": serialize_run(run)})
