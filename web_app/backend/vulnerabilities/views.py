"""HTTP endpoints only enqueue or read persisted NVD search runs."""
from django.shortcuts import get_object_or_404
from django.db.models import OuterRef, Subquery
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from rest_framework.response import Response
from rest_framework.views import APIView

from assets.models import Asset
from users.models import User
from vulnerabilities.models import CpeSearchRun
from .services.cpe_search import create_run, serialize_run
from .services.candidate_matching import hardware_candidates
from .services.identity import fingerprint, hardware_identity


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


class CpeOverviewView(APIView):
    """Read-only work queue overview. No CPE decisions are persisted in phase 1."""
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request):
        latest = CpeSearchRun.objects.filter(asset_id=OuterRef("pk")).order_by(
            "-created_at", "-pk"
        ).values("pk")[:1]
        assets = list(Asset.objects.filter(
            inventory_status=Asset.InventoryStatus.ACTIVE
        ).select_related("hardware", "software").annotate(
            last_cpe_run_id=Subquery(latest)
        ).order_by("name", "pk"))
        ids = {asset.last_cpe_run_id for asset in assets if asset.last_cpe_run_id}
        runs = CpeSearchRun.objects.in_bulk(ids)
        results = []
        for asset in assets:
            run = runs.get(asset.last_cpe_run_id)
            if asset.asset_type == Asset.AssetType.SOFTWARE:
                state = "NOT_SUPPORTED"
            elif run is None:
                state = "NOT_SEARCHED"
            elif run.identity_fingerprint != fingerprint(hardware_identity(asset)):
                state = "STALE"
            elif run.status == CpeSearchRun.Status.COMPLETED:
                state = "CANDIDATES" if hardware_candidates(run.candidates) else "NO_RESULTS"
            else:
                state = run.status

            hardware = getattr(asset, "hardware", None)
            software = getattr(asset, "software", None)
            results.append({
                "asset_id": asset.pk,
                "asset_name": asset.name,
                "asset_type": asset.asset_type,
                "manufacturer": hardware.manufacturer if hardware else (
                    software.manufacturer if software else ""
                ),
                "product": hardware.model if hardware else (
                    software.product if software else ""
                ),
                "cpu_model": hardware.cpu_model if hardware else "",
                "role": hardware.role if hardware else "",
                "version": software.version if software else "",
                "identification_status": state,
                "run_id": run.pk if run else None,
                "candidate_count": len(hardware_candidates(run.candidates)) if run else 0,
                "last_search_at": run.created_at if run else None,
            })
        return Response({"results": results})
