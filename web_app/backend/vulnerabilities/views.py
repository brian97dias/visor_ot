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
from .services.cpe_search import create_run, create_advanced_run, serialize_run
from .models import AssetCpe
from .services.identity import fingerprint, hardware_identity, software_identity
from .services.cpe_overview import count_current_cpes, is_outdated_association


class CpeSearchPermission(BasePermission):
    def has_permission(self, request, view):
        role = getattr(request.user, "role", None)
        if request.method in SAFE_METHODS:
            return role in (User.Role.ADMIN, User.Role.ANALYST, User.Role.OPERATOR)
        return request.method in ("POST", "PATCH") and role in (User.Role.ADMIN, User.Role.ANALYST)


def hardware_or_404(asset_id):
    return get_object_or_404(
        Asset.objects.select_related("hardware"),
        pk=asset_id, asset_type=Asset.AssetType.HARDWARE
    )


def identifiable_asset_or_404(asset_id):
    return get_object_or_404(
        Asset.objects.select_related("hardware", "software"),
        pk=asset_id, asset_type__in=(Asset.AssetType.HARDWARE, Asset.AssetType.SOFTWARE),
    )


class CpeSearchStartView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def post(self, request, asset_id):
        asset = identifiable_asset_or_404(asset_id)
        if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
            raise ValidationError({"asset": "Solo se buscan CPE de activos vigentes."})
        if set(request.data) - {"scope"}:
            raise ValidationError({"scope": "Solo se admite el campo scope."})
        scope = request.data.get("scope", "SPECIFIC")
        if scope not in CpeSearchRun.Scope.values:
            raise ValidationError({"scope": "Usa SPECIFIC o BROAD."})
        run = create_run(asset.pk, request.user, scope)
        return Response({"run_id": run.pk, "status": run.status}, status=status.HTTP_202_ACCEPTED)



class CpeAdvancedSearchView(APIView):
    """Advanced requests use the same PostgreSQL queue and authenticated roles."""
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def post(self, request, asset_id):
        asset = hardware_or_404(asset_id)
        if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
            raise ValidationError({"asset": "Solo se buscan CPE de hardware activo."})
        if not isinstance(request.data, dict):
            raise ValidationError({"advanced": "Envía un objeto JSON."})
        run, reused = create_advanced_run(asset.pk, request.user, request.data)
        return Response(
            {"run_id": run.pk, "status": run.status, "reused": reused},
            status=status.HTTP_202_ACCEPTED,
        )


class CpeSearchLatestView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id):
        identifiable_asset_or_404(asset_id)
        run = CpeSearchRun.objects.filter(asset_id=asset_id).first()
        if run is None:
            return Response({"run": None})
        return Response({"run": serialize_run(run)})


class CpeSearchDetailView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id, run_id):
        identifiable_asset_or_404(asset_id)
        run = get_object_or_404(
            CpeSearchRun.objects.select_related("asset__hardware", "asset__software"),
            pk=run_id, asset_id=asset_id
        )
        return Response({"run": serialize_run(run)})


class CpeOverviewView(APIView):
    """One lifecycle status plus CPE counts from current completed search."""
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request):
        ordered_runs = CpeSearchRun.objects.filter(
            asset_id=OuterRef("pk")
        ).order_by("-created_at", "-pk")
        latest = ordered_runs.values("pk")[:1]
        latest_completed = ordered_runs.filter(
            status=CpeSearchRun.Status.COMPLETED
        ).values("pk")[:1]
        assets = list(
            Asset.objects.filter(inventory_status=Asset.InventoryStatus.ACTIVE)
            .select_related("hardware", "software")
            .annotate(
                last_cpe_run_id=Subquery(latest),
                last_completed_cpe_run_id=Subquery(latest_completed),
            )
            .order_by("name", "pk")
        )
        run_ids = {
            pk for asset in assets
            for pk in (asset.last_cpe_run_id, asset.last_completed_cpe_run_id)
            if pk is not None
        }
        runs = CpeSearchRun.objects.in_bulk(run_ids)
        associations_by_asset = {}
        for association in AssetCpe.objects.filter(
            asset_id__in=[asset.pk for asset in assets]
        ).select_related("cpe"):
            associations_by_asset.setdefault(association.asset_id, []).append(association)

        results = []
        for asset in assets:
            latest_run = runs.get(asset.last_cpe_run_id)
            completed_run = runs.get(asset.last_completed_cpe_run_id)
            associations = associations_by_asset.get(asset.pk, [])
            try:
                identity = fingerprint(
                    software_identity(asset) if asset.asset_type == Asset.AssetType.SOFTWARE
                    else hardware_identity(asset)
                )
            except (ValueError, AttributeError):
                identity = ""
            counts = count_current_cpes(completed_run, associations, identity)
            outdated = any(is_outdated_association(a, identity) for a in associations)
            # A current decision absent from the latest completed valid search
            # cannot be silently treated as validated by that search.
            # A rejected historical suggestion missing from a fresh search
            # needs no further review. A confirmed CPE missing from a valid
            # search DOES: its applicability requires renewed investigation.
            unmatched_decisions = sum(
                a.validation_status == AssetCpe.Validation.CONFIRMED
                and a.validated_identity_fingerprint == identity
                and str(a.cpe.cpe_name_id).lower() not in counts["candidate_ids"]
                for a in associations
            ) if counts["available"] else 0
            if latest_run is None:
                state = "NOT_SEARCHED"
            elif latest_run.status in (
                CpeSearchRun.Status.QUEUED, CpeSearchRun.Status.RUNNING,
            ):
                state = latest_run.status
            elif latest_run.status == CpeSearchRun.Status.FAILED:
                state = "FAILED"
            elif outdated or unmatched_decisions:
                state = "STALE"
            elif not counts["available"]:
                state = "STALE"
            elif completed_run.result_truncated:
                state = "PARTIAL_RESULTS"
            elif counts["total"] == 0:
                state = "NO_RESULTS"
            elif (counts["exploratory_count"] > 0 and counts["unreviewed"] == 0
                  and counts["confirmed"] == 0 and counts["rejected"] == 0):
                # Weak candidates can be explored; they are not confirmations
                # and never inflate mandatory pending counts.
                state = "TO_REVIEW"
            elif counts["unreviewed"] == 0:
                state = "EVALUATED"
            elif counts["confirmed"] or counts["rejected"]:
                state = "IN_REVIEW"
            else:
                state = "TO_REVIEW"

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
                "run_id": latest_run.pk if latest_run else None,
                "candidate_count": counts["total"],
                "exploratory_count": counts["exploratory_count"],
                "confirmed_count": counts["confirmed"],
                "rejected_count": counts["rejected"],
                "unreviewed_count": counts["unreviewed"],
                "legacy_pending_count": counts["legacy_pending"],
                # Kept for backwards compatibility; reopened are NOT reviewed.
                "reopened_count": sum(
                    a.validation_status == AssetCpe.Validation.REOPENED
                    for a in associations
                ),
                "reviewed_count": counts["confirmed"] + counts["rejected"]
                    + counts["legacy_pending"],
                "out_of_scope_count": unmatched_decisions,
                "last_search_at": latest_run.created_at if latest_run else None,
            })
        return Response({"results": results})
