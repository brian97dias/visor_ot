"""Read-only CPE snapshot explorer and evidence-based human review preparation.

This API never queries NVD and never automatically validates CPEs.
"""
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from assets.models import Asset
from vulnerabilities.models import CpeQuerySnapshot, CpeQueryProduct, CpeSearchRun
from .services.candidate_matching import normalize_candidate
from .services.cpe_catalogue_matching import browse_catalogue, summarize_catalogue
from .services.cpe_search import serialize_run
from .services.identity import hardware_identity, fingerprint
from .views import CpeSearchPermission, hardware_or_404


class ExplorerFilters(serializers.Serializer):
    view = serializers.ChoiceField(choices=("ALL", "CANDIDATES", "EXCLUDED"), default="ALL")
    q = serializers.CharField(required=False, allow_blank=True, max_length=120, default="")
    cpe_type = serializers.ChoiceField(choices=("ALL", "h", "o", "a"), default="ALL")
    deprecated = serializers.ChoiceField(choices=("ALL", "YES", "NO"), default="ALL")
    after = serializers.IntegerField(min_value=0, default=0)
    limit = serializers.IntegerField(min_value=1, max_value=100, default=25)


class CatalogueEvidenceSerializer(serializers.Serializer):
    evidence_id = serializers.IntegerField(min_value=1)


class CatalogueSnapshotsView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id):
        asset = hardware_or_404(asset_id)
        snapshots = CpeQuerySnapshot.objects.select_related("cache").order_by(
            "-created_at", "-pk"
        )[:100]
        return Response({
            "asset_id": asset.pk,
            "snapshots": [{
                "id": snapshot.pk,
                "strategy": snapshot.cache.strategy,
                "parameter": snapshot.cache.parameter,
                "status": snapshot.status,
                "expected_total": snapshot.expected_total,
                "stored_products": snapshot.unique_products_count,
                "next_start_index": snapshot.next_start_index,
                "created_at": snapshot.created_at,
                "finished_at": snapshot.finished_at,
            } for snapshot in snapshots]
        })


class CatalogueSnapshotBrowseView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id, snapshot_id):
        asset = hardware_or_404(asset_id)
        filters = ExplorerFilters(data=request.query_params)
        filters.is_valid(raise_exception=True)
        snapshot = get_object_or_404(
            CpeQuerySnapshot.objects.select_related("cache"), pk=snapshot_id
        )
        try:
            identity = hardware_identity(asset)
            params = filters.validated_data
            page = browse_catalogue(
                snapshot, identity, view=params["view"], after_id=params["after"],
                limit=params["limit"], search=params["q"],
                cpe_type=params["cpe_type"], deprecated=params["deprecated"],
            )
            summary = summarize_catalogue(snapshot, identity)
        except ValueError as exc:
            raise ValidationError({"catalogue": str(exc)}) from exc
        return Response({
            "snapshot": {
                "id": snapshot.pk, "strategy": snapshot.cache.strategy,
                "parameter": snapshot.cache.parameter, "status": snapshot.status,
            },
            "page": page,
            "summary": summary,
        })


class CatalogueSelectEvidenceView(APIView):
    """Prepare a single, audited, NVD-backed candidate for existing review API.

    POST only selects; CONFIRMED or REJECTED requires the existing explicit
    AssetCpe decision endpoint. No arbitrary UUIDs are accepted from clients.
    """
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def post(self, request, asset_id, snapshot_id):
        data = CatalogueEvidenceSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        with transaction.atomic():
            asset = get_object_or_404(
                Asset.objects.select_for_update(),
                pk=asset_id, asset_type=Asset.AssetType.HARDWARE
            )
            if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
                raise ValidationError({"asset": "No se permite revisar CPE para hardware archivado."})
            snapshot = get_object_or_404(
                CpeQuerySnapshot.objects.select_related("cache"), pk=snapshot_id
            )
            if snapshot.status != CpeQuerySnapshot.Status.COMPLETED:
                raise ValidationError({"snapshot": "La recuperación debe estar completada para seleccionar evidencia."})
            evidence = get_object_or_404(
                CpeQueryProduct, snapshot=snapshot, pk=data.validated_data["evidence_id"]
            )
            identity = hardware_identity(asset)
            candidate = normalize_candidate(
                evidence.nvd_record, identity, snapshot.cache.strategy
            )
            if (candidate is None or candidate["cpe_type"] != "h" or
                    str(candidate["cpe_name_id"]).lower() !=
                    str(evidence.cpe.cpe_name_id).lower()):
                raise ValidationError({
                    "evidence_id": "La evidencia no identifica un CPE hardware válido de este snapshot."
                })
            key = fingerprint(identity)
            # Avoid duplicate review preparations on repeat button clicks.
            for previous in CpeSearchRun.objects.filter(
                asset=asset, trigger="CATALOGUE",
                identity_fingerprint=key, status=CpeSearchRun.Status.COMPLETED,
            ).order_by("-pk")[:25]:
                if (previous.queries and previous.queries[0].get("snapshot_id") == snapshot.pk
                        and previous.queries[0].get("evidence_id") == evidence.pk):
                    return Response({"run": serialize_run(previous), "reused": True})

            candidate["discovery_levels"] = ["CATALOGUE"]
            candidate["source_snapshot_id"] = snapshot.pk
            candidate["source_evidence_id"] = evidence.pk
            now = timezone.now()
            run = CpeSearchRun.objects.create(
                asset=asset, requested_by=request.user,
                trigger="CATALOGUE", status=CpeSearchRun.Status.COMPLETED,
                scope=CpeSearchRun.Scope.SPECIFIC,
                identity_snapshot=identity, identity_fingerprint=key,
                candidates=[candidate],
                queries=[{
                    "level": "CATALOGUE", "strategy": snapshot.cache.strategy,
                    "parameter": snapshot.cache.parameter, "snapshot_id": snapshot.pk,
                    "evidence_id": evidence.pk, "status": "COMPLETED",
                    "source": "NVD_CPE_2.0",
                }],
                result_truncated=False, started_at=now, finished_at=now,
            )
            return Response({"run": serialize_run(run), "reused": False},
                            status=status.HTTP_201_CREATED)
