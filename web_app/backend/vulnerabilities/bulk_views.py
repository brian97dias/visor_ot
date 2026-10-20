"""Bulk CPE discovery. Submits durable work only; NVD remains worker-owned."""
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from assets.models import Asset
from vulnerabilities.models import CpeSearchRun
from .services.cpe_search import create_run
from .views import CpeSearchPermission

MAX_BULK_ASSETS = 100


class BulkCpeSerializer(serializers.Serializer):
    asset_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        allow_empty=False, max_length=MAX_BULK_ASSETS,
    )
    scope = serializers.ChoiceField(
        choices=[CpeSearchRun.Scope.SPECIFIC],
        default=CpeSearchRun.Scope.SPECIFIC,
    )

    def validate_asset_ids(self, ids):
        # Duplicate IDs in one batch are harmless and must not enqueue twice.
        return list(dict.fromkeys(ids))


class CpeBulkSearchView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def post(self, request):
        serializer = BulkCpeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ids = serializer.validated_data["asset_ids"]
        scope = serializer.validated_data["scope"]
        assets = Asset.objects.filter(pk__in=ids).only(
            "id", "name", "asset_type", "inventory_status"
        ).in_bulk()

        results = []
        summary = {
            "received": len(ids), "queued": 0, "reused": 0,
            "skipped": 0, "failed": 0,
        }
        for asset_id in ids:
            asset = assets.get(asset_id)
            result = {"asset_id": asset_id}
            if asset is None:
                result.update(outcome="NOT_FOUND", message="El activo no existe.")
                summary["failed"] += 1
            else:
                result["asset_name"] = asset.name
                result["asset_type"] = asset.asset_type
                if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
                    result.update(outcome="SKIPPED", message="El activo está archivado.")
                    summary["skipped"] += 1
                elif asset.asset_type == Asset.AssetType.SOFTWARE:
                    result.update(
                        outcome="UNSUPPORTED",
                        message="La búsqueda CPE de software se habilitará en la siguiente fase.",
                    )
                    summary["skipped"] += 1
                elif asset.asset_type != Asset.AssetType.HARDWARE:
                    result.update(outcome="SKIPPED", message="Tipo de activo sin soporte.")
                    summary["skipped"] += 1
                else:
                    try:
                        run, reused = create_run(
                            asset.pk, request.user, scope, return_reused=True
                        )
                        result.update(
                            outcome="REUSED" if reused else "QUEUED",
                            run_id=run.pk, status=run.status,
                        )
                        summary["reused" if reused else "queued"] += 1
                    except (ValueError, serializers.ValidationError) as exc:
                        # One bad identity must not roll back valid sibling jobs.
                        reason = (getattr(exc, "detail", None) or str(exc))
                        result.update(outcome="INVALID_IDENTITY", message=str(reason))
                        summary["failed"] += 1
            results.append(result)

        return Response(
            {"scope": scope, "results": results, "summary": summary},
            status=status.HTTP_202_ACCEPTED if (summary["queued"] or summary["reused"])
            else status.HTTP_200_OK,
        )
