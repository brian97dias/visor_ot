"""API for worker-backed official NVD CPE UUID verification (no inline NVD I/O)."""
from rest_framework import status, serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404

from vulnerabilities.models import CpeSearchRun
from .services.external_cpe import (
    EXTERNAL_CPE_TRIGGER, enqueue_external_cpe, serialize_external_cpe
)
from .views import CpeSearchPermission, identifiable_asset_or_404


class CpeUUIDRequestSerializer(serializers.Serializer):
    cpe_name_id = serializers.UUIDField()


class ExternalCpeVerificationListView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id):
        identifiable_asset_or_404(asset_id)
        runs = (CpeSearchRun.objects.filter(asset_id=asset_id, trigger=EXTERNAL_CPE_TRIGGER)
                .select_related("asset__hardware", "asset__software")
                .order_by("-created_at", "-pk")[:30])
        return Response({"verifications": [serialize_external_cpe(r) for r in runs]})

    def post(self, request, asset_id):
        identifiable_asset_or_404(asset_id)
        serializer = CpeUUIDRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        run, reused = enqueue_external_cpe(
            asset_id, request.user, serializer.validated_data["cpe_name_id"]
        )
        return Response({
            "run_id": run.pk, "status": run.status, "reused": reused,
        }, status=status.HTTP_202_ACCEPTED)


class ExternalCpeVerificationDetailView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id, run_id):
        identifiable_asset_or_404(asset_id)
        run = get_object_or_404(
            CpeSearchRun.objects.select_related("asset__hardware", "asset__software"),
            pk=run_id, asset_id=asset_id, trigger=EXTERNAL_CPE_TRIGGER,
        )
        return Response({"verification": serialize_external_cpe(run)})
