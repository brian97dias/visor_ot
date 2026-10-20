"""CPE association review endpoints, separate from NVD discovery."""
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from assets.models import Asset
from .serializers import CpeDecisionSerializer
from .services.cpe_validation import decide, list_associations
from .views import CpeSearchPermission


class AssetCpeListCreateView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id):
        asset = get_object_or_404(Asset, pk=asset_id)
        return Response({"associations": list_associations(asset)})

    def post(self, request, asset_id):
        serializer = CpeDecisionSerializer(data=request.data, context={"creating": True})
        serializer.is_valid(raise_exception=True)
        association = decide(asset_id, request.user, serializer.validated_data)
        return Response({
            "association": next(
                item for item in list_associations(association.asset)
                if item["id"] == association.pk
            )
        }, status=status.HTTP_201_CREATED)


class AssetCpeDecisionView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def patch(self, request, asset_id, association_id):
        serializer = CpeDecisionSerializer(data=request.data, context={"creating": False})
        serializer.is_valid(raise_exception=True)
        association = decide(
            asset_id, request.user, serializer.validated_data, association_id=association_id
        )
        return Response({
            "association": next(
                item for item in list_associations(association.asset)
                if item["id"] == association.pk
            )
        })
