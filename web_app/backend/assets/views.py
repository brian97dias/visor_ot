from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Asset
from .permissions import AssetPermission
from .serializers import (
    AssetCreateSerializer,
    AssetReadSerializer,
    AssetUpdateSerializer,
)
from .services import register_hardware_asset, update_hardware_asset


def asset_queryset():
    return Asset.objects.select_related(
        "hardware",
        "created_by",
        "updated_by",
    )


class AssetListCreateView(APIView):
    permission_classes = [IsAuthenticated, AssetPermission]

    def get(self, request):
        assets = asset_queryset()
        return Response({
            "assets": AssetReadSerializer(assets, many=True).data,
        })

    def post(self, request):
        serializer = AssetCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

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

        asset = update_hardware_asset(
            asset=asset,
            data=serializer.validated_data,
            user=request.user,
        )
        return Response(AssetReadSerializer(asset).data)
