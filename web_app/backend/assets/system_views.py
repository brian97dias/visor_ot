"""Sistemas OT: lifecycle API. Memberships arrive in the next increment."""
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import OTSystem
from .permissions import SystemPermission
from .system_serializers import OTSystemReadSerializer, OTSystemListSerializer, OTSystemWriteSerializer
from .system_services import register_system, update_system, change_system_status


def system_queryset():
    return OTSystem.objects.select_related("created_by", "updated_by", "archived_by")


def system_list_queryset():
    """Count *current* member Hardware and distinct software variants in one query.

    This counts recorded relationships, not a physically verified inventory.
    A still-current link remains counted when its counterpart is archived.
    """
    return system_queryset().annotate(
        hardware_count=Count(
            "memberships__hardware_id",
            filter=Q(memberships__unlinked_at__isnull=True),
            distinct=True,
        ),
        software_count=Count(
            "memberships__hardware__software_installations__software_id",
            filter=Q(
                memberships__unlinked_at__isnull=True,
                memberships__hardware__software_installations__unlinked_at__isnull=True,
            ),
            distinct=True,
        ),
    )


class SystemListCreateView(APIView):
    permission_classes = [IsAuthenticated, SystemPermission]

    def get(self, request):
        state = request.query_params.get("status", "ACTIVE")
        if state not in ("ACTIVE", "ARCHIVED", "ALL"):
            raise ValidationError({"status": "Usa ACTIVE, ARCHIVED o ALL."})
        systems = system_list_queryset()
        if state != "ALL":
            systems = systems.filter(status=state)
        return Response({"systems": OTSystemListSerializer(systems, many=True).data})

    def post(self, request):
        serializer = OTSystemWriteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        system = register_system(data=serializer.validated_data, user=request.user)
        return Response(OTSystemReadSerializer(system).data, status=status.HTTP_201_CREATED)


class SystemDetailView(APIView):
    permission_classes = [IsAuthenticated, SystemPermission]

    def get(self, request, system_id):
        system = get_object_or_404(system_queryset(), pk=system_id)
        return Response(OTSystemReadSerializer(system).data)

    def patch(self, request, system_id):
        system = get_object_or_404(system_queryset(), pk=system_id)
        serializer = OTSystemWriteSerializer(system, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        system = update_system(
            system_id=system.pk, data=serializer.validated_data, user=request.user,
        )
        return Response(OTSystemReadSerializer(system).data)


class SystemArchiveView(APIView):
    permission_classes = [IsAuthenticated, SystemPermission]

    def post(self, request, system_id):
        get_object_or_404(OTSystem, pk=system_id)
        system = change_system_status(
            system_id=system_id, new_status=OTSystem.Status.ARCHIVED, user=request.user,
        )
        return Response(OTSystemReadSerializer(system).data)


class SystemRestoreView(APIView):
    permission_classes = [IsAuthenticated, SystemPermission]

    def post(self, request, system_id):
        get_object_or_404(OTSystem, pk=system_id)
        system = change_system_status(
            system_id=system_id, new_status=OTSystem.Status.ACTIVE, user=request.user,
        )
        return Response(OTSystemReadSerializer(system).data)
