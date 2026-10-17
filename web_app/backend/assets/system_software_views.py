"""Read-only software visibility inferred from active system and installation links.

An OTSystem does NOT install software: member Hardware hosts installation records.
Archive flags label the inventory state without hiding a still-current relationship.
"""
from collections import OrderedDict

from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import OTSystem, SoftwareInstallation, SystemMembership
from .permissions import SystemPermission


def software_for_system(system_id):
    """Group installed software variants across currently participating hardware.

    Only links with no unlinked_at are current, regardless of an Asset's archive
    state. Do not use the plain ManyToMany managers: they include history.
    """
    participating = SystemMembership.objects.filter(
        system_id=system_id, unlinked_at__isnull=True,
    ).values("hardware_id")

    participant_count = participating.count()
    installations = (
        SoftwareInstallation.objects.filter(
            hardware_id__in=participating,
            unlinked_at__isnull=True,
        )
        .select_related("software__asset", "hardware__asset")
        .order_by("software__asset__name", "software_id", "hardware__asset__name", "id")
    )
    grouped = OrderedDict()
    for installation in installations:
        variant = installation.software
        sw_asset = variant.asset
        host = installation.hardware
        if variant.pk not in grouped:
            grouped[variant.pk] = {
                "software_asset_id": sw_asset.pk,
                "name": sw_asset.name,
                "software_type": variant.software_type,
                "manufacturer": variant.manufacturer,
                "product": variant.product,
                "version": variant.version,
                "inventory_status": sw_asset.inventory_status,
                "hardware_count": 0,
                "hardware": [],
            }
        grouped[variant.pk]["hardware"].append({
            "hardware_asset_id": host.asset_id,
            "name": host.asset.name,
            "role": host.role,
            "inventory_status": host.asset.inventory_status,
            "installation_id": installation.pk,
        })
        grouped[variant.pk]["hardware_count"] += 1

    return {
        "system_id": system_id,
        "participant_hardware_count": participant_count,
        "software_count": len(grouped),
        "installation_count": sum(row["hardware_count"] for row in grouped.values()),
        "results": list(grouped.values()),
    }


class SystemSoftwareView(APIView):
    """Derived software inventory; no direct association or mutation endpoint."""
    permission_classes = [IsAuthenticated, SystemPermission]

    def get(self, request, system_id):
        get_object_or_404(OTSystem, pk=system_id)
        return Response(software_for_system(system_id))
