"""Inventory integrity rules for active assets and active OT systems.

Existing rows remain untouched. Reports and operators may inspect deficiencies
without silently assigning criticality or inventing a system association.
"""
from .models import Asset, OTSystem, SystemMembership


VALID_CRITICALITIES = frozenset({"LOW", "MEDIUM", "HIGH"})


def has_valid_criticality(value):
    return value in VALID_CRITICALITIES


def current_active_system_links(hardware_asset_id, *, exclude_membership_id=None):
    """Current memberships to active OT systems for an active hardware asset."""
    rows = SystemMembership.objects.filter(
        hardware_id=hardware_asset_id,
        unlinked_at__isnull=True,
        system__status=OTSystem.Status.ACTIVE,
    )
    if exclude_membership_id is not None:
        rows = rows.exclude(pk=exclude_membership_id)
    return rows


def inventory_integrity_issues():
    """Return issues in active inventory; read only, stable and serializable.

    Archived hardware/systems and unlinked memberships never enter the
    report's current scope. This is a preflight, not an implicit migration.
    """
    issues = []
    hardware = list(
        Asset.objects.filter(
            inventory_status=Asset.InventoryStatus.ACTIVE,
            asset_type=Asset.AssetType.HARDWARE,
        ).select_related("hardware").order_by("pk")
    )
    all_active = Asset.objects.filter(inventory_status=Asset.InventoryStatus.ACTIVE)
    for asset in all_active.only("pk", "asset_type", "criticality").order_by("pk"):
        if not has_valid_criticality(asset.criticality):
            issues.append({
                "entity": "asset", "id": asset.pk, "field": "criticality",
                "message": "Registra una criticidad Baja, Media o Alta.",
            })
    for system in OTSystem.objects.filter(status=OTSystem.Status.ACTIVE).only(
        "pk", "criticality"
    ).order_by("pk"):
        if not has_valid_criticality(system.criticality):
            issues.append({
                "entity": "system", "id": system.pk, "field": "criticality",
                "message": "Registra una criticidad Baja, Media o Alta.",
            })
    linked = set(SystemMembership.objects.filter(
        hardware_id__in=[asset.pk for asset in hardware],
        unlinked_at__isnull=True,
        system__status=OTSystem.Status.ACTIVE,
    ).values_list("hardware_id", flat=True))
    for asset in hardware:
        try:
            device = asset.hardware
        except Asset.hardware.RelatedObjectDoesNotExist:
            issues.append({
                "entity": "asset", "id": asset.pk, "field": "hardware",
                "message": "Faltan los datos de identificación del hardware.",
            })
            continue
        for key in ("manufacturer", "model", "role"):
            if not (getattr(device, key) or "").strip():
                issues.append({
                    "entity": "asset", "id": asset.pk, "field": key,
                    "message": "Completa la identificación del hardware.",
                })
        if asset.pk not in linked:
            issues.append({
                "entity": "asset", "id": asset.pk, "field": "system_ids",
                "message": "Asocia el hardware a un sistema OT activo.",
            })
    return issues
