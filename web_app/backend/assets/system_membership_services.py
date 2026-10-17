"""Single transactional service for both association directions."""
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .models import Asset, Hardware, OTSystem, SystemMembership


@transaction.atomic
def associate_hardware_to_system(*, system_id, hardware_asset_id, user):
    # Serialize changes to a system before checking its current membership.
    system = OTSystem.objects.select_for_update().get(pk=system_id)
    hardware = Hardware.objects.select_related("asset").get(pk=hardware_asset_id)
    if system.status != OTSystem.Status.ACTIVE:
        raise ValidationError({"system": "Restaura el sistema para asociar hardware."})
    if hardware.asset.inventory_status != Asset.InventoryStatus.ACTIVE:
        raise ValidationError({"hardware": "No se puede asociar un hardware archivado."})
    if SystemMembership.objects.filter(
        system=system, hardware=hardware, unlinked_at__isnull=True,
    ).exists():
        raise ValidationError({"hardware": "El hardware ya pertenece a este sistema."})
    # The partial unique constraint also protects against concurrent duplicates.
    return SystemMembership.objects.create(
        system=system, hardware=hardware, registered_by=user,
    )


@transaction.atomic
def unlink_hardware_from_system(*, membership_id, user, system_id=None, hardware_asset_id=None):
    membership = SystemMembership.objects.select_related("hardware__asset").get(pk=membership_id)
    system = OTSystem.objects.select_for_update().get(pk=membership.system_id)
    membership = SystemMembership.objects.select_for_update().get(pk=membership_id)
    if system_id is not None and membership.system_id != system_id:
        raise ValidationError({"membership": "La asociación no pertenece al sistema indicado."})
    if hardware_asset_id is not None and membership.hardware_id != hardware_asset_id:
        raise ValidationError({"membership": "La asociación no pertenece al hardware indicado."})
    if system.status != OTSystem.Status.ACTIVE:
        raise ValidationError({"system": "Restaura el sistema antes de desvincular hardware."})
    if membership.unlinked_at is not None:
        raise ValidationError({"membership": "La asociación ya fue desvinculada."})
    membership.unlinked_at = timezone.now()
    membership.unlinked_by = user
    membership.save(update_fields=["unlinked_at", "unlinked_by"])
    return membership
