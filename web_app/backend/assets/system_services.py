"""Transactional operations for operational systems, including audit history."""
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .models import OTSystem, Asset, SystemMembership
from .inventory_integrity import has_valid_criticality


def save_system(instance):
    try:
        instance.full_clean()
    except DjangoValidationError as error:
        raise ValidationError(
            error.message_dict if hasattr(error, "message_dict")
            else {"non_field_errors": error.messages}
        ) from error
    instance.save()
    return instance


@transaction.atomic
def register_system(*, data, user):
    system = OTSystem(**data, created_by=user, updated_by=user)
    return save_system(system)


@transaction.atomic
def update_system(*, system_id, data, user):
    system = OTSystem.objects.select_for_update().get(pk=system_id)
    if system.status != OTSystem.Status.ACTIVE:
        # The existing form sends the complete payload. Permit only a
        # criticality correction on an archived legacy record: other values
        # must remain identical, so restoration is not made impossible.
        changed = {
            key for key, value in data.items()
            if getattr(system, key) != value
        }
        if changed - {"criticality"}:
            raise ValidationError({
                "status": "Para editar otros datos de un sistema archivado, "
                          "restáuralo primero."
            })
        if not has_valid_criticality(data.get("criticality", system.criticality)):
            raise ValidationError({
                "criticality": "Registra criticidad Baja, Media o Alta."
            })
    for field, value in data.items():
        setattr(system, field, value)
    system.updated_by = user
    return save_system(system)


@transaction.atomic
def change_system_status(*, system_id, new_status, user):
    system = OTSystem.objects.select_for_update().get(pk=system_id)
    if new_status not in (OTSystem.Status.ACTIVE, OTSystem.Status.ARCHIVED):
        raise ValidationError({"status": "Estado no permitido."})
    if system.status == new_status:
        raise ValidationError({"status": "El sistema ya tiene ese estado."})
    if new_status == OTSystem.Status.ARCHIVED:
        # Keep the active Hardware->System invariant. Lock the involved
        # hardware rows so concurrent membership changes serialize.
        hardware_ids = sorted(set(SystemMembership.objects.filter(
            system=system, unlinked_at__isnull=True,
            hardware__asset__inventory_status=Asset.InventoryStatus.ACTIVE,
        ).values_list("hardware_id", flat=True)))
        list(Asset.objects.select_for_update().filter(pk__in=hardware_ids).order_by("pk"))
        stranded = [hardware_id for hardware_id in hardware_ids
            if not SystemMembership.objects.filter(
                hardware_id=hardware_id, unlinked_at__isnull=True,
                system__status=OTSystem.Status.ACTIVE,
            ).exclude(system_id=system.pk).exists()]
        if stranded:
            raise ValidationError({
                "system": "No puedes archivar este sistema: dejaría hardware "
                          "activo sin sistema OT. Hardware: "
                          + ", ".join(map(str, stranded))
            })
        system.archived_at = timezone.now()
        system.archived_by = user
    else:
        if not has_valid_criticality(system.criticality):
            raise ValidationError({
                "criticality": "Define criticidad Baja, Media o Alta antes de restaurar."
            })
        system.archived_at = None
        system.archived_by = None
    system.status = new_status
    system.updated_by = user
    return save_system(system)
