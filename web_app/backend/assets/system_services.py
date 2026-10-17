"""Transactional operations for operational systems, including audit history."""
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .models import OTSystem


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
        raise ValidationError({"status": "Restaura el sistema antes de editarlo."})
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
        system.archived_at = timezone.now()
        system.archived_by = user
    else:
        system.archived_at = None
        system.archived_by = None
    system.status = new_status
    system.updated_by = user
    return save_system(system)
