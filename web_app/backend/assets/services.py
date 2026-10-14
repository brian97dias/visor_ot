from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError as APIValidationError

from .models import Asset, Hardware


def save_validated(instance):
    try:
        instance.full_clean()
    except DjangoValidationError as error:
        details = (
            error.message_dict
            if hasattr(error, "message_dict")
            else {"non_field_errors": error.messages}
        )
        raise APIValidationError(details) from error
    instance.save()


@transaction.atomic
def register_hardware_asset(*, data, user):
    values = data.copy()
    hardware_values = values.pop("hardware")

    asset = Asset(
        **values,
        created_by=user,
        updated_by=user,
    )
    save_validated(asset)

    hardware = Hardware(asset=asset, **hardware_values)
    save_validated(hardware)
    return asset


@transaction.atomic
def update_hardware_asset(*, asset, data, user):
    values = data.copy()
    hardware_values = values.pop("hardware", None)

    for field, value in values.items():
        setattr(asset, field, value)
    asset.updated_by = user
    save_validated(asset)

    if hardware_values is not None:
        hardware = asset.hardware
        for field, value in hardware_values.items():
            setattr(hardware, field, value)
        save_validated(hardware)

    return asset

@transaction.atomic
def change_inventory_status(*, asset, new_status, user):
    # Bloquea la fila para que dos solicitudes concurrentes no cambien
    # simultáneamente el estado del mismo activo.
    asset = Asset.objects.select_for_update().get(pk=asset.pk)

    if asset.inventory_status == new_status:
        action = "archivado" if new_status == Asset.InventoryStatus.ARCHIVED else "en inventario"
        raise APIValidationError({
            "inventory_status": f"El activo ya está {action}."
        })

    if new_status == Asset.InventoryStatus.ARCHIVED:
        asset.inventory_status = Asset.InventoryStatus.ARCHIVED
        asset.archived_at = timezone.now()
        asset.archived_by = user
    elif new_status == Asset.InventoryStatus.ACTIVE:
        asset.inventory_status = Asset.InventoryStatus.ACTIVE
        asset.archived_at = None
        asset.archived_by = None
    else:
        raise APIValidationError({"inventory_status": "Estado no permitido."})

    asset.updated_by = user
    asset.save(update_fields=[
        "inventory_status",
        "archived_at",
        "archived_by",
        "updated_by",
        "updated_at",
    ])
    return asset
