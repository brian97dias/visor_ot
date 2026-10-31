from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError as APIValidationError

from .models import Asset, Hardware
from .interface_assignment import identify_interface, create_identified_interface
from .system_membership_services import associate_hardware_to_system
from .inventory_integrity import current_active_system_links, has_valid_criticality


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
    assignment = values.pop("interface_assignment", None)
    system_ids = values.pop("system_ids", [])
    # Public registration and XLSX import pass AssetCreateSerializer before
    # reaching this service. Legacy internal fixtures may still construct
    # incomplete records; the read-only integrity audit identifies those.

    asset = Asset(
        **values,
        created_by=user,
        updated_by=user,
    )
    save_validated(asset)

    hardware = Hardware(asset=asset, **hardware_values)
    save_validated(hardware)
    if assignment:
        if assignment["mode"] == "EXISTING":
            identify_interface(
                interface_id=assignment["interface_id"],
                asset_id=asset.pk, user=user,
            )
        else:
            create_identified_interface(
                hardware=hardware,
                mac=assignment.get("mac"),
                declared_ip=assignment.get("declared_ip"),
                user=user,
            )
    for system_id in system_ids:
        # Registration and all optional memberships share a transaction.
        from .models import OTSystem
        if not OTSystem.objects.filter(pk=system_id).exists():
            raise APIValidationError({"system_ids": "Uno de los sistemas seleccionados no existe."})
        associate_hardware_to_system(
            system_id=system_id, hardware_asset_id=asset.pk, user=user,
        )
    return asset


@transaction.atomic
def update_hardware_asset(*, asset, data, user):
    values = data.copy()
    hardware_values = values.pop("hardware", None)

    if "criticality" in values and not has_valid_criticality(values["criticality"]):
        raise APIValidationError({"criticality": "Selecciona Baja, Media o Alta."})
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
def change_inventory_status(*, asset, new_status, user, system_ids=None):
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
        if asset.asset_type == Asset.AssetType.HARDWARE:
            if system_ids is not None and (
                not isinstance(system_ids, list)
                or any(type(pk) is not int or pk < 1 for pk in system_ids)
                or len(system_ids) != len(set(system_ids))
            ):
                raise APIValidationError({
                    "system_ids": "Selecciona identificadores de sistemas OT válidos y sin repetir."
                })
            if not current_active_system_links(asset.pk).exists():
                if not system_ids:
                    raise APIValidationError({
                        "system_ids": "Para restaurar, selecciona un sistema OT activo."
                    })
                from .models import OTSystem
                valid = OTSystem.objects.filter(
                    pk__in=system_ids, status=OTSystem.Status.ACTIVE
                ).count()
                if valid != len(system_ids):
                    raise APIValidationError({
                        "system_ids": "Los sistemas seleccionados deben estar activos."
                    })
            device = asset.hardware
            if any(not (getattr(device, field) or "").strip()
                   for field in ("manufacturer", "model", "role")):
                raise APIValidationError({
                    "hardware": "Completa fabricante, modelo y rol antes de restaurar."
                })
        if not has_valid_criticality(asset.criticality):
            raise APIValidationError({
                "criticality": "Define criticidad Baja, Media o Alta antes de restaurar."
            })
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
    if new_status == Asset.InventoryStatus.ACTIVE and (
        asset.asset_type == Asset.AssetType.HARDWARE and system_ids
    ):
        for system_id in system_ids:
            # Validation and membership creation share the same transaction.
            if not current_active_system_links(asset.pk).filter(
                system_id=system_id
            ).exists():
                associate_hardware_to_system(
                    system_id=system_id, hardware_asset_id=asset.pk, user=user,
                )
    return asset
