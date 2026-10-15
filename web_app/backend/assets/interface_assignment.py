"""Explicit assignments, distinct from passive interface discovery."""

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .models import Asset, Hardware, NetworkInterface


def save_interface(instance):
    try:
        instance.save()
    except DjangoValidationError as error:
        details = error.message_dict if hasattr(error, "message_dict") else {
            "non_field_errors": error.messages
        }
        raise ValidationError(details) from error
    except IntegrityError as error:
        raise ValidationError({"mac": "MAC duplicada o restricción no satisfecha."}) from error


def validate_hardware_asset(asset):
    if asset.asset_type != Asset.AssetType.HARDWARE:
        raise ValidationError({"asset_id": "El activo debe ser hardware."})
    if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
        raise ValidationError({"asset_id": "No es posible asociar un activo archivado."})


@transaction.atomic
def identify_interface(*, interface_id, asset_id, user):
    asset = get_object_or_404(Asset.objects.select_for_update(), pk=asset_id)
    validate_hardware_asset(asset)
    hardware = get_object_or_404(Hardware, pk=asset.pk)
    interface = get_object_or_404(
        NetworkInterface.objects.select_for_update(), pk=interface_id
    )
    if interface.hardware_id is not None:
        if interface.hardware_id == hardware.pk:
            raise ValidationError({"interface_id": "Ya está asociada a este hardware."})
        raise ValidationError({
            "interface_id": "Ya pertenece a otro hardware; desvincula antes de reasignar."
        })
    interface.hardware = hardware
    interface.identified_by = user
    interface.identified_at = timezone.now()
    save_interface(interface)
    return interface


@transaction.atomic
def unlink_interface(*, interface_id):
    interface = get_object_or_404(
        NetworkInterface.objects.select_for_update(), pk=interface_id
    )
    if interface.hardware_id is None:
        raise ValidationError({"interface_id": "La interfaz no está asociada."})
    interface.hardware = None
    interface.identified_by = None
    interface.identified_at = None
    save_interface(interface)
    return interface


@transaction.atomic
def create_identified_interface(*, hardware, mac, declared_ip, user):
    validate_hardware_asset(hardware.asset)
    interface = NetworkInterface(
        mac=mac, declared_ip=declared_ip,
        hardware=hardware, created_by=user,
        identified_by=user, identified_at=timezone.now(),
    )
    save_interface(interface)
    return interface
