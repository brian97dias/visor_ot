"""Transactional services for software inventory and installation history.

This increment intentionally exposes no API endpoints. Future serializers and
views must call these functions rather than editing the relations directly.
"""

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied, ValidationError

from users.models import User

from .models import Asset, Hardware, Software, SoftwareInstallation, SoftwareCorrection
from .software_identity_snapshot import snapshot_software
from .software_validation import normalize_software_fields, software_identity


_ASSET_FIELDS = {
    "name", "description", "criticality", "impact",
    "replacement_cost", "replacement_currency",
}
_SOFTWARE_FIELDS = {
    "software_type", "manufacturer", "product", "version",
}
_VARIANT_FIELDS = {
    "software_type", "manufacturer", "product", "version",
}


def _check_role(user, *, associate=False, criticality=False):
    role = getattr(user, "role", None)
    if associate:
        if role not in (User.Role.ADMIN, User.Role.OPERATOR):
            raise PermissionDenied("Solo administrador u operador gestionan asociaciones.")
    elif role not in (User.Role.ADMIN, User.Role.OPERATOR, User.Role.ANALYST):
        raise PermissionDenied("No tienes permiso para modificar software.")
    if criticality and role == User.Role.ANALYST:
        raise PermissionDenied("El analista no puede modificar la criticidad.")


def _validate_keys(values, allowed, *, location):
    unexpected = set(values) - allowed
    if unexpected:
        raise ValidationError({
            location: f"Campos no permitidos: {', '.join(sorted(unexpected))}."
        })


def _save_validated(instance):
    try:
        instance.full_clean()
    except DjangoValidationError as error:
        detail = error.message_dict if hasattr(error, "message_dict") else {
            "non_field_errors": error.messages,
        }
        raise ValidationError(detail) from error

    try:
        # A savepoint lets us translate uniqueness failures without leaving
        # the caller's transaction in a broken state.
        with transaction.atomic():
            instance.save()
    except IntegrityError as error:
        raise ValidationError({
            "non_field_errors": "Conflicto de integridad o registro duplicado."
        }) from error
    return instance


def _check_variant_available(values, *, exclude_id=None):
    identity = software_identity(
        values.get("manufacturer"), values.get("product"), values.get("version")
    )
    if identity is None:
        return

    manufacturer, product, version = identity
    query = Software.objects.filter(
        manufacturer__iexact=manufacturer,
        product__iexact=product,
        version__iexact=version,
    )
    if exclude_id is not None:
        query = query.exclude(pk=exclude_id)
    if query.exists():
        raise ValidationError({
            "software": "Esta variante ya existe en el inventario; reutiliza el registro existente."
        })


def _validate_software_data(values):
    _validate_keys(values, _SOFTWARE_FIELDS, location="software")
    required = ("software_type", "product")
    missing = [field for field in required if not values.get(field)]
    if missing:
        raise ValidationError({
            "software": f"Faltan datos obligatorios: {', '.join(missing)}."
        })


def _require_active(asset, label):
    if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
        raise ValidationError({
            label: "No se puede asociar un activo archivado."
        })


@transaction.atomic
def register_software_asset(*, data, user):
    """Create a reusable Software variant, optionally without installations."""
    _check_role(user, associate=True)

    values = data.copy()
    software_values = values.pop("software", None)
    if not isinstance(software_values, dict):
        raise ValidationError({"software": "Indica los datos técnicos del software."})
    if values.pop("asset_type", Asset.AssetType.SOFTWARE) != Asset.AssetType.SOFTWARE:
        raise ValidationError({"asset_type": "El activo debe ser SOFTWARE."})

    _validate_keys(values, _ASSET_FIELDS, location="asset")
    _validate_software_data(software_values)

    manufacturer, product, version = normalize_software_fields(
        software_values.get("manufacturer"),
        software_values.get("product"),
        software_values.get("version"),
    )
    software_values = {
        **software_values, "manufacturer": manufacturer,
        "product": product, "version": version,
    }
    _check_variant_available(software_values)

    asset = Asset(
        asset_type=Asset.AssetType.SOFTWARE,
        created_by=user, updated_by=user, **values,
    )
    _save_validated(asset)

    software = Software(asset=asset, **software_values)
    _save_validated(software)
    return asset


@transaction.atomic
def register_installed_software_asset(*, data, user):
    """Register software independently, optionally associating its first host atomically."""
    values = data.copy()
    hardware_asset_id = values.pop("hardware_asset_id", None)
    if hardware_asset_id is not None and (
        not isinstance(hardware_asset_id, int) or hardware_asset_id < 1
    ):
        raise ValidationError({"hardware_asset_id": "Selecciona un hardware válido."})
    asset = register_software_asset(data=values, user=user)
    if hardware_asset_id is not None:
        associate_software(
            software_id=asset.pk, hardware_asset_id=hardware_asset_id, user=user
        )
    return asset


@transaction.atomic
def update_software_asset(*, asset_id, data, user):
    """Change permitted details; never rewrite an installed variant's history."""
    _check_role(user)

    values = data.copy()
    if "asset_type" in values:
        raise ValidationError({"asset_type": "El tipo del activo no se puede modificar."})
    software_values = values.pop("software", None)
    correction_reason = values.pop("correction_reason", "")
    confirm_shared_correction = values.pop("confirm_shared_correction", False)
    software_change_type = values.pop("software_change_type", "CORRECTION")
    if software_change_type not in ("CORRECTION", "UPGRADE"):
        raise ValidationError({"software_change_type": "Usa CORRECTION o UPGRADE."})
    _validate_keys(values, _ASSET_FIELDS, location="asset")
    if software_values is not None:
        if not isinstance(software_values, dict):
            raise ValidationError({"software": "Formato inválido."})
        _validate_keys(software_values, _SOFTWARE_FIELDS, location="software")

    if "criticality" in values:
        _check_role(user, criticality=True)

    asset = get_object_or_404(Asset.objects.select_for_update(), pk=asset_id)
    if asset.asset_type != Asset.AssetType.SOFTWARE:
        raise ValidationError({"asset_id": "No es un activo SOFTWARE."})
    software = get_object_or_404(Software.objects.select_for_update(), pk=asset.pk)

    if software_values:
        proposed = {
            field: software_values.get(field, getattr(software, field))
            for field in _SOFTWARE_FIELDS
        }
        manufacturer, product, version = normalize_software_fields(
            proposed["manufacturer"], proposed["product"], proposed["version"]
        )
        proposed.update(
            manufacturer=manufacturer, product=product, version=version
        )
        changed = any(
            proposed[field] != getattr(software, field)
            for field in _VARIANT_FIELDS
        )
        if changed:
            if software_change_type == "UPGRADE":
                raise ValidationError({
                    "software_change_type": (
                        "Una actualización real debe registrar otra variante "
                        "y trasladar la instalación correspondiente."
                    ),
                })
            if not isinstance(correction_reason, str) or not correction_reason.strip():
                raise ValidationError({
                    "correction_reason": "Explica el motivo de la corrección técnica."
                })
            if len(correction_reason.strip()) > 1000:
                raise ValidationError({"correction_reason": "Máximo 1000 caracteres."})
            active_count = SoftwareInstallation.objects.filter(
                software=software, unlinked_at__isnull=True
            ).count()
            if active_count > 1 and confirm_shared_correction is not True:
                raise ValidationError({
                    "confirm_shared_correction": (
                        f"Esta variante está asociada a {active_count} hardware activos. "
                        "Confirma que la corrección corresponde al producto compartido."
                    )
                })
            _check_variant_available(proposed, exclude_id=asset.pk)
            identity_before = snapshot_software(software, source="before_correction")
            for field, value in proposed.items():
                setattr(software, field, value)
            correction = SoftwareCorrection(
                software=software,
                changed_by=user,
                reason=correction_reason.strip(),
                identity_before=identity_before,
                identity_after=snapshot_software(software, source="after_correction"),
                affected_active_installations=active_count,
            )
        else:
            correction = None

    for field, value in values.items():
        setattr(asset, field, value)
    asset.updated_by = user
    _save_validated(asset)

    if software_values:
        _save_validated(software)
        if correction is not None:
            _save_validated(correction)
    return asset


@transaction.atomic
def associate_software(*, software_id, hardware_asset_id, user):
    """Create one active installation. Lock both parent assets against races."""
    _check_role(user, associate=True)

    parents = {
        asset.pk: asset
        for asset in Asset.objects.select_for_update()
        .filter(pk__in=(software_id, hardware_asset_id))
        .order_by("pk")
    }
    software_asset = parents.get(software_id)
    hardware_asset = parents.get(hardware_asset_id)
    if software_asset is None or software_asset.asset_type != Asset.AssetType.SOFTWARE:
        raise ValidationError({"software_id": "El software no existe."})
    if hardware_asset is None or hardware_asset.asset_type != Asset.AssetType.HARDWARE:
        raise ValidationError({"hardware_asset_id": "El hardware no existe."})

    _require_active(software_asset, "software_id")
    _require_active(hardware_asset, "hardware_asset_id")

    software = get_object_or_404(Software, pk=software_id)
    hardware = get_object_or_404(Hardware, pk=hardware_asset_id)

    if SoftwareInstallation.objects.filter(
        software=software, hardware=hardware, unlinked_at__isnull=True
    ).exists():
        raise ValidationError({
            "software_id": "Este software ya está asociado al hardware."
        })

    return _save_validated(SoftwareInstallation(
        software=software, hardware=hardware, registered_by=user,
        identity_snapshot=snapshot_software(software),
    ))


@transaction.atomic
def unlink_software(*, installation_id, user):
    """Deactivate an association but retain both assets and the audit record."""
    _check_role(user, associate=True)

    installation = get_object_or_404(
        SoftwareInstallation.objects.select_for_update(),
        pk=installation_id,
    )
    if not installation.is_active:
        raise ValidationError({
            "installation_id": "La instalación ya está desvinculada."
        })

    installation.unlinked_at = timezone.now()
    installation.unlinked_by = user
    _save_validated(installation)
    return installation
