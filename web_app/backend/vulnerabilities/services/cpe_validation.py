"""Explicit CPE review, consistency locks and immutable decision evidence."""
from datetime import timezone as dt_timezone
from uuid import UUID

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import APIException, ValidationError, NotFound

from assets.models import Asset
from vulnerabilities.models import Cpe, CpeSearchRun, AssetCpe, AssetCpeDecision
from .candidate_matching import hardware_candidates
from .identity import fingerprint, hardware_identity


class ReviewConflict(APIException):
    status_code = 409
    default_detail = "La asociación CPE ya existe. Utiliza la operación de revisión."
    default_code = "conflict"


def _date(value):
    if not value or not isinstance(value, str):
        return None
    result = parse_datetime(value)
    if result is not None and timezone.is_naive(result):
        result = result.replace(tzinfo=dt_timezone.utc)
    return result


def current_identity(asset):
    if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
        raise ValidationError({"asset": "No se validan CPE de activos archivados."})
    if asset.asset_type != Asset.AssetType.HARDWARE:
        raise ValidationError({"asset": "La validación de software corresponde a la fase 4."})
    return fingerprint(hardware_identity(asset))


def select_evidence(asset, run_id, cpe_name_id):
    try:
        run = CpeSearchRun.objects.get(pk=run_id, asset=asset)
    except CpeSearchRun.DoesNotExist as error:
        raise NotFound("No existe esa búsqueda para el activo.") from error
    if run.status != CpeSearchRun.Status.COMPLETED:
        raise ValidationError({"run_id": "La búsqueda debe finalizar antes de validar candidatos."})
    current = current_identity(asset)
    if run.identity_fingerprint != current:
        raise ValidationError({
            "run_id": "La identidad técnica cambió; ejecuta otra búsqueda antes de validar."
        })
    candidate = next((
        row for row in hardware_candidates(run.candidates)
        if str(row.get("cpe_name_id", "")).lower() == str(cpe_name_id).lower()
    ), None)
    if candidate is None:
        raise ValidationError({"cpe_name_id": "Este CPE no aparece en la búsqueda del activo."})
    if not candidate.get("cpe_name"):
        raise ValidationError({"cpe_name_id": "El candidato no tiene un nombre CPE válido."})
    try:
        UUID(str(candidate["cpe_name_id"]))
    except (ValueError, TypeError, KeyError) as error:
        raise ValidationError({"cpe_name_id": "El identificador oficial NVD es inválido."}) from error
    return run, current, candidate


def get_or_update_catalogue(candidate):
    cpe_id = UUID(str(candidate["cpe_name_id"]))
    values = {
        "cpe_name": candidate["cpe_name"],
        "title": (candidate.get("title") or candidate["cpe_name"])[:400],
        "deprecated": bool(candidate.get("deprecated", False)),
    }
    created_at = _date(candidate.get("nvd_created_at"))
    modified_at = _date(candidate.get("nvd_modified_at"))
    if created_at:
        values["nvd_created_at"] = created_at
    if modified_at:
        values["nvd_modified_at"] = modified_at
    catalogue, created = Cpe.objects.get_or_create(cpe_name_id=cpe_id, defaults=values)
    if not created:
        for key, value in values.items():
            setattr(catalogue, key, value)
        catalogue.save(update_fields=[*values, "fetched_at"])
    return catalogue


@transaction.atomic
def decide(asset_id, user, data, association_id=None):
    # Lock the asset only, never its nullable reverse OneToOne hardware JOIN.
    # Serializes concurrent CPE decisions and prevents duplicate audit entries.
    try:
        asset = Asset.objects.select_for_update().get(pk=asset_id)
    except Asset.DoesNotExist as error:
        raise NotFound("Activo inexistente.") from error

    status = data["status"]
    reason = data.get("justification", "").strip()
    association = None
    if association_id is not None:
        try:
            association = AssetCpe.objects.select_related("cpe", "source_run").get(
                pk=association_id, asset=asset
            )
        except AssetCpe.DoesNotExist as error:
            raise NotFound("Asociación CPE inexistente para este activo.") from error
        requested_id = data.get("cpe_name_id")
        if requested_id is not None and str(requested_id) != str(association.cpe.cpe_name_id):
            raise ValidationError({"cpe_name_id": "No se puede reemplazar el CPE de una asociación."})
    elif status == AssetCpe.Validation.REOPENED:
        raise ValidationError({"status": "La reapertura requiere una asociación existente."})

    if status == AssetCpe.Validation.REOPENED:
        # Re-opening withdraws a prior judgement; it does NOT certify a new
        # technical match, so a completed/current NVD run is not required.
        identity = current_identity(asset)
        if association.validation_status == status:
            raise ReviewConflict("Esta asociación ya tiene la revisión reabierta.")
        run = association.source_run  # Preserve original evidence provenance.
        candidate = None
    else:
        requested_id = association.cpe.cpe_name_id if association else data["cpe_name_id"]
        run, identity, candidate = select_evidence(asset, data["run_id"], requested_id)
        if association is not None and association.validation_status == status:
            # Revalidation with a genuinely newer run or changed identity is
            # meaningful. Otherwise a repeated button click must not pollute
            # the append-only decision history.
            if (association.source_run_id == run.pk
                    and association.validated_identity_fingerprint == identity):
                raise ReviewConflict("La asociación ya tiene ese estado y no hay evidencia nueva.")

    if association is None:
        catalogue = get_or_update_catalogue(candidate)
        if AssetCpe.objects.filter(asset=asset, cpe=catalogue).exists():
            raise ReviewConflict()
        association = AssetCpe.objects.create(
            asset=asset, cpe=catalogue, source_run=run, validation_status=status,
            justification=reason, validated_by=user, validated_at=timezone.now(),
            validated_identity_fingerprint=identity
        )
        old_status = ""
    else:
        old_status = association.validation_status
        association.source_run = run
        association.validation_status = status
        association.justification = reason
        association.validated_by = user
        association.validated_at = timezone.now()
        association.validated_identity_fingerprint = identity
        association.save(update_fields=[
            "source_run", "validation_status", "justification", "validated_by",
            "validated_at", "validated_identity_fingerprint"
        ])

    AssetCpeDecision.objects.create(
        association=association, previous_status=old_status, new_status=status,
        justification=reason, source_run=run, actor=user,
        identity_fingerprint=identity
    )
    return association


def serialize_association(association, current_fingerprint):
    catalogue = association.cpe
    return {
        "id": association.pk,
        "cpe_name_id": str(catalogue.cpe_name_id),
        "cpe_name": catalogue.cpe_name,
        "title": catalogue.title,
        "deprecated": catalogue.deprecated,
        "validation_status": association.validation_status,
        "justification": association.justification,
        "validated_at": association.validated_at,
        "validated_by": association.validated_by.username if association.validated_by else None,
        "needs_review": association.validation_status != AssetCpe.Validation.REOPENED and association.validated_identity_fingerprint != current_fingerprint,
        "source_run_id": association.source_run_id,
        "history": [{
            "id": entry.pk,
            "previous_status": entry.previous_status,
            "new_status": entry.new_status,
            "justification": entry.justification,
            "actor": entry.actor.username if entry.actor else None,
            "created_at": entry.created_at,
            "source_run_id": entry.source_run_id,
        } for entry in association.decision_history.all()],
    }


def list_associations(asset):
    try:
        current = fingerprint(hardware_identity(asset))
    except (ValueError, AttributeError):
        current = ""
    associations = AssetCpe.objects.filter(asset=asset).select_related(
        "cpe", "validated_by", "source_run"
    ).prefetch_related("decision_history__actor")
    return [serialize_association(item, current) for item in associations]
