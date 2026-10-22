"""Auditable CPE-ID verification using the existing worker and decision engine.

Never creates AssetCpe or AssetCpeDecision. Official UUID evidence remains
separate from automatic discovery runs and is valid only for its asset identity.
"""
from uuid import UUID

from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import NotFound, ValidationError

from assets.models import Asset
from vulnerabilities.models import CpeSearchRun, AssetCpe
from .candidate_matching import normalize_candidate, matches_vendor, _cpe_part
from .identity import fingerprint, hardware_identity, software_identity, SOFTWARE_CPE_PARTS
from .nvd_client import fetch_page, NvdError


EXTERNAL_CPE_TRIGGER = "EXTERNAL_CPE"  # 12 chars, fits existing trigger column


def _identity(asset):
    if asset.inventory_status != Asset.InventoryStatus.ACTIVE:
        raise ValidationError({"asset": "No se verifica CPE para activos archivados."})
    try:
        return (software_identity(asset) if asset.asset_type == Asset.AssetType.SOFTWARE
                else hardware_identity(asset))
    except (ValueError, AttributeError) as error:
        raise ValidationError({"asset": str(error)}) from error


@transaction.atomic
def enqueue_external_cpe(asset_id, actor, cpe_name_id):
    """Persist the request without making HTTP calls; reuse identical pending jobs."""
    try:
        identifier = str(UUID(str(cpe_name_id)))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValidationError({"cpe_name_id": "Debe ser un UUID de NVD válido."}) from error
    try:
        asset = Asset.objects.select_for_update().get(pk=asset_id)
    except Asset.DoesNotExist as error:
        raise NotFound("El activo no existe.") from error
    identity = _identity(asset)
    digest = fingerprint(identity)
    existing = CpeSearchRun.objects.filter(
        asset=asset, trigger=EXTERNAL_CPE_TRIGGER, identity_fingerprint=digest,
        status__in=(CpeSearchRun.Status.QUEUED, CpeSearchRun.Status.RUNNING),
        queries__0__parameter=identifier,
    ).first()
    if existing:
        return existing, True
    run = CpeSearchRun.objects.create(
        asset=asset, requested_by=actor, trigger=EXTERNAL_CPE_TRIGGER,
        scope=CpeSearchRun.Scope.SPECIFIC,
        identity_snapshot=identity, identity_fingerprint=digest,
        queries=[{"level": "EXTERNAL_CPE", "strategy": "cpeNameId",
                  "parameter": identifier, "status": "QUEUED"}],
        candidates=[],
    )
    return run, False


def _failure(run, query, status, message):
    query["status"] = status
    run.status = CpeSearchRun.Status.FAILED
    run.finished_at = timezone.now()
    run.error_message = message[:1000]
    run.queries = [query]
    run.candidates = []
    run.save(update_fields=["status", "finished_at", "error_message",
                            "queries", "candidates"])
    return run


def _warning(candidate, identity):
    """Keep text discrepancies as warnings, not gates for a verified CPE ID."""
    warnings = []
    if not matches_vendor(_cpe_part(candidate["cpe_name"], 3), identity):
        warnings.append("El fabricante NVD no coincide textualmente con el inventario.")
    if candidate.get("match_level") in ("POSSIBLE_INCOMPATIBILITY", "RELATED",
                                         "EXPLORATORY", "SOFTWARE_BRANCH",
                                         "SOFTWARE_PRODUCT", "NEEDS_INFO", "FAMILY"):
        warnings.append("La denominación de producto/modelo o su versión requiere revisión técnica.")
    if candidate["deprecated"]:
        warnings.append("NVD marca este CPE como obsoleto (deprecated).")
    return warnings


def execute_external_cpe(run, pacer, fetcher=fetch_page):
    """Process exactly one verified UUID using the worker's NVD pacing/lock."""
    if run.status != CpeSearchRun.Status.QUEUED or run.trigger != EXTERNAL_CPE_TRIGGER:
        return run
    query = dict((run.queries or [{}])[0])
    identifier = query.get("parameter")
    try:
        expected_id = UUID(str(identifier))
    except (ValueError, TypeError, AttributeError):
        return _failure(run, query, "INVALID_UUID", "La solicitud almacenada contiene un UUID inválido.")
    run.status = CpeSearchRun.Status.RUNNING
    run.started_at = timezone.now()
    run.error_message = ""
    query["status"] = "RUNNING"
    run.queries = [query]
    run.save(update_fields=["status", "started_at", "error_message", "queries"])
    try:
        data = fetcher("cpeNameId", str(expected_id), 0, pacer, results_per_page=1)
    except (NvdError, TimeoutError, ConnectionError, OSError) as error:
        return _failure(run, query, "ERROR",
                        "No fue posible verificar el CPE en NVD: " + str(error))

    if (not isinstance(data, dict) or not isinstance(data.get("products"), list)
            or not isinstance(data.get("totalResults"), int)
            or isinstance(data["totalResults"], bool)):
        return _failure(run, query, "INVALID_RESPONSE",
                        "La respuesta NVD no tiene la estructura esperada.")

    products = data["products"]
    count = data["totalResults"]
    if count == 0 and not products:
        query["status"] = "NOT_FOUND"
        run.candidates = []
    elif count != 1 or len(products) != 1:
        return _failure(run, query, "INVALID_RESPONSE",
                        "NVD devolvió una respuesta ambigua para el identificador solicitado.")
    else:
        record = products[0]
        cpe = record.get("cpe") if isinstance(record, dict) else None
        if not isinstance(cpe, dict):
            return _failure(run, query, "INVALID_RESPONSE", "NVD no devolvió un CPE válido.")
        try:
            returned_id = UUID(str(cpe["cpeNameId"]))
        except (KeyError, ValueError, TypeError, AttributeError):
            return _failure(run, query, "INVALID_RESPONSE", "El identificador NVD es inválido.")
        name = cpe.get("cpeName")
        if returned_id != expected_id or not isinstance(name, str) or len(name.split(":")) != 13 or not name.startswith("cpe:2.3:"):
            return _failure(run, query, "INVALID_RESPONSE",
                            "NVD no devolvió exactamente el CPE oficial solicitado.")
        identity = run.identity_snapshot
        expected_part = (SOFTWARE_CPE_PARTS.get(identity.get("software_type"))
                         if identity.get("asset_type") == "SOFTWARE" else "h")
        if _cpe_part(name, 2) != expected_part:
            query["status"] = "INCOMPATIBLE_PART"
            query["warning"] = "La parte CPE no corresponde al tipo del activo."
            run.candidates = []
        else:
            try:
                candidate = normalize_candidate(record, identity, "cpeNameId")
            except (ValueError, TypeError, KeyError) as error:
                return _failure(run, query, "INVALID_RESPONSE", str(error))
            if not candidate:
                return _failure(run, query, "INVALID_RESPONSE", "El registro CPE carece de datos oficiales válidos.")
            candidate["verification_origin"] = EXTERNAL_CPE_TRIGGER
            candidate["warnings"] = _warning(candidate, identity)
            # This never upgrades the text classification into a human decision.
            run.candidates = [candidate]
            query["status"] = "VERIFIED"
            query["cpe_name_id"] = str(expected_id)

    run.status = CpeSearchRun.Status.COMPLETED
    run.finished_at = timezone.now()
    run.queries = [query]
    run.save(update_fields=["status", "finished_at", "queries", "candidates"])
    return run


def serialize_external_cpe(run):
    """One stored result for polling/review, including any existing association."""
    if run.trigger != EXTERNAL_CPE_TRIGGER:
        raise ValueError("Este trabajo no es una verificación CPE por ID.")
    candidate = run.candidates[0] if run.candidates else None
    assoc = None
    if candidate:
        current = AssetCpe.objects.select_related("cpe").filter(
            asset_id=run.asset_id,
            cpe__cpe_name_id=candidate["cpe_name_id"],
        ).first()
        if current:
            assoc = {"id": current.pk, "status": current.validation_status}
    from .cpe_search import serialize_run
    result = serialize_run(run)
    result["verification_status"] = (
        run.queries[0].get("status") if run.queries else "QUEUED"
    )
    result["existing_association"] = assoc
    return result
