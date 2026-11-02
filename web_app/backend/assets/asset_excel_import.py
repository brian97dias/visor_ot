"""Conservative two-sheet XLSX inventory import with stateless preview.

Identifiers are only those belonging to Visor OT. No MAC, IP, hardware/software
associations, archive/restore actions or invented identity keys are imported.
The confirm endpoint re-parses the workbook and compares a signed fingerprint
against the current database before applying any writes atomically.
"""
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from io import BytesIO
from zipfile import ZipFile, BadZipFile
import json

from django.core import signing
from django.db import transaction
from rest_framework.exceptions import ValidationError

from .asset_excel import HARDWARE_COLUMNS, SOFTWARE_COLUMNS
from .models import Asset, AssetImportBatch
from .serializers import AssetCreateSerializer, AssetUpdateSerializer
from .services import register_hardware_asset, update_hardware_asset
from .software_services import register_installed_software_asset, update_software_asset
from .software_validation import software_identity

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ROWS = 500
PREVIEW_SALT = "assets.excel.import.v1"
BASE = ("nombre_activo", "descripcion", "criticidad",
        "impacto_indisponibilidad", "costo_reposicion", "moneda")
TECH = {
    "Hardware": ("fabricante", "modelo", "rol", "numero_serie", "ubicacion_fisica", "modelo_cpu"),
    "Software": ("tipo_software", "fabricante", "producto", "version"),
}
GENERAL_MAP = {
    "nombre_activo": "name",
    "descripcion": "description",
    "criticidad": "criticality",
    "impacto_indisponibilidad": "impact",
    "costo_reposicion": "replacement_cost",
    "moneda": "replacement_currency",
}
TECH_MAP = {
    "Hardware": {
        "fabricante": "manufacturer", "modelo": "model", "rol": "role",
        "numero_serie": "serial_number", "ubicacion_fisica": "physical_location",
        "modelo_cpu": "cpu_model",
    },
    "Software": {
        "tipo_software": "software_type", "fabricante": "manufacturer",
        "producto": "product", "version": "version",
    },
}
COLUMNS = {"Hardware": HARDWARE_COLUMNS, "Software": SOFTWARE_COLUMNS}


def _as_text(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        raise ValueError("Los valores booleanos no son válidos.")
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _value(key, value):
    if value is None or value == "":
        return None
    if key == "numero_serie" and isinstance(value, (int, float, Decimal)):
        # Excel numeric cells preserve at most ~15 significant digits;
        # 16+ digit serials must be entered as text to avoid false identity.
        if len(str(abs(int(value)))) > 15:
            raise ValueError(
                "Serie numérica de más de 15 dígitos: usa formato Texto en Excel."
            )
    if key == "id_visor_ot":
        if isinstance(value, bool):
            raise ValueError("El ID debe ser un número entero.")
        try:
            parsed = Decimal(str(value))
            if parsed != parsed.to_integral_value() or parsed < 1:
                raise ValueError()
            return int(parsed)
        except (ValueError, InvalidOperation):
            raise ValueError("El ID de Visor OT debe ser entero y positivo.")
    if key == "costo_reposicion":
        try:
            number = Decimal(str(value).strip())
        except (ValueError, InvalidOperation, TypeError):
            raise ValueError("Costo de reposición inválido.")
        if not number.is_finite() or number < 0 or number.as_tuple().exponent < -2:
            raise ValueError("El costo debe ser positivo y tener máximo dos decimales.")
        return str(number)
    return _as_text(value)


def _physical_rows(sheet, workbook, width):
    """Yield only rows that exist in worksheet XML, without filling gaps.

    openpyxl's public read-only iter_rows() synthesizes every missing row
    between nonconsecutive row indices. Some LibreOffice-generated files
    contain a few empty <row> records at row 1,048,576, which would make
    iter_rows() generate a million empty rows. The underlying streaming
    parser instead preserves physical row numbers and ignores these gaps.
    Pin openpyxl to major version 3; covered by regression tests.
    """
    from openpyxl.worksheet._reader import WorkSheetParser

    with sheet._get_source() as source:
        parser = WorkSheetParser(
            source,
            sheet._shared_strings,
            data_only=workbook.data_only,
            epoch=workbook.epoch,
            date_formats=workbook._date_formats,
            timedelta_formats=workbook._timedelta_formats,
        )
        for number, cells in parser.parse():
            yield number, sheet._get_row(cells, 1, width, values_only=True)


def parse_workbook(file_bytes):
    if len(file_bytes) > MAX_FILE_BYTES:
        raise ValidationError({"file": "El Excel supera el límite de 2 MB."})
    if not file_bytes.startswith(b"PK"):
        raise ValidationError({"file": "Selecciona un archivo XLSX válido."})
    try:
        with ZipFile(BytesIO(file_bytes)) as archive:
            # Bound decompression before openpyxl parses shared strings/XML.
            if sum(item.file_size for item in archive.infolist()) > 20 * 1024 * 1024:
                raise ValidationError({"file": "El Excel descomprimido supera 20 MB."})
    except (BadZipFile, OSError) as error:
        raise ValidationError({"file": "El archivo no es un XLSX válido."}) from error
    try:
        from openpyxl import load_workbook
        workbook = load_workbook(BytesIO(file_bytes), read_only=True, data_only=False)
        try:
            if set(workbook.sheetnames) != set(COLUMNS):
                raise ValidationError({
                    "file": "El Excel debe contener únicamente las hojas Hardware y Software."
                })
            result = []
            for sheet_name in ("Hardware", "Software"):
                sheet = workbook[sheet_name]
                expected = [col[0] for col in COLUMNS[sheet_name]]
                # XLSX dimensions can include thousands of *formatted but
                # empty* rows/columns. max_row / max_column cannot be used as
                # the count of assets, nor as an indicator of extra data.
                #
                # The exporter puts headers on row 1. Earlier research
                # templates placed them on row 5; keep both interoperable.
                # Ignore decorative rows before the header and count only
                # rows that have at least one non-empty value afterwards.
                header_row = None
                sheet_count = 0
                for physical_count, (row_num, values) in enumerate(
                    _physical_rows(sheet, workbook, len(expected)), start=1
                ):
                    # Bound the number of physically encoded worksheet rows,
                    # not their Excel row numbers, which may be very large.
                    if physical_count > 20000:
                        raise ValidationError({
                            "file": (
                                f"{sheet_name}: demasiadas filas de formato. "
                                "Elimina el rango sobrante y vuelve a exportar."
                            )
                        })
                    if header_row is None:
                        header = [_as_text(value) for value in values]
                        # Older exports had no modelo_cpu column. Its blank
                        # trailing value remains None, so legacy books still import.
                        legacy_hw = (
                            sheet_name == "Hardware"
                            and header[:-1] == expected[:-1]
                            and header[-1] == ""
                        )
                        if header == expected or legacy_hw:
                            header_row = row_num
                        elif row_num >= 5:
                            raise ValidationError({
                                "file": (
                                    f"{sheet_name}: encabezados incorrectos. "
                                    "Se esperan en la fila 1 o 5."
                                )
                            })
                        continue

                    if all(value is None or str(value).strip() == "" for value in values):
                        continue
                    sheet_count += 1
                    if sheet_count > MAX_ROWS or len(result) >= MAX_ROWS:
                        raise ValidationError({
                            "file": f"{sheet_name}: máximo {MAX_ROWS} activos con datos."
                        })
                    row = {
                        "sheet": sheet_name, "row": row_num,
                        "key": f"{sheet_name}:{row_num}",
                        "data": {}, "errors": [],
                    }
                    for column, raw in zip(expected, values):
                        try:
                            if isinstance(raw, str) and raw.startswith("="):
                                raise ValueError("No se permiten fórmulas en los campos.")
                            row["data"][column] = _value(column, raw)
                        except ValueError as error:
                            row["data"][column] = None
                            row["errors"].append(f"{column}: {error}")
                    result.append(row)
                if header_row is None:
                    raise ValidationError({
                        "file": f"{sheet_name}: no se encontraron los encabezados esperados."
                    })
            return result
        finally:
            workbook.close()
    except ValidationError:
        raise
    except (ValueError, KeyError, OSError, EOFError, ImportError) as error:
        raise ValidationError({"file": f"No se pudo leer el Excel: {error}"})
    except Exception as error:
        # Corrupt ZIP/worksheet must never become an unhandled 500 response.
        raise ValidationError({"file": "Archivo XLSX dañado o no compatible."}) from error


def _payload(sheet, data):
    obj = {
        "name": data.get("nombre_activo") or "",
        "asset_type": "HARDWARE" if sheet == "Hardware" else "SOFTWARE",
    }
    for excel_key, backend_key in GENERAL_MAP.items():
        val = data.get(excel_key)
        if val is None:
            continue
        obj[backend_key] = val
    if data.get("costo_reposicion") is None:
        obj["replacement_cost"] = None
    if data.get("moneda") is None:
        obj["replacement_currency"] = ""
    nested = {}
    for excel_key, backend_key in TECH_MAP[sheet].items():
        val = data.get(excel_key)
        if val is not None:
            nested[backend_key] = val
    obj["hardware" if sheet == "Hardware" else "software"] = nested
    return obj


def _validate_row(sheet, row):
    data = row["data"]
    errors = list(row["errors"])
    if not data.get("nombre_activo"):
        errors.append("nombre_activo: obligatorio.")
    if sheet == "Hardware" and not data.get("rol"):
        errors.append("rol: obligatorio.")
    if sheet == "Software" and (not data.get("tipo_software") or not data.get("producto")):
        errors.append("tipo_software y producto: obligatorios.")
    state = data.get("estado_inventario")
    if state not in (None, "ACTIVE", "ARCHIVED"):
        errors.append("estado_inventario: valor inválido.")
    if data.get("costo_reposicion") is None and data.get("moneda") is not None:
        errors.append("moneda: no puede existir sin costo.")
    if data.get("costo_reposicion") is not None and not data.get("moneda"):
        errors.append("costo_reposicion: debe tener moneda.")
    # Excel carries asset data only, never OT system associations.
    # Existing rows remain correctable even if they are legacy-incomplete.
    serializer = AssetCreateSerializer(
        data=_payload(sheet, data),
        context={"import_preview": True,
                 "import_preview_existing": data.get("id_visor_ot") is not None},
    )
    if not serializer.is_valid():
        errors.extend(f"{key}: {val}" for key, val in serializer.errors.items())
    return errors


def _norm(value):
    return " ".join(str(value or "").casefold().split())


def _candidate_matches(sheet, data, all_assets):
    name = _norm(data.get("nombre_activo"))
    matches = []
    if sheet == "Hardware":
        serial = _norm(data.get("numero_serie"))
        for asset in all_assets:
            if asset.asset_type != Asset.AssetType.HARDWARE:
                continue
            if name and _norm(asset.name) == name:
                matches.append(asset.pk)
            elif serial and _norm(asset.hardware.serial_number) == serial:
                matches.append(asset.pk)
    else:
        manufacturer = data.get("fabricante")
        product = data.get("producto")
        version = data.get("version")
        identity = software_identity(manufacturer, product, version)
        for asset in all_assets:
            if asset.asset_type != Asset.AssetType.SOFTWARE:
                continue
            candidate = asset.software
            known = software_identity(candidate.manufacturer, candidate.product, candidate.version)
            if identity is not None and known == identity:
                matches.append(asset.pk)
            elif name and _norm(asset.name) == name:
                matches.append(asset.pk)
    return sorted(set(matches))


def _field_diffs(sheet, data, asset):
    fields = {}
    for column in BASE + TECH[sheet]:
        incoming = data.get(column)
        if incoming is None:  # never clear existing values with blank cells
            continue
        if column in GENERAL_MAP:
            old = getattr(asset, GENERAL_MAP[column])
        else:
            old = getattr(asset.hardware if sheet == "Hardware" else asset.software,
                          TECH_MAP[sheet][column])
        if column == "costo_reposicion":
            changed = old is None or Decimal(incoming) != old
            old_value = str(old) if old is not None else None
        else:
            changed = str(old or "") != str(incoming)
            old_value = str(old) if old not in (None, "") else None
        if changed:
            fields[column] = {"current": old_value, "incoming": incoming}
    return fields


def build_plan(rows):
    assets = list(Asset.objects.select_related("hardware", "software"))
    index = {asset.pk: asset for asset in assets}
    seen_ids = Counter(row["data"].get("id_visor_ot") for row in rows
                       if row["data"].get("id_visor_ot") is not None)
    # Detect repeated known identities within the workbook itself. Distinct
    # physical devices sharing manufacturer+model are *not* duplicates.
    in_file = defaultdict(list)
    for row in rows:
        d, sheet = row["data"], row["sheet"]
        if d.get("id_visor_ot"):
            continue
        name = _norm(d.get("nombre_activo"))
        if name:
            in_file[("NAME", sheet, name)].append(row["key"])
        if sheet == "Hardware":
            serial = _norm(d.get("numero_serie"))
            if serial:
                in_file[("HARDWARE_SERIAL", serial)].append(row["key"])
        else:
            identity = software_identity(d.get("fabricante"), d.get("producto"), d.get("version"))
            if identity:
                in_file[("SOFTWARE_VARIANT", identity)].append(row["key"])
    ambiguous = {key for ids in in_file.values() if len(ids) > 1 for key in ids}

    plan = []
    for row in rows:
        sheet, data = row["sheet"], row["data"]
        pk = data.get("id_visor_ot")
        info = {
            "key": row["key"], "sheet": sheet, "row": row["row"],
            "id_visor_ot": pk, "name": data.get("nombre_activo") or "",
            "status": "CREATE", "fields": {}, "messages": [],
            "current_version": None,
        }
        errors = _validate_row(sheet, row)
        if pk is not None:
            if seen_ids[pk] > 1:
                errors.append(f"id_visor_ot {pk} repetido en el archivo.")
            asset = index.get(pk)
            if asset is None:
                errors.append(f"id_visor_ot {pk} no existe. No se genera otro ID.")
            elif asset.asset_type != ("HARDWARE" if sheet == "Hardware" else "SOFTWARE"):
                errors.append(f"El ID {pk} pertenece a otro tipo de activo.")
            else:
                info["current_version"] = asset.updated_at.isoformat()
                state = data.get("estado_inventario")
                if state and state != asset.inventory_status:
                    errors.append("El estado difiere del inventario; archivar/restaurar se hace desde Visor OT.")
                info["fields"] = _field_diffs(sheet, data, asset)
                info["status"] = "UPDATE" if info["fields"] else "SAME"
        else:
            if data.get("estado_inventario") == "ARCHIVED":
                errors.append("No se crean activos archivados desde Excel.")
            possible = _candidate_matches(sheet, data, assets)
            if possible:
                info["status"] = "REVIEW"
                info["messages"].append(
                    "Posible duplicado; revisa estos IDs en Visor OT: " +
                    ", ".join(map(str, possible)) +
                    ". Si es el mismo activo, asigna su ID en el Excel."
                )
            if row["key"] in ambiguous:
                info["status"] = "REVIEW"
                info["messages"].append("La identidad de esta fila se repite dentro del Excel.")
        if errors:
            info["status"] = "ERROR"
            info["messages"].extend(errors)
        plan.append(info)
    return plan


def plan_digest(plan):
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256(encoded).hexdigest()


def preview(file_bytes):
    rows = parse_workbook(file_bytes)
    plan = build_plan(rows)
    token = signing.dumps({
        "file_hash": sha256(file_bytes).hexdigest(),
        "plan_hash": plan_digest(plan),
    }, salt=PREVIEW_SALT)
    return {"rows": plan, "token": token, "summary": {
        key: sum(row["status"] == key for row in plan)
        for key in ("CREATE", "UPDATE", "SAME", "REVIEW", "ERROR")
    }}


def _update_payload(sheet, row, changed_fields, reason, confirm_shared):
    data = row["data"]
    body, technical = {}, {}
    for key in changed_fields:
        val = data[key]
        if key in GENERAL_MAP:
            body[GENERAL_MAP[key]] = val
        else:
            technical[TECH_MAP[sheet][key]] = val
    if technical:
        body["hardware" if sheet == "Hardware" else "software"] = technical
        if sheet == "Software":
            body["correction_reason"] = reason
            body["confirm_shared_correction"] = confirm_shared
    return body


@transaction.atomic
def confirm(file_bytes, *, token, actions, user):
    try:
        bound = signing.loads(token, salt=PREVIEW_SALT, max_age=900)
    except (signing.BadSignature, signing.SignatureExpired, TypeError):
        raise ValidationError({"preview": "Previsualización vencida o inválida; vuelve a analizar el Excel."})
    if bound.get("file_hash") != sha256(file_bytes).hexdigest():
        raise ValidationError({"file": "El archivo es distinto al previsualizado."})

    # Lock existing inventory to prevent concurrent changes between the
    # freshness verification and the updates in this transaction.
    list(Asset.objects.select_for_update().values_list("pk", flat=True))
    rows = parse_workbook(file_bytes)
    plan = build_plan(rows)
    if plan_digest(plan) != bound.get("plan_hash"):
        raise ValidationError({"preview": "El inventario cambió. Vuelve a previsualizar."})
    lookup = {row["key"]: row for row in rows}
    planned = {item["key"]: item for item in plan}
    if set(actions) != set(planned):
        raise ValidationError({"actions": "Las filas seleccionadas no coinciden con la previsualización."})
    result = {"created": [], "updated": [], "skipped": []}
    for key, decision in actions.items():
        info = planned[key]
        action = decision.get("action") if isinstance(decision, dict) else None
        if action == "SKIP":
            result["skipped"].append(key)
            continue
        if action == "CREATE" and info["status"] == "CREATE":
            payload = _payload(info["sheet"], lookup[key]["data"])
            if info["sheet"] == "Hardware":
                # Import NEVER establishes OT system memberships. The operator
                # may add systems later from the hardware details screen.
                # Reject legacy nonempty choices rather than silently ignoring
                # a relationship the operator believed would be created.
                if decision.get("system_ids"):
                    raise ValidationError({
                        "actions": f"{key}: asocia los sistemas manualmente después de importar."
                    })
            serializer = AssetCreateSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            if info["sheet"] == "Hardware":
                created = register_hardware_asset(data=serializer.validated_data, user=user)
            else:
                created = register_installed_software_asset(data=serializer.validated_data, user=user)
            result["created"].append({"key": key, "id": created.pk, "name": created.name})
            continue
        if action == "UPDATE" and info["status"] == "UPDATE":
            fields = decision.get("fields", [])
            if not isinstance(fields, list) or not fields or len(fields) != len(set(fields)):
                raise ValidationError({"actions": f"{key}: selecciona campos válidos."})
            if not set(fields).issubset(info["fields"]):
                raise ValidationError({"actions": f"{key}: campos no previsualizados."})
            reason = decision.get("correction_reason", "")
            confirm_shared = decision.get("confirm_shared_correction") is True
            body = _update_payload(info["sheet"], lookup[key], fields, reason, confirm_shared)
            asset = Asset.objects.select_related("hardware", "software").get(pk=info["id_visor_ot"])
            serializer = AssetUpdateSerializer(asset, data=body, partial=True)
            serializer.is_valid(raise_exception=True)
            if info["sheet"] == "Hardware":
                update_hardware_asset(asset=asset, data=serializer.validated_data, user=user)
            else:
                update_software_asset(asset_id=asset.pk, data=serializer.validated_data, user=user)
            result["updated"].append({"key": key, "id": asset.pk, "fields": fields})
            continue
        raise ValidationError({"actions": f"{key}: acción {action} no permitida para {info['status']}."})
    batch = AssetImportBatch.objects.create(
        imported_by=user,
        file_sha256=sha256(file_bytes).hexdigest(),
        created_count=len(result["created"]),
        updated_count=len(result["updated"]),
        skipped_count=len(result["skipped"]),
        details=result,
    )
    result["import_id"] = batch.pk
    return result
