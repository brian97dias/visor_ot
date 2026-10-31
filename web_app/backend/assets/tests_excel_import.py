"""XLSX inventory import: preview, confirmation, permissions and rollback.

Run via:
python manage.py test assets.tests_excel_import --settings=config.settings_test_sqlite
Requires openpyxl from requirements-import.txt.
"""
from io import BytesIO
import json

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIClient
from openpyxl import Workbook

from .asset_excel import HARDWARE_COLUMNS, SOFTWARE_COLUMNS
from .models import Asset, AssetImportBatch, Software, SoftwareCorrection, SoftwareInstallation, OTSystem
from .services import register_hardware_asset
from .software_services import register_installed_software_asset

PREVIEW = "/api/assets/import/preview/"
CONFIRM = "/api/assets/import/confirm/"


def xlsx(hardware=(), software=()):
    wb = Workbook()
    hw = wb.active
    hw.title = "Hardware"
    sw = wb.create_sheet("Software")
    for worksheet, fields, values in (
        (hw, HARDWARE_COLUMNS, hardware), (sw, SOFTWARE_COLUMNS, software)
    ):
        header = [key for key, _ in fields]
        worksheet.append(header)
        for item in values:
            worksheet.append([item.get(key) for key in header])
    output = BytesIO()
    wb.save(output)
    wb.close()
    return output.getvalue()


def upload(blob):
    return SimpleUploadedFile("inventario.xlsx", blob, content_type=
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


class ExcelImportTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="import-operador", password="pw", role=User.Role.OPERATOR
        )
        self.analyst = User.objects.create_user(
            username="import-analyst", password="pw", role=User.Role.ANALYST
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)
        self.system = OTSystem.objects.create(
            name="Sistema para importaciones", criticality="MEDIUM",
            created_by=self.operator, updated_by=self.operator,
        )
        self.hw = register_hardware_asset(data={
            "name": "DirectLogic 205", "asset_type": "HARDWARE",
            "description": "Anterior", "hardware": {
                "manufacturer": "AutomationDirect", "model": "DL205",
                "role": "PLC", "physical_location": "Rack #1",
            },
        }, user=self.operator)
        self.sw = register_installed_software_asset(data={
            "name": "Firmware DL205", "asset_type": "SOFTWARE",
            "software": {
                "software_type": "FIRMWARE", "manufacturer": "AutomationDirect",
                "product": "DL205 Firmware", "version": "V18",
            },
            "hardware_asset_id": self.hw.pk, "criticality": "MEDIUM",
        }, user=self.operator)

    def _hw(self, **overrides):
        return {
            "id_visor_ot": self.hw.pk,
            "nombre_activo": "DirectLogic 205",
            "descripcion": "Descripción enriquecida",
            "fabricante": "AutomationDirect", "modelo": "DL205",
            "rol": "PLC", "numero_serie": "001286",
            "ubicacion_fisica": "Rack #1",
            "criticidad": "MEDIUM",
            "impacto_indisponibilidad": "Parada de control",
            "costo_reposicion": 123,
            "moneda": "INR",
            "estado_inventario": "ACTIVE",
            **overrides,
        }

    def _sw(self, **overrides):
        return {
            "id_visor_ot": self.sw.pk, "nombre_activo": "Firmware DL205",
            "tipo_software": "FIRMWARE", "fabricante": "AutomationDirect",
            "producto": "DL205 Firmware", "version": "V18",
            "criticidad": "MEDIUM",
            "estado_inventario": "ACTIVE",
            **overrides,
        }

    def _preview(self, blob):
        return self.client.post(PREVIEW, {"file": upload(blob)}, format="multipart")

    def _confirm(self, blob, preview_data, actions):
        return self.client.post(CONFIRM, {
            "file": upload(blob), "token": preview_data["token"],
            "actions": json.dumps(actions),
        }, format="multipart")

    def _choices(self, preview):
        return {
            row["key"]: {
                "action": "CREATE" if row["status"] == "CREATE" else "SKIP",
                "fields": [], "correction_reason": "",
                "confirm_shared_correction": False,
                "system_ids": [self.system.pk] if row["sheet"] == "Hardware" else [],
            } for row in preview["rows"]
        }

    def test_preview_splits_new_and_existing_and_does_not_write(self):
        new = self._hw(id_visor_ot=None, nombre_activo="Nuevo PLC",
                       numero_serie="000142", moneda="AUD")
        blob = xlsx([self._hw(), new], [self._sw()])
        before = Asset.objects.count()
        response = self._preview(blob)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["summary"]["CREATE"], 1)
        self.assertEqual(response.data["summary"]["UPDATE"], 1)
        self.assertEqual(response.data["summary"]["SAME"], 1)
        self.assertEqual(Asset.objects.count(), before)
        self.assertIn("numero_serie", response.data["rows"][0]["fields"])
        self.assertEqual(response.data["rows"][0]["fields"]["numero_serie"]["incoming"], "001286")

    def test_selective_updates_only_approved_fields_and_creates_new(self):
        blob = xlsx([self._hw(), self._hw(id_visor_ot=None,
                nombre_activo="Nuevo hardware", numero_serie="0042",
                moneda="AUD")])
        prev = self._preview(blob).data
        acts = self._choices(prev)
        acts["Hardware:2"] = {
            "action": "UPDATE", "fields": ["numero_serie","impacto_indisponibilidad"]
        }
        response = self._confirm(blob, prev, acts)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data["created"]), 1)
        self.assertEqual(len(response.data["updated"]), 1)
        self.hw.refresh_from_db()
        self.assertEqual(self.hw.hardware.serial_number, "001286")
        self.assertEqual(self.hw.impact, "Parada de control")
        self.assertEqual(self.hw.description, "Anterior")
        added = Asset.objects.get(pk=response.data["created"][0]["id"])
        self.assertEqual(added.replacement_currency, "AUD")
        audit = AssetImportBatch.objects.get()
        self.assertEqual(audit.imported_by, self.operator)
        self.assertEqual(audit.created_count, 1)
        self.assertEqual(audit.updated_count, 1)
        self.assertEqual(response.data["import_id"], audit.pk)
        self.assertEqual(audit.details["updated"][0]["fields"],
                         ["numero_serie", "impacto_indisponibilidad"])

    def test_correction_of_software_version_requires_audit_reason(self):
        blob = xlsx([], [self._sw(version="V19")])
        prev = self._preview(blob).data
        acts = self._choices(prev)
        acts["Software:2"] = {"action": "UPDATE", "fields": ["version"]}
        denied = self._confirm(blob, prev, acts)
        self.assertEqual(denied.status_code, 400)
        self.assertEqual(SoftwareCorrection.objects.count(), 0)
        acts["Software:2"]["correction_reason"] = "Versión mal registrada"
        accepted = self._confirm(blob, prev, acts)
        self.assertEqual(accepted.status_code, 200, accepted.data)
        self.sw.refresh_from_db()
        self.assertEqual(self.sw.software.version, "V19")
        self.assertEqual(SoftwareCorrection.objects.count(), 1)
        self.assertEqual(SoftwareInstallation.objects.get().identity_snapshot["version"], "V18")

    def test_duplicate_ids_in_excel_are_errors(self):
        blob = xlsx([self._hw(), self._hw(nombre_activo="Duplicado")])
        response = self._preview(blob)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["summary"]["ERROR"], 2)

    def test_unknown_id_is_error_not_a_new_asset(self):
        blob = xlsx([self._hw(id_visor_ot=99999)])
        response = self._preview(blob)
        self.assertEqual(response.data["summary"]["ERROR"], 1)

    def test_name_match_without_id_requires_review(self):
        blob = xlsx([self._hw(id_visor_ot=None, numero_serie=None)])
        response = self._preview(blob)
        self.assertEqual(response.data["summary"]["REVIEW"], 1)

    def test_same_model_different_serial_allows_distinct_devices(self):
        first = self._hw(id_visor_ot=None, nombre_activo="RS910 A",
                         fabricante="Siemens", modelo="RS910", numero_serie="RS-A")
        second = self._hw(id_visor_ot=None, nombre_activo="RS910 B",
                          fabricante="Siemens", modelo="RS910", numero_serie="RS-B")
        response = self._preview(xlsx([first, second]))
        self.assertEqual(response.data["summary"]["CREATE"], 2)

    def test_known_software_variant_without_id_requires_review(self):
        blob = xlsx([], [self._sw(id_visor_ot=None, nombre_activo="Otro nombre")])
        response = self._preview(blob)
        self.assertEqual(response.data["summary"]["REVIEW"], 1)

    def test_preview_expired_by_data_change_fails_safely(self):
        blob = xlsx([self._hw()])
        prev = self._preview(blob).data
        self.hw.name = "Cambio concurrente"
        self.hw.save(update_fields=["name", "updated_at"])
        result = self._confirm(blob, prev, self._choices(prev))
        self.assertEqual(result.status_code, 400)
        self.assertIn("preview", result.data)

    def test_bad_token_and_modified_file_rejected(self):
        blob = xlsx([self._hw()])
        prev = self._preview(blob).data
        actions = self._choices(prev)
        wrong_file = xlsx([self._hw(numero_serie="ABC")])
        self.assertEqual(self._confirm(wrong_file, prev, actions).status_code, 400)
        response = self.client.post(CONFIRM, {
            "file": upload(blob), "token": "invalid",
            "actions": json.dumps(actions),
        }, format="multipart")
        self.assertEqual(response.status_code, 400)

    def test_confirm_all_or_nothing_when_later_row_fails(self):
        new = self._hw(id_visor_ot=None, nombre_activo="Nuevo hardware",
                       numero_serie="SN-NUEVO")
        blob = xlsx([new], [self._sw(version="V19")])
        prev = self._preview(blob).data
        actions = self._choices(prev)
        actions["Software:2"] = {"action": "UPDATE", "fields": ["version"]}
        result = self._confirm(blob, prev, actions)
        self.assertEqual(result.status_code, 400)
        self.assertFalse(Asset.objects.filter(name="Nuevo hardware").exists())
        self.assertEqual(SoftwareCorrection.objects.count(), 0)
        self.assertFalse(AssetImportBatch.objects.exists())

    def test_analyst_and_anonymous_cannot_import(self):
        blob = xlsx([self._hw()])
        self.client.force_authenticate(self.analyst)
        self.assertEqual(self._preview(blob).status_code, 403)
        self.client.force_authenticate(user=None)
        self.assertIn(self._preview(blob).status_code, (401, 403))

    def test_blank_columns_do_not_erase_existing_data(self):
        blob = xlsx([self._hw(descripcion=None, numero_serie=None,
                              impacto_indisponibilidad=None)])
        prev = self._preview(blob)
        self.assertEqual(prev.status_code, 200, prev.data)
        fields = prev.data["rows"][0]["fields"]
        self.assertNotIn("descripcion", fields)
        self.assertNotIn("numero_serie", fields)

    def test_rejects_incompatible_header(self):
        from openpyxl import load_workbook
        blob = xlsx([self._hw()])
        book = load_workbook(BytesIO(blob))
        book["Hardware"]["B1"] = "nombre_incorrecto"
        output = BytesIO()
        book.save(output)
        result = self._preview(output.getvalue())
        self.assertEqual(result.status_code, 400)


    def test_same_name_in_source_without_ids_must_be_reviewed(self):
        first = self._hw(id_visor_ot=None, nombre_activo="PLC copia",
                         numero_serie="S-A")
        second = self._hw(id_visor_ot=None, nombre_activo="PLC copia",
                          numero_serie="S-B")
        result = self._preview(xlsx([first, second]))
        self.assertEqual(result.data["summary"]["REVIEW"], 2)

    def test_indian_rupee_cost_import_is_preserved(self):
        new = self._hw(id_visor_ot=None, nombre_activo="Beckhoff CX1010",
                       numero_serie="INR-001", moneda="INR",
                       costo_reposicion=1777)
        blob = xlsx([new])
        prev = self._preview(blob).data
        actions = self._choices(prev)
        result = self._confirm(blob, prev, actions)
        self.assertEqual(result.status_code, 200, result.data)
        asset = Asset.objects.get(pk=result.data["created"][0]["id"])
        self.assertEqual(asset.replacement_currency, "INR")
        self.assertEqual(str(asset.replacement_cost), "1777.00")


    def test_long_numeric_serial_requires_text_cell(self):
        row = self._hw(id_visor_ot=None, nombre_activo="Router nuevo",
                       numero_serie=12345678901234567)
        result = self._preview(xlsx([row]))
        self.assertEqual(result.status_code, 200, result.data)
        self.assertEqual(result.data["summary"]["ERROR"], 1)
        self.assertIn("formato Texto", str(result.data["rows"][0]["messages"]))


    def test_sparse_hardware_sheet_with_excel_last_row_marker(self):
        """A huge declared dimension must not mean a million inventory rows."""
        from openpyxl import load_workbook

        base = xlsx([self._hw()], [self._sw()])
        wb = load_workbook(BytesIO(base))
        sheet = wb["Hardware"]
        sheet.row_dimensions[1048575].height = 12.8
        sheet.row_dimensions[1048576].height = 12.8
        # A formatted extra column must not be interpreted as real data.
        sheet["R2"].number_format = "@"
        output = BytesIO()
        wb.save(output)
        wb.close()
        data = output.getvalue()

        result = self._preview(data)
        self.assertEqual(result.status_code, 200, result.data)
        self.assertEqual(len(result.data["rows"]), 2)
        self.assertEqual(result.data["summary"]["UPDATE"], 1)
        self.assertEqual(result.data["summary"]["SAME"], 1)
        self.assertEqual(result.data["rows"][0]["row"], 2)

    def test_previews_legacy_template_with_header_in_row_five(self):
        from openpyxl import Workbook

        wb = Workbook()
        hw = wb.active
        hw.title = "Hardware"
        sw = wb.create_sheet("Software")
        for worksheet, columns, values in (
            (hw, HARDWARE_COLUMNS, self._hw()),
            (sw, SOFTWARE_COLUMNS, self._sw()),
        ):
            headers = [key for key, _ in columns]
            for i, header in enumerate(headers, start=1):
                worksheet.cell(row=5, column=i, value=header)
                if values.get(header) is not None:
                    worksheet.cell(row=6, column=i, value=values[header])
        output = BytesIO()
        wb.save(output)
        wb.close()

        result = self._preview(output.getvalue())
        self.assertEqual(result.status_code, 200, result.data)
        self.assertEqual(len(result.data["rows"]), 2)
        self.assertEqual([r["key"] for r in result.data["rows"]],
                         ["Hardware:6", "Software:6"])

    def test_more_than_five_hundred_populated_rows_still_rejected(self):
        entries = [
            {"nombre_activo": f"Dispositivo {index}", "rol": "PLC"}
            for index in range(501)
        ]
        result = self._preview(xlsx(entries))
        self.assertEqual(result.status_code, 400)
        self.assertIn("500 activos con datos", str(result.data))
