"""Read-only two-sheet XLSX export; run with settings_test_sqlite."""
from io import BytesIO
from xml.etree import ElementTree as ET
from zipfile import ZipFile

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .models import Asset
from .services import register_hardware_asset
from .software_services import register_installed_software_asset
from .asset_excel import HARDWARE_COLUMNS, SOFTWARE_COLUMNS, column_letter


NS = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def worksheet_rows(archive, index):
    root = ET.fromstring(archive.read(f"xl/worksheets/sheet{index}.xml"))
    result = []
    for row in root.findall("x:sheetData/x:row", NS):
        values = {}
        for cell in row.findall("x:c", NS):
            text = cell.find("x:is/x:t", NS) if cell.get("t") == "inlineStr" \
                else cell.find("x:v", NS)
            values[cell.get("r")] = text.text if text is not None else None
        result.append(values)
    return result


class InventoryExportTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="export-operador", password="pw", role=User.Role.OPERATOR
        )
        self.analyst = User.objects.create_user(
            username="export-analyst", password="pw", role=User.Role.ANALYST
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)
        self.hardware = register_hardware_asset(
            data={
                "asset_type": "HARDWARE",
                "name": "PLC con & caracteres <etiqueta>",
                "description": "Equipo de laboratorio",
                "replacement_cost": "120.00",
                "replacement_currency": "USD",
                "hardware": {
                    "role": "PLC", "manufacturer": "AutomationDirect",
                    "model": "DL205", "serial_number": "S-001",
                    "physical_location": "Rack 1",
                },
            },
            user=self.operator,
        )
        self.software = register_installed_software_asset(
            data={
                "asset_type": "SOFTWARE",
                "name": "Firmware 01.20",
                "description": "Firmware del laboratorio",
                "software": {
                    "software_type": "FIRMWARE",
                    "manufacturer": "Phoenix Contact",
                    "product": "FL IL 24 BK-PAC",
                    "version": "01.20",
                },
            },
            user=self.operator,
        )

    def test_download_is_xlsx_with_two_sheets_and_real_fields(self):
        response = self.client.get("/api/assets/export/excel/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("spreadsheetml.sheet", response["Content-Type"])
        self.assertIn(".xlsx", response["Content-Disposition"])
        self.assertEqual(response["Cache-Control"], "no-store")
        with ZipFile(BytesIO(response.content)) as file:
            self.assertEqual(file.testzip(), None)
            wb = ET.fromstring(file.read("xl/workbook.xml"))
            names = [sheet.get("name") for sheet in wb.findall("x:sheets/x:sheet", NS)]
            self.assertEqual(names, ["Hardware", "Software"])
            hw, sw = worksheet_rows(file, 1), worksheet_rows(file, 2)
        self.assertEqual(len(hw), 2)
        self.assertEqual(len(sw), 2)
        self.assertEqual(
            [hw[0].get(f"{column_letter(i)}1") for i in range(len(HARDWARE_COLUMNS))],
            [col[0] for col in HARDWARE_COLUMNS],
        )
        self.assertEqual(
            [sw[0].get(f"{column_letter(i)}1") for i in range(len(SOFTWARE_COLUMNS))],
            [col[0] for col in SOFTWARE_COLUMNS],
        )
        self.assertEqual(hw[1]["A2"], str(self.hardware.pk))
        self.assertEqual(hw[1]["B2"], self.hardware.name)
        self.assertEqual(hw[1]["E2"], "DL205")
        self.assertEqual(hw[1]["F2"], "PLC")
        self.assertEqual(hw[1]["K2"], "120.00")
        self.assertEqual(sw[1]["A2"], str(self.software.pk))
        self.assertEqual(sw[1]["D2"], "FIRMWARE")
        self.assertEqual(sw[1]["G2"], "01.20")

    def test_export_includes_archived_assets_without_changing_status(self):
        original = self.hardware
        original.inventory_status = Asset.InventoryStatus.ARCHIVED
        original.save(update_fields=["inventory_status"])
        response = self.client.get("/api/assets/export/excel/")
        with ZipFile(BytesIO(response.content)) as file:
            hw = worksheet_rows(file, 1)
        self.assertEqual(hw[1]["M2"], "ARCHIVED")
        self.assertEqual(Asset.objects.get(pk=original.pk).inventory_status, "ARCHIVED")

    def test_export_does_not_create_or_change_assets(self):
        before = [(a.pk, a.updated_at) for a in Asset.objects.order_by("pk")]
        self.assertEqual(self.client.get("/api/assets/export/excel/").status_code, 200)
        self.assertEqual(
            [(a.pk, a.updated_at) for a in Asset.objects.order_by("pk")],
            before,
        )

    def test_analyst_can_export_and_anonymous_cannot(self):
        self.client.force_authenticate(self.analyst)
        self.assertEqual(self.client.get("/api/assets/export/excel/").status_code, 200)
        self.client.force_authenticate(user=None)
        self.assertIn(
            self.client.get("/api/assets/export/excel/").status_code,
            (401, 403),
        )

    def test_excel_formula_like_text_is_not_emitted_as_formula(self):
        self.hardware.description = "=HYPERLINK(\"https://example.org\")"
        self.hardware.save(update_fields=["description"])
        response = self.client.get("/api/assets/export/excel/")
        with ZipFile(BytesIO(response.content)) as file:
            raw = file.read("xl/worksheets/sheet1.xml")
            hw = worksheet_rows(file, 1)
        self.assertNotIn(b"<f>", raw)
        self.assertEqual(hw[1]["C2"], self.hardware.description)

    def test_empty_inventory_still_has_both_header_sheets(self):
        Asset.objects.all().delete()
        response = self.client.get("/api/assets/export/excel/")
        with ZipFile(BytesIO(response.content)) as file:
            self.assertEqual(len(worksheet_rows(file, 1)), 1)
            self.assertEqual(len(worksheet_rows(file, 2)), 1)
