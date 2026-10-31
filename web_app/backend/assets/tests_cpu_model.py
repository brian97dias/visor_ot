"""PLC-only CPU model inventory field: model, API and Excel regressions."""
from io import BytesIO
from zipfile import ZipFile

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from rest_framework.test import APIClient
from openpyxl import Workbook

from .asset_excel import HARDWARE_COLUMNS, SOFTWARE_COLUMNS
from .models import Asset, Hardware, OTSystem
from .tests_excel_export import worksheet_rows
from .tests_excel_import import upload, xlsx, PREVIEW, CONFIRM
import json


class CpuModelTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.operator = User.objects.create_user(
            username="cpu-operator", password="pw", role=User.Role.OPERATOR
        )
        self.client = APIClient()
        self.client.force_authenticate(self.operator)
        self.system = OTSystem.objects.create(
            name="Sistema de CPU", criticality="MEDIUM",
            created_by=self.operator, updated_by=self.operator,
        )

    def register(self, role="PLC", cpu_model=None):
        hardware = {
            "manufacturer": "Siemens",
            "model": "SIMATIC S7-1200",
            "role": role,
        }
        if cpu_model is not None:
            hardware["cpu_model"] = cpu_model
        return self.client.post("/api/assets/", {
            "name": "PLC-01",
            "asset_type": "HARDWARE",
            "criticality": "MEDIUM",
            "system_ids": [self.system.pk],
            "hardware": hardware,
        }, format="json")

    def test_plc_cpu_can_be_created_read_and_updated(self):
        response = self.register(cpu_model="1215C")
        self.assertEqual(response.status_code, 201, response.data)
        asset_id = response.data["id"]
        self.assertEqual(response.data["hardware"]["cpu_model"], "1215C")

        updated = self.client.patch(f"/api/assets/{asset_id}/", {
            "hardware": {"cpu_model": "1214C"}
        }, format="json")
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertEqual(updated.data["hardware"]["cpu_model"], "1214C")
        self.assertEqual(Hardware.objects.get(asset_id=asset_id).cpu_model, "1214C")

    def test_cpu_is_optional_for_plc_and_other_hardware(self):
        for role in ("PLC", "RTU", "SWITCH"):
            with self.subTest(role=role):
                response = self.register(role=role)
                self.assertEqual(response.status_code, 201, response.data)
                self.assertEqual(response.data["hardware"]["cpu_model"], "")

    def test_cpu_is_rejected_on_non_plc_create_and_patch(self):
        denied = self.register(role="SWITCH", cpu_model="1215C")
        self.assertEqual(denied.status_code, 400)
        self.assertEqual(Asset.objects.count(), 0)
        created = self.register(role="SWITCH")
        self.assertEqual(created.status_code, 201, created.data)
        denied = self.client.patch(f"/api/assets/{created.data['id']}/", {
            "hardware": {"cpu_model": "1215C"}
        }, format="json")
        self.assertEqual(denied.status_code, 400)
        self.assertEqual(Hardware.objects.get(asset_id=created.data["id"]).cpu_model, "")

    def test_role_change_requires_clearing_existing_cpu(self):
        created = self.register(cpu_model="1215C")
        asset_id = created.data["id"]
        denied = self.client.patch(f"/api/assets/{asset_id}/", {
            "hardware": {"role": "HMI"}
        }, format="json")
        self.assertEqual(denied.status_code, 400)
        changed = self.client.patch(f"/api/assets/{asset_id}/", {
            "hardware": {"role": "HMI", "cpu_model": ""}
        }, format="json")
        self.assertEqual(changed.status_code, 200, changed.data)
        self.assertEqual(changed.data["hardware"]["cpu_model"], "")
        self.assertEqual(changed.data["hardware"]["role"], "HMI")

    def test_model_and_database_reject_cpu_on_non_plc(self):
        asset = Asset.objects.create(
            name="Switch", asset_type=Asset.AssetType.HARDWARE,
            created_by=self.operator, updated_by=self.operator,
        )
        hardware = Hardware(asset=asset, role=Hardware.Role.SWITCH, cpu_model="1215C")
        with self.assertRaises(ValidationError):
            hardware.full_clean()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                hardware.save()

    def test_excel_exports_cpu_as_optional_trailing_column(self):
        created = self.register(cpu_model="1215C")
        self.assertEqual(created.status_code, 201)
        exported = self.client.get("/api/assets/export/excel/")
        self.assertEqual(exported.status_code, 200)
        with ZipFile(BytesIO(exported.content)) as archive:
            hardware_rows = worksheet_rows(archive, 1)
        self.assertEqual(HARDWARE_COLUMNS[-1], ("modelo_cpu", "cpu_model"))
        self.assertEqual(hardware_rows[0]["N1"], "modelo_cpu")
        self.assertEqual(hardware_rows[1]["N2"], "1215C")

    def test_excel_can_register_cpu_and_reject_cpu_for_other_roles(self):
        row = {
            "nombre_activo": "PLC-Excel",
            "fabricante": "Siemens",
            "modelo": "S7-1200",
            "rol": "PLC",
            "modelo_cpu": "1215C",
            "criticidad": "MEDIUM",
        }
        blob = xlsx([row])
        preview = self.client.post(PREVIEW, {"file": upload(blob)}, format="multipart")
        self.assertEqual(preview.status_code, 200, preview.data)
        self.assertEqual(preview.data["summary"]["CREATE"], 1)
        actions = {"Hardware:2": {
            "action": "CREATE", "system_ids": [self.system.pk],
        }}
        result = self.client.post(CONFIRM, {
            "file": upload(blob),
            "token": preview.data["token"],
            "actions": json.dumps(actions),
        }, format="multipart")
        self.assertEqual(result.status_code, 200, result.data)
        hardware = Hardware.objects.get(asset_id=result.data["created"][0]["id"])
        self.assertEqual(hardware.cpu_model, "1215C")

        row["nombre_activo"] = "Switch-Excel"
        row["rol"] = "SWITCH"
        preview = self.client.post(PREVIEW, {"file": upload(xlsx([row]))}, format="multipart")
        self.assertEqual(preview.status_code, 200, preview.data)
        self.assertEqual(preview.data["summary"]["ERROR"], 1)

    def test_excel_accepts_existing_hardware_template_without_cpu_column(self):
        workbook = Workbook()
        hardware = workbook.active
        hardware.title = "Hardware"
        software = workbook.create_sheet("Software")
        hardware.append([key for key, _ in HARDWARE_COLUMNS[:-1]])
        software.append([key for key, _ in SOFTWARE_COLUMNS])
        hardware.append([
            None, "PLC legado", None, "Siemens", "SIMATIC S7-1200",
            "PLC", None, None, "MEDIUM", None, None, None, "ACTIVE",
        ])
        stream = BytesIO()
        workbook.save(stream)
        workbook.close()
        response = self.client.post(PREVIEW, {
            "file": upload(stream.getvalue())
        }, format="multipart")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["summary"]["CREATE"], 1)
