"""DRF Software payload validation without a temporary database."""

from django.test import SimpleTestCase

from .serializers import AssetCreateSerializer, AssetUpdateSerializer
from .models import Asset


class SoftwarePayloadTests(SimpleTestCase):
    def software_payload(self, **overrides):
        data = {
            "name": "TIA Portal V18",
            "asset_type": "SOFTWARE",
            "hardware_asset_id": 5,
            "software": {
                "software_type": "APPLICATION",
                "manufacturer": "Siemens",
                "product": "TIA Portal",
                "version": "V18",
            },
        }
        data.update(overrides)
        return data

    def test_software_creation_payload(self):
        serializer = AssetCreateSerializer(data=self.software_payload())
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["asset_type"], "SOFTWARE")
        self.assertEqual(
            serializer.validated_data["software"]["product"], "TIA Portal"
        )

    def test_unknown_version_is_optional(self):
        serializer = AssetCreateSerializer(data=self.software_payload(software={
            "software_type": "FIRMWARE",
            "manufacturer": "Advantech",
            "product": "ADAM Firmware",
            "version": "",
        }))
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_product_and_type_are_required(self):
        for technical in ({"product": "Firmware"},
                          {"software_type": "FIRMWARE"},
                          {}):
            with self.subTest(software=technical):
                serializer = AssetCreateSerializer(
                    data=self.software_payload(software=technical)
                )
                self.assertFalse(serializer.is_valid())

    def test_rejects_hardware_and_interface_on_software(self):
        for injected in (
            {"hardware": {"role": "PLC"}},
            {"interface_assignment": {"mode": "EXISTING", "interface_id": 1}},
        ):
            with self.subTest(injected=injected):
                serializer = AssetCreateSerializer(
                    data=self.software_payload(**injected)
                )
                self.assertFalse(serializer.is_valid())

    def test_hardware_registration_still_valid(self):
        serializer = AssetCreateSerializer(data={
            "name": "PLC-01",
            "asset_type": "HARDWARE",
            "hardware": {"role": "PLC"},
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_hardware_without_hardware_data_is_invalid(self):
        serializer = AssetCreateSerializer(data={
            "name": "PLC",
            "asset_type": "HARDWARE",
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn("hardware", serializer.errors)

    def test_hardware_rejects_software_payload(self):
        serializer = AssetCreateSerializer(data={
            "name": "PLC",
            "asset_type": "HARDWARE",
            "hardware": {"role": "PLC"},
            "software": {"software_type": "APPLICATION", "product": "App"},
        })
        self.assertFalse(serializer.is_valid())

    def test_update_rejects_technical_fields_from_wrong_type(self):
        hardware = Asset(asset_type=Asset.AssetType.HARDWARE)
        software = Asset(asset_type=Asset.AssetType.SOFTWARE)
        a = AssetUpdateSerializer(hardware, data={
            "software": {"product": "Firmware"},
        }, partial=True)
        c = AssetUpdateSerializer(software, data={
            "hardware": {"role": "PLC"},
        }, partial=True)
        self.assertFalse(a.is_valid())
        self.assertFalse(c.is_valid())

    def test_update_rejects_change_of_asset_type(self):
        software = Asset(asset_type=Asset.AssetType.SOFTWARE)
        serializer = AssetUpdateSerializer(
            software, data={"asset_type": "HARDWARE"}, partial=True
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("asset_type", serializer.errors)

    def test_software_without_hardware_is_a_valid_inventory_entry(self):
        payload = self.software_payload()
        payload.pop("hardware_asset_id")
        serializer = AssetCreateSerializer(data=payload)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertNotIn("hardware_asset_id", serializer.validated_data)

    def test_hardware_id_must_be_positive(self):
        serializer = AssetCreateSerializer(
            data=self.software_payload(hardware_asset_id=0)
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("hardware_asset_id", serializer.errors)

    def test_hardware_asset_rejects_initial_software_host(self):
        serializer = AssetCreateSerializer(data={
            "name": "PLC-01",
            "asset_type": "HARDWARE",
            "hardware": {"role": "PLC"},
            "hardware_asset_id": 5,
        })
        self.assertFalse(serializer.is_valid())
