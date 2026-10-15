"""Authorization and validation for hardware/interface assignments without a test DB."""

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from .interface_views import (
    AssetInterfaceAssignView, InterfaceIdentifyView, InterfaceUnlinkView,
)
from .serializers import InterfaceAssignmentSerializer


class AssignmentValidationTests(SimpleTestCase):
    def test_existing_requires_interface_id(self):
        serializer = InterfaceAssignmentSerializer(data={"mode": "EXISTING"})
        self.assertFalse(serializer.is_valid())

    def test_existing_accepts_only_id(self):
        serializer = InterfaceAssignmentSerializer(
            data={"mode": "EXISTING", "interface_id": 112}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["interface_id"], 112)

    def test_existing_cannot_be_combined_with_manual_fields(self):
        serializer = InterfaceAssignmentSerializer(data={
            "mode": "EXISTING", "interface_id": 112,
            "declared_ip": "192.168.88.15",
        })
        self.assertFalse(serializer.is_valid())

    def test_manual_requires_an_address(self):
        serializer = InterfaceAssignmentSerializer(data={"mode": "MANUAL"})
        self.assertFalse(serializer.is_valid())

    def test_manual_rejects_interface_id(self):
        serializer = InterfaceAssignmentSerializer(data={
            "mode": "MANUAL", "interface_id": 112, "declared_ip": "192.168.88.15",
        })
        self.assertFalse(serializer.is_valid())

    def test_manual_rejects_invalid_mac(self):
        serializer = InterfaceAssignmentSerializer(data={
            "mode": "MANUAL", "mac": "incorrecta",
        })
        self.assertFalse(serializer.is_valid())

    def test_analyst_cannot_associate_or_unlink(self):
        User = get_user_model()
        analyst = User(username="analista", role=User.Role.ANALYST)
        factory = APIRequestFactory()
        cases = [
            (InterfaceIdentifyView, "/api/assets/interfaces/112/identify/",
             {"interface_id": 112}, {"asset_id": 1}),
            (InterfaceUnlinkView, "/api/assets/interfaces/112/unlink/",
             {"interface_id": 112}, {}),
            (AssetInterfaceAssignView, "/api/assets/1/interfaces/",
             {"asset_id": 1}, {"mode": "EXISTING", "interface_id": 112}),
        ]
        for view, url, kwargs, payload in cases:
            with self.subTest(url=url):
                request = factory.post(url, payload, format="json")
                force_authenticate(request, user=analyst)
                response = view.as_view()(request, **kwargs)
                self.assertEqual(response.status_code, 403)
