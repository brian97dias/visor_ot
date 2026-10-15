"""Interface API permission and payload checks without creating a test DB."""

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory

from .interface_permissions import NetworkInterfacePermission
from .interface_serializers import NetworkInterfaceCreateSerializer


class InterfaceAPINoDatabaseTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.User = get_user_model()

    def test_permissions_for_list_and_create(self):
        permission = NetworkInterfacePermission()
        for role, create_allowed in (
            (self.User.Role.ADMIN, True),
            (self.User.Role.ANALYST, False),
            (self.User.Role.OPERATOR, True),
        ):
            user = self.User(username=f"test-{role.lower()}", role=role)
            for method in ("get", "post"):
                with self.subTest(role=role, method=method):
                    request = getattr(self.factory, method)("/api/assets/interfaces/")
                    request.user = user
                    self.assertEqual(
                        permission.has_permission(request, None),
                        True if method == "get" else create_allowed,
                    )

    def test_empty_interface_is_invalid(self):
        serializer = NetworkInterfaceCreateSerializer(data={})
        self.assertFalse(serializer.is_valid())
        self.assertIn("non_field_errors", serializer.errors)

    def test_mac_invalid(self):
        serializer = NetworkInterfaceCreateSerializer(
            data={"mac": "no-es-una-mac"}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("mac", serializer.errors)

    def test_declared_ip_invalid(self):
        serializer = NetworkInterfaceCreateSerializer(
            data={"declared_ip": "no-es-una-ip"}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("declared_ip", serializer.errors)
