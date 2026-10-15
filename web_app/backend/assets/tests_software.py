"""Pure software identity and permission tests: no database required."""

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase
from rest_framework.exceptions import PermissionDenied, ValidationError

from .software_services import _check_role, _validate_software_data
from .software_validation import (
    compact_spaces, normalize_software_fields, software_identity,
)


class SoftwareIdentityTests(SimpleTestCase):
    def test_known_identity_ignores_case_and_repeated_spaces(self):
        a = software_identity("  Siemens ", " TIA   Portal ", " V18 ")
        b = software_identity("SIEMENS", "tia portal", "v18")
        self.assertEqual(a, b)

    def test_different_versions_are_distinct(self):
        self.assertNotEqual(
            software_identity("Siemens", "TIA Portal", "V18"),
            software_identity("Siemens", "TIA Portal", "V19"),
        )

    def test_unknown_version_or_vendor_does_not_imply_identity(self):
        self.assertIsNone(software_identity("Siemens", "TIA Portal", ""))
        self.assertIsNone(software_identity("", "TIA Portal", "V18"))

    def test_fields_preserve_case_but_normalize_spaces(self):
        self.assertEqual(compact_spaces(" WinCC \t  Unified "),
                         "WinCC Unified")
        self.assertEqual(
            normalize_software_fields(" Siemens ", "  TIA   Portal ", " V18 "),
            ("Siemens", "TIA Portal", "V18"),
        )

    def test_required_software_fields(self):
        for values in ({}, {"software_type": "FIRMWARE"},
                       {"product": "ADAM Firmware"}):
            with self.subTest(values=values):
                with self.assertRaises(ValidationError):
                    _validate_software_data(values)

    def test_unknown_software_field_is_rejected(self):
        with self.assertRaises(ValidationError):
            _validate_software_data({
                "software_type": "FIRMWARE",
                "product": "ADAM",
                "hardware_id": 1,
            })


class SoftwarePermissionTests(SimpleTestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User(username="admin", role=User.Role.ADMIN)
        self.operator = User(username="operador", role=User.Role.OPERATOR)
        self.analyst = User(username="analista", role=User.Role.ANALYST)

    def test_only_admin_and_operator_manage_associations(self):
        for user in (self.admin, self.operator):
            _check_role(user, associate=True)
        with self.assertRaises(PermissionDenied):
            _check_role(self.analyst, associate=True)

    def test_analyst_may_edit_except_criticality(self):
        _check_role(self.analyst)
        with self.assertRaises(PermissionDenied):
            _check_role(self.analyst, criticality=True)
