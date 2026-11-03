"""Safety checks for targeted lab reset.

SQLite can test preview and guard behavior. Real PostgreSQL TRUNCATE behavior
must be verified separately against a disposable database, never production.
"""
from io import StringIO

from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TestCase

from assets.management.commands.reset_lab_data import (
    CONFIRMATION_PHRASE, LAB_APPS, lab_models,
)
from assets.models import OTSystem


class ResetLabDataTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="keep-lab-admin", password="NotARealProductionPassword",
        )

    def test_allowlist_has_all_four_lab_apps_and_no_user_table(self):
        selected = lab_models()
        included_labels = {model._meta.app_label for model in selected.values()}
        self.assertEqual(included_labels, set(LAB_APPS))
        self.assertTrue(all(
            table.startswith(f"{model._meta.app_label}_")
            for table, model in selected.items()
        ))
        self.assertNotIn(get_user_model()._meta.db_table, selected)
        self.assertTrue(any(model is OTSystem for model in selected.values()))
        self.assertNotIn("django_migrations", selected)
        self.assertNotIn("django_session", selected)

    def test_preview_does_not_delete_users_or_ot_system(self):
        system = OTSystem.objects.create(
            name="Sistema de prueba", description="Temporal",
            criticality="HIGH", created_by=self.user,
        )
        output = StringIO()
        call_command("reset_lab_data", stdout=output)
        result = output.getvalue()
        self.assertIn("VISTA PREVIA", result)
        self.assertIn("Usuarios que se conservarán: 1", result)
        self.assertIn("assets_otsystem: 1", result)
        self.assertTrue(get_user_model().objects.filter(pk=self.user.pk).exists())
        self.assertTrue(OTSystem.objects.filter(pk=system.pk).exists())

    def test_execute_without_confirmations_does_not_touch_data(self):
        system = OTSystem.objects.create(
            name="Sistema conservado", description="Temporal",
            criticality="HIGH",
        )
        with self.assertRaises(CommandError):
            call_command(
                "reset_lab_data", "--execute",
                "--confirm-database", "no-autorizada",
                "--confirm", CONFIRMATION_PHRASE,
                "--backup-confirmed", stdout=StringIO(),
            )
        self.assertTrue(get_user_model().objects.filter(pk=self.user.pk).exists())
        self.assertTrue(OTSystem.objects.filter(pk=system.pk).exists())

    def test_execute_is_blocked_on_sqlite_even_with_confirmations(self):
        if connection.vendor != "sqlite":
            self.skipTest("Protection specific to SQLite test settings.")
        with self.assertRaisesMessage(CommandError, "PostgreSQL"):
            call_command(
                "reset_lab_data", "--execute",
                "--confirm-database", str(connection.settings_dict["NAME"]),
                "--confirm", CONFIRMATION_PHRASE,
                "--backup-confirmed", stdout=StringIO(),
            )
        self.assertTrue(get_user_model().objects.filter(pk=self.user.pk).exists())
