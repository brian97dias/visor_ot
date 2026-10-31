"""Phase C: authenticated PDF export, access control and read-only behavior."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient

from vulnerabilities.tests_hardening_pdf_diagnosis import diagnosis_fixture


class HardeningReportHttpTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="report-admin", first_name="Ana", last_name="Seguridad",
            role=User.Role.ADMIN,
        )
        self.analyst = User.objects.create_user(
            username="report-analyst", role=User.Role.ANALYST,
        )
        self.operator = User.objects.create_user(
            username="report-operator", role=User.Role.OPERATOR,
        )
        self.client = APIClient()
        self.url = reverse("vulnerabilities:hardening-pdf-download")

    def test_anonymous_cannot_generate_and_collector_is_not_called(self):
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data"
        ) as collect:
            response = self.client.post(self.url)
        self.assertEqual(response.status_code, 401)
        collect.assert_not_called()

    def test_operator_cannot_export_diagnostic_pdf(self):
        self.client.force_authenticate(self.operator)
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data"
        ) as collect:
            response = self.client.post(self.url)
        self.assertEqual(response.status_code, 403)
        collect.assert_not_called()

    def test_admin_generates_pdf_with_security_and_download_headers(self):
        self.client.force_authenticate(self.admin)
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data",
            return_value=diagnosis_fixture(),
        ) as collect:
            response = self.client.post(self.url)
        collect.assert_called_once_with()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response["Content-Disposition"].startswith(
            'attachment; filename="VISOR_OT_diagnostico_'
        ))
        self.assertTrue(response["Content-Disposition"].endswith('.pdf"'))
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertTrue(response.content.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", response.content[-128:])
        self.assertGreater(len(response.content), 3000)

    def test_author_is_derived_from_user_not_client(self):
        self.client.force_authenticate(self.admin)
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data",
            return_value=diagnosis_fixture(),
        ), patch(
            "vulnerabilities.hardening_report_views.render_hardening_pdf"
        ) as renderer:
            renderer.side_effect = lambda report, output, **kwargs: output.write(
                b"%PDF-1.4\n%%EOF\n"
            )
            response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(renderer.call_args.kwargs["author"], "Ana Seguridad")
        self.assertNotIn(b"report-admin", response.content)

    def test_analyst_without_full_name_uses_username(self):
        self.client.force_authenticate(self.analyst)
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data",
            return_value=diagnosis_fixture(),
        ), patch(
            "vulnerabilities.hardening_report_views.render_hardening_pdf"
        ) as renderer:
            renderer.side_effect = lambda report, output, **kwargs: output.write(
                b"%PDF-1.4\n%%EOF\n"
            )
            response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(renderer.call_args.kwargs["author"], "report-analyst")

    def test_malformed_inventory_returns_json_error_not_partial_pdf(self):
        self.client.force_authenticate(self.admin)
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data",
            side_effect=ValidationError({
                "inventory": "Falta criticidad en hardware activo."
            }),
        ) as collect:
            response = self.client.post(self.url)
        collect.assert_called_once_with()
        self.assertEqual(response.status_code, 400)
        self.assertIn("application/json", response["Content-Type"])
        self.assertIn("inventory", response.data)

    def test_invalid_diagnosis_does_not_return_a_partial_pdf(self):
        self.client.force_authenticate(self.admin)
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data",
            return_value=diagnosis_fixture(),
        ), patch(
            "vulnerabilities.hardening_report_views.render_hardening_pdf",
            side_effect=ValueError("Contrato inválido"),
        ):
            response = self.client.post(self.url)
        self.assertEqual(response.status_code, 400)
        self.assertIn("application/json", response["Content-Type"])
        self.assertIn("detail", response.data)

    def test_rejects_client_options_to_prevent_forged_author(self):
        self.client.force_authenticate(self.admin)
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data"
        ) as collect:
            response = self.client.post(
                self.url, {"author": "Nombre suplantado"}, format="json"
            )
        self.assertEqual(response.status_code, 400)
        collect.assert_not_called()

    def test_only_post_generates_pdf(self):
        self.client.force_authenticate(self.admin)
        with patch(
            "vulnerabilities.hardening_report_views.collect_hardening_report_data"
        ) as collect:
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)
        collect.assert_not_called()
