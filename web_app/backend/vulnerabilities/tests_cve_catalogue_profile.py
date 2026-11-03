"""Profiler guardrails: real DRF view, SQL timings, no DB mutations/NVD calls."""
from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from users.models import User
from vulnerabilities.models import Cve


class CveCatalogueProfileTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="profile-analista", role=User.Role.ANALYST,
        )
        self.cve = Cve.objects.create(
            cve_id="CVE-2026-87654",
            fetch_status=Cve.FetchStatus.COMPLETED,
            description="Descripción de prueba",
            retrieved_at=timezone.now(),
            configurations=[],
        )

    def test_profile_reports_endpoint_phase_count_sql_and_does_not_write(self):
        before = list(Cve.objects.values_list(
            "pk", "cve_id", "fetch_status"
        ))
        out = StringIO()
        call_command(
            "profile_cve_catalogue", "--username", self.user.username,
            "--runs", "1", "--slow-sql", "0",
            stdout=out,
        )
        output = out.getvalue()
        self.assertIn("Ejecución 1:", output)
        self.assertIn("consultas SQL", output)
        self.assertIn("1 CVE oficiales", output)
        self.assertIn("proyeccion_hardware_cve", output)
        self.assertIn("recalculo_indicadores", output)
        self.assertIn("1 pasada de proyección hardware-CVE", output)
        self.assertIn("Mediana de 1 ejecución(es)", output)
        self.assertEqual(
            list(Cve.objects.values_list("pk", "cve_id", "fetch_status")),
            before,
        )

    def test_search_filter_profiling_keeps_api_result_scoped(self):
        out = StringIO()
        call_command(
            "profile_cve_catalogue", "--username", self.user.username,
            "--runs", "1", "--q", "noexiste",
            "--status", "PENDING_REVIEW", "--slow-sql", "0",
            stdout=out,
        )
        output = out.getvalue()
        self.assertIn("0 evaluaciones filtradas", output)
        self.assertIn("1 CVE oficiales", output)
        self.assertIn("busqueda_por_activo", output)

    def test_refuses_nonexistent_user_and_out_of_range_repeats(self):
        with self.assertRaises(CommandError):
            call_command(
                "profile_cve_catalogue", "--username", "does-not-exist",
                "--runs", "1", stdout=StringIO(),
            )
        with self.assertRaises(CommandError):
            call_command(
                "profile_cve_catalogue", "--username", self.user.username,
                "--runs", "0", stdout=StringIO(),
            )
