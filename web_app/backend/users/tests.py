from types import SimpleNamespace

from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from ingestion.views import (
    IngestionActivateView,
    IngestionExcludeView,
    PcapAnalyzeView,
    PcapImportView,
)
from network.views import CommunicationClassificationView

from .models import User
from .permissions import IsAdminOrAnalyst


class OTManagementPermissionTests(SimpleTestCase):
    """Permission checks without a PostgreSQL test database."""

    def test_only_admin_and_analyst_can_manage_ot_evidence(self):
        permission = IsAdminOrAnalyst()
        for role, allowed in (
            (User.Role.ADMIN, True),
            (User.Role.ANALYST, True),
            (User.Role.OPERATOR, False),
        ):
            with self.subTest(role=role):
                user = User(username=f"test-{role.lower()}", role=role)
                request = SimpleNamespace(user=user)
                self.assertEqual(
                    permission.has_permission(request, None), allowed
                )

    def test_operator_gets_403_before_mutating_any_resource(self):
        user = User(username="operador-paula", role=User.Role.OPERATOR)
        factory = APIRequestFactory()
        endpoints = [
            (PcapAnalyzeView, "/api/ingestion/pcaps/test/analyze/", {"pcap_id": "test"}, "post"),
            (PcapImportView, "/api/ingestion/pcaps/test/import/", {"pcap_id": "test"}, "post"),
            (IngestionExcludeView, "/api/ingestion/imports/7/exclude/", {"ingestion_id": 7}, "post"),
            (IngestionActivateView, "/api/ingestion/imports/7/activate/", {"ingestion_id": 7}, "post"),
            (
                CommunicationClassificationView,
                "/api/network/communications/1/classification/",
                {"communication_id": 1},
                "patch",
            ),
        ]
        for view, url, kwargs, method in endpoints:
            with self.subTest(url=url):
                request = getattr(factory, method)(url, {}, format="json")
                force_authenticate(request, user=user)
                response = view.as_view()(request, **kwargs)
                self.assertEqual(response.status_code, 403)
