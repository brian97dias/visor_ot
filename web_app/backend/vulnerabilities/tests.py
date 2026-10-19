"""Phase 0 smoke tests: the CPE module is installed but has no public views."""
from django.apps import apps
from django.test import SimpleTestCase
from django.urls import get_resolver
from django.urls.resolvers import URLResolver


class VulnerabilitiesIntegrationTests(SimpleTestCase):
    def test_vulnerabilities_app_is_registered(self):
        app = apps.get_app_config("vulnerabilities")
        self.assertEqual(app.name, "vulnerabilities")

    def test_vulnerabilities_api_namespace_is_registered(self):
        routes = [
            route for route in get_resolver().url_patterns
            if isinstance(route, URLResolver)
        ]
        self.assertTrue(any(
            str(route.pattern) == "api/vulnerabilities/"
            and route.namespace == "vulnerabilities"
            for route in routes
        ))
