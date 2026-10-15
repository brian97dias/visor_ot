"""No-database validation tests for IP exact mode in Interfaces."""

from django.test import SimpleTestCase
from rest_framework.exceptions import ValidationError

from .interface_search import validate_interface_search


class InterfaceSearchTests(SimpleTestCase):
    def test_partial_search_accepts_mac_and_ip_prefixes(self):
        for query in ("192.168.88.1", "00:e0:62", "192.168."):
            with self.subTest(query=query):
                self.assertEqual(
                    validate_interface_search(query, "PARTIAL"),
                    (query, "PARTIAL"),
                )

    def test_exact_ip_rejects_partial_address_and_mac(self):
        for query in ("192.168.88.", "192.168.88.999", "00:e0:62"):
            with self.subTest(query=query):
                with self.assertRaises(ValidationError):
                    validate_interface_search(query, "EXACT_IP")

    def test_exact_ip_accepts_ipv4(self):
        self.assertEqual(
            validate_interface_search(" 192.168.88.1 ", "EXACT_IP"),
            ("192.168.88.1", "EXACT_IP"),
        )

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate_interface_search("192.168.88.1", "INVALID")

    def test_empty_query_is_allowed(self):
        self.assertEqual(validate_interface_search(" ", "EXACT_IP"), ("", "EXACT_IP"))
