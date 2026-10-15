"""Pure endpoint resolution checks; no PostgreSQL test database required."""

from django.test import SimpleTestCase

from .endpoint_resolution import resolve_endpoint


MAC_A = "00:e0:62:00:17:0a"
MAC_B = "28:cf:e9:18:b5:ed"
IDENTITY_A = (112, 1, "DirectLogic 205", "PLC")
IDENTITY_B = (89, 2, "Otro equipo", "HMI")


def observation(ingestion_id, macs, side="client"):
    return {
        "ingestion_id": ingestion_id,
        "client_macs": macs if side == "client" else None,
        "server_macs": macs if side == "server" else None,
    }


class EndpointResolutionTests(SimpleTestCase):
    def test_identifies_hardware_with_capture_binding(self):
        result = resolve_endpoint(
            "192.168.88.15",
            [observation(7, [MAC_A])],
            "client",
            {(7, "192.168.88.15"): {MAC_A: IDENTITY_A}},
        )
        self.assertEqual(result["status"], "IDENTIFIED")
        self.assertEqual(result["identity"]["asset_name"], "DirectLogic 205")
        self.assertEqual(result["identity"]["interface_id"], 112)

    def test_same_mac_can_have_multiple_ips(self):
        bindings = {
            (7, "192.168.88.15"): {MAC_A: IDENTITY_A},
            (7, "192.168.88.16"): {MAC_A: IDENTITY_A},
        }
        for ip in ("192.168.88.15", "192.168.88.16"):
            with self.subTest(ip=ip):
                result = resolve_endpoint(
                    ip, [observation(7, [MAC_A])], "client", bindings
                )
                self.assertEqual(result["status"], "IDENTIFIED")

    def test_requires_mac_from_relevant_capture(self):
        result = resolve_endpoint(
            "192.168.88.15",
            [observation(7, [MAC_A])],
            "client",
            {(5, "192.168.88.15"): {MAC_A: IDENTITY_A}},
        )
        self.assertEqual(result["status"], "UNKNOWN")

    def test_multiple_macs_for_same_ip_are_ambiguous(self):
        result = resolve_endpoint(
            "192.168.88.15",
            [observation(7, [MAC_A])],
            "client",
            {(7, "192.168.88.15"): {
                MAC_A: IDENTITY_A, MAC_B: IDENTITY_B,
            }},
        )
        self.assertEqual(result["status"], "AMBIGUOUS")
        self.assertIsNone(result["identity"])

    def test_conflicting_active_ingestions_are_ambiguous(self):
        result = resolve_endpoint(
            "192.168.88.15",
            [observation(5, [MAC_B]), observation(7, [MAC_A])],
            "client",
            {
                (5, "192.168.88.15"): {MAC_B: IDENTITY_B},
                (7, "192.168.88.15"): {MAC_A: IDENTITY_A},
            },
        )
        self.assertEqual(result["status"], "AMBIGUOUS")

    def test_unknown_mac_or_unassigned_interface_stays_ip(self):
        cases = [
            ([observation(7, None)], {}),
            ([observation(7, [MAC_A])], {(7, "192.168.88.15"): {MAC_A: None}}),
            ([observation(7, [MAC_A])], {
                (7, "192.168.88.15"): {MAC_A: (112, None, None, None)}
            }),
        ]
        for evidence, bindings in cases:
            with self.subTest(evidence=evidence, bindings=bindings):
                result = resolve_endpoint(
                    "192.168.88.15", evidence, "client", bindings
                )
                self.assertEqual(result["status"], "UNKNOWN")

    def test_mismatching_mac_is_not_attributed(self):
        result = resolve_endpoint(
            "192.168.88.15",
            [observation(7, [MAC_B])],
            "client",
            {(7, "192.168.88.15"): {MAC_A: IDENTITY_A}},
        )
        self.assertEqual(result["status"], "UNKNOWN")

    def test_server_endpoint_uses_server_macs(self):
        result = resolve_endpoint(
            "192.168.88.15",
            [observation(7, [MAC_A], "server")],
            "server",
            {(7, "192.168.88.15"): {MAC_A: IDENTITY_A}},
        )
        self.assertEqual(result["status"], "IDENTIFIED")
