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


    def test_ambiguous_ip_shows_assigned_and_unassigned_mac_candidates(self):
        ip = "192.168.88.1"
        unassigned = "b0:99:28:d9:1a:24"
        assigned = ("83", 20, "Westermo Lynx 3643-0105", "SWITCH")
        result = resolve_endpoint(
            ip,
            [observation(7, [MAC_A])],
            "client",
            {(7, ip): {
                MAC_A: (83, 20, assigned[2], assigned[3]),
                unassigned: (116, None, None, None),
            }},
        )
        self.assertEqual(result["status"], "AMBIGUOUS")
        self.assertIsNone(result["identity"])
        self.assertEqual(len(result["candidates"]), 2)
        candidates = {item["mac"]: item for item in result["candidates"]}
        self.assertEqual(candidates[MAC_A]["asset_name"], "Westermo Lynx 3643-0105")
        self.assertIsNone(candidates[unassigned]["asset_id"])
        self.assertEqual(candidates[unassigned]["interface_id"], 116)

    def test_two_macs_for_one_hardware_are_still_ambiguous(self):
        ip = "192.168.88.1"
        result = resolve_endpoint(
            ip, [observation(7, [MAC_A])], "client",
            {(7, ip): {
                MAC_A: IDENTITY_A,
                MAC_B: (113, IDENTITY_A[1], IDENTITY_A[2], IDENTITY_A[3]),
            }},
        )
        self.assertEqual(result["status"], "AMBIGUOUS")
        self.assertEqual(
            {item["asset_id"] for item in result["candidates"]}, {1}
        )
        self.assertEqual(len(result["candidates"]), 2)

    def test_candidates_do_not_include_unrelated_capture_or_ip(self):
        ip = "192.168.88.1"
        result = resolve_endpoint(
            ip, [observation(7, [MAC_A])], "client",
            {
                (7, ip): {MAC_A: IDENTITY_A, MAC_B: None},
                (8, ip): {"b0:99:28:d9:1a:24": IDENTITY_B},
                (7, "192.168.88.2"): {"00:11:22:33:44:55": IDENTITY_B},
            },
        )
        self.assertEqual(result["status"], "AMBIGUOUS")
        self.assertEqual({c["mac"] for c in result["candidates"]}, {MAC_A, MAC_B})

    def test_candidates_on_server_side_and_multiple_active_ingestions(self):
        ip = "192.168.88.1"
        result = resolve_endpoint(
            ip, [observation(7, [MAC_A], "server"),
                 observation(9, [MAC_B], "server")],
            "server",
            {(7, ip): {MAC_A: IDENTITY_A}, (9, ip): {MAC_B: IDENTITY_B}},
        )
        self.assertEqual(result["status"], "AMBIGUOUS")
        self.assertEqual(
            {row["asset_id"] for row in result["candidates"]}, {1, 2}
        )

    def test_missing_or_mismatching_evidence_stays_unknown_without_candidates(self):
        ip = "192.168.88.1"
        for macs, bindings in [
            (None, {MAC_A: IDENTITY_A, MAC_B: IDENTITY_B}),
            ([MAC_A], {MAC_B: IDENTITY_B}),
        ]:
            with self.subTest(macs=macs):
                result = resolve_endpoint(
                    ip, [observation(7, macs)], "client",
                    {(7, ip): bindings},
                )
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertIsNone(result["identity"])
