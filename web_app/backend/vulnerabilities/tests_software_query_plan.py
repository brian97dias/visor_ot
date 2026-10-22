"""Phase 1 only: software CPE identity and pure query planning, no worker/I/O."""
from copy import deepcopy
from types import SimpleNamespace

from django.test import SimpleTestCase
from assets.models import Asset

from vulnerabilities.services.identity import (
    software_identity, hardware_identity, build_cpe_match_plan,
    build_software_cpe_match_plan, build_alternative_keyword_plan,
    software_numeric_model, software_numeric_prefixes,
    software_short_series_model, software_short_series_prefixes,
    fingerprint, software_version_in_branch,
)
from vulnerabilities.tests_query_plan import SIEMENS, ADAM, ROCKWELL


def ios(version="12.1", product="IOS"):
    return {
        "asset_type": "SOFTWARE",
        "software_type": "OS",
        "manufacturer": "Cisco",
        "product": product,
        "version": version,
    }


class SoftwareCpePlanPhase1Tests(SimpleTestCase):
    def test_cisco_software_identity_reads_only_inventory_software_fields(self):
        asset = SimpleNamespace(
            asset_type=Asset.AssetType.SOFTWARE,
            name="Cisco IOS Catalyst 2955",
            software=SimpleNamespace(software_type="OS", manufacturer=" Cisco ",
                                     product=" Cisco IOS ", version=" 12.1 "),
        )
        self.assertEqual(software_identity(asset), ios(product="Cisco IOS"))
        with self.assertRaises(ValueError):
            hardware_identity(asset)

    def test_ios_12_1_specific_branch_product_manufacturer_order(self):
        original = ios()
        frozen = deepcopy(original)
        plan = build_software_cpe_match_plan(original)
        self.assertEqual(
            [(row["level"], row["parameter"], row["version_scope"]) for row in plan],
            [
                ("SPECIFIC", "cpe:2.3:o:cisco:ios:12.1", "RECORDED_VERSION"),
                ("FAMILY", "cpe:2.3:o:cisco:ios:12.1*", "BRANCH_PREFIX"),
                ("FAMILY", "cpe:2.3:o:cisco:ios:*", "PRODUCT_CATALOGUE"),
                ("MANUFACTURER", "cpe:2.3:o:cisco:*", "MANUFACTURER_CATALOGUE"),
            ],
        )
        self.assertEqual([r["requires_local_version_filter"] for r in plan],
                         [False, True, True, True])
        self.assertTrue(all(r["strategy"] == "cpeMatchString" for r in plan))
        self.assertEqual(original, frozen)

    def test_inventoried_cisco_ios_and_ios_produce_same_cpe_plan(self):
        self.assertEqual(
            build_software_cpe_match_plan(ios(product="Cisco IOS")),
            build_software_cpe_match_plan(ios(product="IOS")),
        )

    def test_cisco_branch_requires_delimited_version_not_12_10(self):
        self.assertTrue(software_version_in_branch("12.1", "12.1"))
        self.assertTrue(software_version_in_branch("12.1", r"12.1\(22\)ea14"))
        self.assertTrue(software_version_in_branch("12.1", "12.1(22)EA14"))
        self.assertTrue(software_version_in_branch("12.1", "12.1a"))
        self.assertFalse(software_version_in_branch("12.1", "12.10"))
        self.assertFalse(software_version_in_branch("12.1", "12.11"))
        self.assertTrue(software_version_in_branch("12.1", "12.1.00"))

    def test_full_cisco_version_escape_is_preserved_and_not_truncated(self):
        plan = build_software_cpe_match_plan(ios(version="12.1(22)EA14"))
        self.assertEqual(plan[0]["parameter"],
                         r"cpe:2.3:o:cisco:ios:12.1\(22\)ea14")
        self.assertNotIn("BRANCH_PREFIX", [p["version_scope"] for p in plan])
        self.assertIn("cpe:2.3:o:cisco:ios:*", [p["parameter"] for p in plan])

    def test_unknown_version_does_not_guess_or_infer_hardware_version(self):
        plan = build_software_cpe_match_plan(ios(version=""))
        self.assertEqual([p["parameter"] for p in plan],
                         ["cpe:2.3:o:cisco:ios:*", "cpe:2.3:o:cisco:*"])
        self.assertTrue(all(p["requires_local_version_filter"] for p in plan))

    def test_cpe_part_from_software_type_only(self):
        for software_type, expected in (
            ("OS", ":o:"), ("FIRMWARE", ":o:"), ("APPLICATION", ":a:"),
        ):
            with self.subTest(kind=software_type):
                plan = build_software_cpe_match_plan({
                    **ios(), "software_type": software_type,
                })
                self.assertTrue(all(expected in p["parameter"] for p in plan))

    def test_validation_blocks_unsafe_versions_and_invalid_identity(self):
        invalid = [
            {**ios(), "asset_type": "HARDWARE"},
            {**ios(), "software_type": "UNKNOWN"},
            {**ios(), "manufacturer": "!!!"},
            {**ios(), "product": "IOS;injection"},
            {**ios(), "version": "12.1:*"},
            {**ios(), "version": "12.1\nbad"},
            {**ios(), "version": ["12.1"]},
        ]
        for identity in invalid:
            with self.subTest(identity=identity):
                with self.assertRaises(ValueError):
                    build_software_cpe_match_plan(identity)

    def test_advantech_adam_model_gets_fallback_to_product_series(self):
        identity = {
            "asset_type": "SOFTWARE", "software_type": "FIRMWARE",
            "manufacturer": "Advantech", "product": "ADAM-5510", "version": "",
        }
        plan = build_software_cpe_match_plan(identity)
        params = [q["parameter"] for q in plan]
        self.assertIn("cpe:2.3:o:advantech:adam-5510:*", params)
        self.assertIn("cpe:2.3:o:advantech:adam*", params)
        self.assertLess(params.index("cpe:2.3:o:advantech:adam-5510:*"),
                        params.index("cpe:2.3:o:advantech:adam*"))
        self.assertLess(params.index("cpe:2.3:o:advantech:adam*"),
                        params.index("cpe:2.3:o:advantech:*"))
        series_query = next(q for q in plan
                            if q["parameter"] == "cpe:2.3:o:advantech:adam*")
        self.assertEqual(series_query["level"], "FAMILY")
        self.assertEqual(series_query["version_scope"], "RELATED_SERIES")
        self.assertTrue(series_query["requires_local_version_filter"])
        self.assertEqual(plan, build_software_cpe_match_plan(identity))

    def test_axis_206_firmware_has_bounded_numeric_prefixes_in_priority_order(self):
        identity = {
            "asset_type": "SOFTWARE", "software_type": "OS",
            "manufacturer": "Axis Communications",
            "product": "AXIS 206 Firmware", "version": "",
        }
        self.assertEqual(software_numeric_model("AXIS 206 Firmware", "Axis Communications"), "206")
        self.assertEqual(
            software_numeric_prefixes("AXIS 206 Firmware", "Axis Communications"),
            ["206*", "20*"],
        )
        plan = build_software_cpe_match_plan(identity)
        parameters = [query["parameter"] for query in plan]
        self.assertIn("cpe:2.3:o:axis:206_firmware:*", parameters)
        self.assertIn("cpe:2.3:o:axis:206*", parameters)
        self.assertIn("cpe:2.3:o:axis:20*", parameters)
        self.assertIn("cpe:2.3:o:axis:*", parameters)
        self.assertLess(
            parameters.index("cpe:2.3:o:axis:206_firmware:*"),
            parameters.index("cpe:2.3:o:axis:206*"),
        )
        self.assertLess(
            parameters.index("cpe:2.3:o:axis:206*"),
            parameters.index("cpe:2.3:o:axis:20*"),
        )
        self.assertLess(
            parameters.index("cpe:2.3:o:axis:20*"),
            parameters.index("cpe:2.3:o:axis:*"),
        )
        numeric = [q for q in plan if q.get("version_scope") == "NUMERIC_MODEL_PREFIX"]
        self.assertEqual(len(numeric), 8)
        self.assertTrue(all(q["level"] == "FAMILY" for q in numeric))
        self.assertTrue(all(q["requires_local_version_filter"] for q in numeric))
        self.assertEqual(plan, build_software_cpe_match_plan(identity))

    def test_numeric_firmware_plan_never_guesses_numbers_from_unrelated_software(self):
        self.assertEqual(software_numeric_model("Cisco IOS 12.1", "Cisco"), "")
        self.assertEqual(software_numeric_model("AXIS 2060 Camera", "Axis Communications"), "")
        self.assertEqual(software_numeric_model("AXIS 206 Firmware 2.1", "Axis Communications"), "")
        self.assertEqual(software_numeric_prefixes("AXIS 206 Firmware", "Unrelated Vendor"), [])
        self.assertNotIn(
            "NUMERIC_MODEL_PREFIX",
            [q["version_scope"] for q in build_software_cpe_match_plan(ios())],
        )

    def test_phoenix_fl_firmware_reuses_progressive_hardware_short_series(self):
        inventory = {
            "asset_type": "SOFTWARE", "software_type": "OS",
            "manufacturer": "Phoenix Contact",
            "product": "FL IL 24 BK PAC Firmware", "version": "",
        }
        self.assertEqual(
            software_short_series_model(inventory["product"], inventory["manufacturer"]),
            "fl_il_24_bk_pac",
        )
        self.assertEqual(
            software_short_series_prefixes(inventory["product"], inventory["manufacturer"]),
            ["fl_il_24*", "fl_il*", "fl_*"],
        )
        plan = build_software_cpe_match_plan(inventory)
        params = [step["parameter"] for step in plan]
        expected = [
            "cpe:2.3:o:phoenixcontact:fl_il_24_bk_pac_firmware:*",
            "cpe:2.3:o:phoenixcontact:fl_il_24*",
            "cpe:2.3:o:phoenixcontact:fl_il*",
            "cpe:2.3:o:phoenixcontact:fl_*",
            "cpe:2.3:o:phoenixcontact:*",
        ]
        for param in expected:
            self.assertIn(param, params)
        self.assertEqual(
            [params.index(p) for p in expected],
            sorted(params.index(p) for p in expected),
        )
        self.assertTrue(
            all(step["version_scope"] == "SHORT_SERIES_PREFIX"
                and step["level"] == "FAMILY" and step["requires_local_version_filter"]
                for step in plan
                if step["parameter"].startswith("cpe:2.3:o:phoenixcontact:fl_")
                and step["parameter"] in expected[1:4])
        )
        self.assertEqual(plan, build_software_cpe_match_plan(inventory))

    def test_short_series_is_not_inferred_from_generic_software_or_short_names(self):
        self.assertEqual(software_short_series_prefixes("IOS", "Cisco"), [])
        self.assertEqual(software_short_series_prefixes("FL", "Phoenix Contact"), [])
        self.assertEqual(software_short_series_prefixes("FL IL 24 BK PAC", "Phoenix Contact"), [])
        self.assertEqual(software_short_series_prefixes("Fluffy 24 BK Firmware",
                                                       "Phoenix Contact"), [])
        self.assertNotIn(
            "SHORT_SERIES_PREFIX",
            [p["version_scope"] for p in build_software_cpe_match_plan(ios())],
        )

    def test_software_series_fallback_is_not_generated_for_generic_products(self):
        self.assertNotIn("RELATED_SERIES", [
            step["version_scope"] for step in build_software_cpe_match_plan(ios())
        ])
        self.assertNotIn("RELATED_SERIES", [
            step["version_scope"] for step in build_software_cpe_match_plan(
                {**ios(), "product": "IOS-XE"}
            )
        ])

    def test_software_short_vendor_has_keyword_fallback_after_structured_plan(self):
        identity = {
            "asset_type": "SOFTWARE", "software_type": "FIRMWARE",
            "manufacturer": "ATC", "product": "ATC-1200 Firmware", "version": "",
        }
        self.assertEqual(
            build_alternative_keyword_plan(identity),
            [
                {"level": "ALTERNATIVE", "strategy": "keywordSearch",
                 "parameter": "ATC ATC-1200 Firmware"},
                {"level": "ALTERNATIVE", "strategy": "keywordSearch",
                 "parameter": "ATC"},
            ],
        )
        structured = build_software_cpe_match_plan(identity)
        self.assertTrue(all(
            step["strategy"] == "cpeMatchString" for step in structured
        ))
        self.assertEqual(structured[-1]["parameter"], "cpe:2.3:o:atc:*")

    def test_software_alternative_query_does_not_change_hardware_or_cisco(self):
        hardware = {"asset_type": "HARDWARE",
                    "manufacturer": "ATC", "model": "ATC-1200"}
        self.assertEqual(build_alternative_keyword_plan(hardware), [])
        self.assertEqual(
            [step["parameter"] for step in build_alternative_keyword_plan(ios())],
            ["Cisco IOS", "Cisco"],
        )
        invalid = {**ios(), "manufacturer": "ATC", "product": "Firmware&token"}
        self.assertEqual(build_alternative_keyword_plan(invalid), [])

    def test_hardware_plans_and_fingerprints_remain_stable(self):
        for device in (SIEMENS, ADAM, ROCKWELL):
            self.assertEqual(build_cpe_match_plan(device),
                             build_cpe_match_plan(deepcopy(device)))
            self.assertEqual(fingerprint(device), fingerprint(deepcopy(device)))
        self.assertNotEqual(fingerprint(ios(version="12.1")),
                            fingerprint(ios(version="12.10")))
        self.assertNotEqual(fingerprint(ios(version="12.1")),
                            fingerprint(ios(version="121")))
