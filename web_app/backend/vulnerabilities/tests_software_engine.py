"""Phase 2: automatic SOFTWARE CPE discovery via existing worker/snapshots.

All NVD responses are synthetic. These tests make no external requests.
"""
from uuid import uuid5, NAMESPACE_DNS

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from assets.models import Asset, Software
from vulnerabilities.models import AssetCpe, AssetCpeDecision, CpeQuerySnapshot
from vulnerabilities.services.candidate_matching import (
    normalize_candidate, is_manufacturer_related, is_pertinent,
)
from vulnerabilities.services.cpe_catalogue import (
    canonical_query, execute_catalogue_snapshot,
)
from vulnerabilities.services.cpe_search import create_run, execute_run, serialize_run
from vulnerabilities.services.cpe_validation import decide, current_identity
from vulnerabilities.services.identity import software_identity, fingerprint


def nvd(product="ios", version="12.1\\(22\\)ea14", *, part="o", vendor="cisco"):
    name = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return {"cpe": {
        "cpeNameId": str(uuid5(NAMESPACE_DNS, "test-software-cpe:" + name)),
        "cpeName": name,
        "deprecated": False,
        "titles": [{"lang": "en", "title": f"Cisco {product} {version}"}],
        "refs": [{"ref": "https://example.org/cisco/ios", "type": "Product"}],
    }}


def page(rows, *, start=0, total=None):
    return {"products": rows, "totalResults": len(rows) if total is None else total,
            "startIndex": start}


class SoftwareMatchingTests(SimpleTestCase):
    identity = {"asset_type": "SOFTWARE", "software_type": "OS",
                "manufacturer": "Cisco", "product": "IOS", "version": "12.1"}

    def test_canonical_software_queries_preserve_version_and_escaped_parentheses(self):
        for q in (
            "cpe:2.3:o:cisco:ios:12.1",
            "cpe:2.3:o:cisco:ios:12.1*",
            "cpe:2.3:o:cisco:ios:*",
            r"cpe:2.3:o:cisco:ios:12.1\(22\)ea14",
            "cpe:2.3:a:cisco:ios:*",
            "cpe:2.3:h:siemens:*",
        ):
            self.assertEqual(canonical_query("cpeMatchString", q)[1], q)
        for invalid in (
            "cpe:2.3:o:cisco:ios:12.1:garbage", "cpe:2.3:x:cisco:ios:*",
            "cpe:2.3:o:cisco:ios:12.1&other=x",
        ):
            with self.subTest(parameter=invalid), self.assertRaises(ValueError):
                canonical_query("cpeMatchString", invalid)

    def test_matching_exact_branch_other_and_related_product(self):
        entries = [
            (nvd(version="12.1"), "SOFTWARE_EXACT", True),
            (nvd(version=r"12.1\(22\)ea14"), "SOFTWARE_BRANCH", False),
            (nvd(version="12.10"), "SOFTWARE_PRODUCT", False),
            (nvd(version="-"), "SOFTWARE_PRODUCT", False),
            (nvd(product="ios_xe", version="12.1"), "EXPLORATORY", False),
            (nvd(part="h"), None, False),
            (nvd(vendor="other"), "POSSIBLE_INCOMPATIBILITY", False),
        ]
        for record, expected, exact in entries:
            with self.subTest(cpe=record["cpe"]["cpeName"]):
                row = normalize_candidate(record, self.identity, "cpeMatchString")
                self.assertEqual(row["match_level"] if row else None, expected)
                if row is not None:
                    self.assertEqual(is_pertinent(row, self.identity), exact)
                    self.assertEqual(
                        is_manufacturer_related(row, self.identity),
                        expected not in ("POSSIBLE_INCOMPATIBILITY",),
                    )

    def test_version_change_invalidates_identity_fingerprint(self):
        self.assertNotEqual(
            fingerprint(self.identity),
            fingerprint({**self.identity, "version": "12.10"}),
        )


class SoftwareWorkerTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="ios-analyst", role=User.Role.ANALYST
        )
        self.asset = Asset.objects.create(
            name="Cisco IOS Catalyst 2955", asset_type=Asset.AssetType.SOFTWARE,
            created_by=self.analyst, updated_by=self.analyst,
        )
        Software.objects.create(
            asset=self.asset, software_type=Software.SoftwareType.OS,
            manufacturer="Cisco", product="IOS", version="12.1",
        )

    def new_run(self):
        return create_run(self.asset.pk, self.analyst, "SPECIFIC")

    def test_branch_snapshot_discovers_cisco_ios_without_claiming_exact_version(self):
        run = self.new_run()
        self.assertEqual(run.identity_snapshot, software_identity(self.asset))
        requested = []
        def fetch(strategy, parameter, start, pacer):
            requested.append(parameter)
            return page([])
        queued = execute_run(run, object(), fetcher=fetch)
        self.assertEqual(queued.status, "QUEUED")
        self.assertEqual(requested, ["cpe:2.3:o:cisco:ios:12.1"])
        snapshot = CpeQuerySnapshot.objects.get()
        self.assertEqual(snapshot.cache.parameter, "cpe:2.3:o:cisco:ios:12.1*")
        self.assertEqual(snapshot.status, "QUEUED")
        products = [nvd(version=r"12.1\(22\)ea14"), nvd(version="12.10"),
                    nvd(part="h")]
        execute_catalogue_snapshot(snapshot, object(),
            fetcher=lambda strategy, parameter, start, pacer, *, results_per_page:
            page(products, start=start)
        )
        completed = execute_run(queued, object(), fetcher=lambda *args:
                                self.fail("No repetir una consulta NVD completada"))
        self.assertEqual(completed.status, "COMPLETED")
        self.assertFalse(completed.result_truncated)
        self.assertEqual(len(completed.candidates), 1)
        candidate = completed.candidates[0]
        self.assertEqual(candidate["match_level"], "SOFTWARE_BRANCH")
        self.assertIn("12.1", candidate["match_reason"])
        self.assertEqual(candidate["discovery_levels"], ["FAMILY"])
        self.assertEqual(serialize_run(completed)["candidate_count"], 1)
        self.assertTrue(serialize_run(completed)["identity_is_current"])
        self.assertFalse(AssetCpe.objects.exists())
        self.assertFalse(AssetCpeDecision.objects.exists())

        # Same completed snapshot is reused when a later run is explicitly queued.
        another = self.new_run()
        finished = execute_run(another, object(), fetcher=fetch)
        self.assertEqual(finished.status, "COMPLETED")
        self.assertEqual(CpeQuerySnapshot.objects.count(), 1)
        self.assertEqual(finished.candidates[0]["cpe_name_id"], candidate["cpe_name_id"])

    def test_version_exact_stops_before_product_catalogue(self):
        run = self.new_run()
        complete = nvd(version="12.1")
        result = execute_run(run, object(), fetcher=lambda *args: page([complete]))
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(result.candidates[0]["match_level"], "SOFTWARE_EXACT")
        self.assertEqual(len(result.queries), 1)
        self.assertFalse(CpeQuerySnapshot.objects.exists())
        self.assertFalse(AssetCpe.objects.exists())

    def test_product_catalogue_filters_large_other_version_list(self):
        run = self.new_run()
        empty = lambda *args: page([])
        pending = execute_run(run, object(), fetcher=empty)
        first = CpeQuerySnapshot.objects.get()
        execute_catalogue_snapshot(
            first, object(), fetcher=lambda s, p, i, pacer, *, results_per_page:
            page([nvd(version="12.10")], start=i),
        )
        pending = execute_run(pending, object(), fetcher=empty)
        self.assertEqual(pending.status, "QUEUED")
        prod_snapshot = CpeQuerySnapshot.objects.exclude(pk=first.pk).get()
        self.assertEqual(prod_snapshot.cache.parameter, "cpe:2.3:o:cisco:ios:*")
        versions = [nvd(version=f"15.{i}") for i in range(23)]
        versions += [nvd(part="h", version="12.1")]
        execute_catalogue_snapshot(
            prod_snapshot, object(),
            fetcher=lambda s, p, i, pacer, *, results_per_page:
            page(versions, start=i),
        )
        finished = execute_run(pending, object(), fetcher=empty)
        self.assertEqual(finished.status, "COMPLETED")
        self.assertEqual(CpeQuerySnapshot.objects.count(), 2)
        self.assertEqual(sum(c["match_level"] == "SOFTWARE_PRODUCT"
                             for c in finished.candidates), 5)
        self.assertTrue(all(c["cpe_type"] == "o" for c in finished.candidates))
        self.assertLessEqual(len(finished.candidates), 5)
        self.assertFalse(finished.result_truncated)

    def test_review_creates_only_explicit_audited_software_decision(self):
        run = self.new_run()
        row = nvd(version="12.1")
        completed = execute_run(run, object(), fetcher=lambda *args: page([row]))
        data = {
            "run_id": completed.pk, "cpe_name_id": row["cpe"]["cpeNameId"],
            "status": "CONFIRMED",
            "justification": "Revisión manual del CPE de software",
        }
        association = decide(self.asset.pk, self.analyst, data)
        self.assertEqual(association.validation_status, "CONFIRMED")
        self.assertEqual(AssetCpeDecision.objects.count(), 1)
        self.assertEqual(current_identity(self.asset),
                         association.validated_identity_fingerprint)
        software = self.asset.software
        software.version = "12.10"
        software.save()
        self.assertNotEqual(current_identity(self.asset),
                            association.validated_identity_fingerprint)
        # Simulate a new HTTP read instead of relying on the related-object
        # cache of the run instance that queued the original discovery.
        completed.refresh_from_db()
        self.assertFalse(serialize_run(completed)["identity_is_current"])
