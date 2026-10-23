"""Generic NVD CVE 2.0 pagination and ingestion; no external network."""
import copy
import json
from decimal import Decimal
from io import BytesIO
from urllib.error import URLError
from urllib.parse import parse_qs, urlparse
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from vulnerabilities.models import (
    AssetCpe, AssetCveAssessment, AssetCveFinding, Cpe, Cve,
)
from vulnerabilities.services.nvd_client import NvdError
from vulnerabilities.services.nvd_cve_client import (
    CVE_RESULTS_PAGE_SIZE, NVD_CVE_URL,
    fetch_cves_by_cpe, iter_cve_pages_by_cpe, validated_cve_page,
)
from vulnerabilities.services.cve_ingestion import (
    CveResponseError, store_official_cve_record, validated_cve_record,
)

CPE_HARDWARE = "cpe:2.3:h:phoenixcontact:il_pn_bk-pac:-:*:*:*:*:*:*:*"


def record(cve_id="CVE-2024-65432"):
    return {
        "id": cve_id,
        "published": "2024-01-10T10:00:00.000",
        "lastModified": "2024-11-10T10:00:00.000",
        "descriptions": [{"lang": "en", "value": "An example vulnerability."}],
        "metrics": {"cvssMetricV31": [{
            "type": "Primary",
            "cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"},
        }]},
        "configurations": [{"operator": "AND", "negate": False, "nodes": [
            {"operator": "OR", "cpeMatch": [
                {"criteria": CPE_HARDWARE, "vulnerable": False,
                 "versionStartIncluding": "1.0"},
            ]},
            {"operator": "OR", "cpeMatch": [
                {"criteria": "cpe:2.3:o:other:firmware:*:*:*:*:*:*:*:*",
                 "vulnerable": True},
            ]},
        ]}],
        "references": [{"url": "https://example.org/advisory"}],
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
    }


def page(records, *, start=0, total=None, size=500):
    return {
        "resultsPerPage": size,
        "startIndex": start,
        "totalResults": len(records) if total is None else total,
        "vulnerabilities": [{"cve": row} for row in records],
    }


class NvdGenericCveClientTests(SimpleTestCase):
    def test_uses_cpe_name_without_vulnerable_filter_and_shares_pacer(self):
        payload = page([record()], size=20)
        pacer = Mock()
        with patch("vulnerabilities.services.nvd_cve_client.urlopen",
                   return_value=BytesIO(json.dumps(payload).encode("utf-8"))) as fetch:
            actual = fetch_cves_by_cpe(CPE_HARDWARE, 0, pacer, results_per_page=20)
        self.assertEqual(actual, payload)
        request = fetch.call_args.args[0]
        self.assertEqual(urlparse(request.full_url).scheme, "https")
        self.assertEqual(request.full_url.split("?")[0], NVD_CVE_URL)
        params = parse_qs(urlparse(request.full_url).query)
        self.assertEqual(params, {"cpeName": [CPE_HARDWARE],
                                  "startIndex": ["0"], "resultsPerPage": ["20"]})
        self.assertEqual(pacer.pace.call_count, 1)
        self.assertEqual(fetch.call_args.kwargs["timeout"], 20)

    def test_rejects_invalid_cpe_or_page_request_without_network(self):
        for cpe in (None, "", "cpe:2.3:*:vendor:product:*",
                    "cpe:2.3:h:*:product:*:*:*:*:*:*:*:*", "random"):
            with self.subTest(cpe=cpe), self.assertRaises(ValueError):
                fetch_cves_by_cpe(cpe, 0, Mock())
        for index, size in ((-1, 500), (True, 500), (0, 0),
                            (0, 2001), (0, True), (1.5, 50)):
            with self.subTest(index=index, size=size), self.assertRaises(ValueError):
                fetch_cves_by_cpe(CPE_HARDWARE, index, Mock(),
                                  results_per_page=size)

    def test_retries_use_same_pacer_without_claiming_empty_results(self):
        pacer = Mock()
        with patch("vulnerabilities.services.nvd_cve_client.urlopen",
                   side_effect=URLError("offline")):
            with self.assertRaises(NvdError):
                fetch_cves_by_cpe(CPE_HARDWARE, 0, pacer)
        self.assertEqual(pacer.pace.call_count, 2)

    def test_two_pages_resume_using_returned_next_index(self):
        first = page([record("CVE-2024-65432"),
                      record("CVE-2024-65433")], total=3, size=2)
        second = page([record("CVE-2024-65434")], start=2, total=3, size=2)
        mock_fetch = Mock(side_effect=[first, second])
        result = list(iter_cve_pages_by_cpe(
            CPE_HARDWARE, Mock(), results_per_page=2, fetcher=mock_fetch
        ))
        self.assertEqual([p["next_start_index"] for p in result], [2, 3])
        self.assertEqual([p["complete"] for p in result], [False, True])
        self.assertEqual([len(p["records"]) for p in result], [2, 1])
        self.assertEqual([call.args[1] for call in mock_fetch.call_args_list], [0, 2])

    def test_checkpoint_resume_starts_from_saved_offset(self):
        returned = page([record()], start=4, total=5, size=2)
        fetch = Mock(return_value=returned)
        items = list(iter_cve_pages_by_cpe(
            CPE_HARDWARE, Mock(), start_index=4,
            results_per_page=2, fetcher=fetch
        ))
        self.assertEqual(items[0]["next_start_index"], 5)
        self.assertTrue(items[0]["complete"])
        self.assertEqual(fetch.call_args.args[1], 4)

    def test_zero_results_is_a_valid_completed_search(self):
        result = list(iter_cve_pages_by_cpe(
            CPE_HARDWARE, Mock(), fetcher=Mock(return_value=page([], total=0))
        ))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["records"], [])
        self.assertTrue(result[0]["complete"])

    def test_malformed_or_partial_envelope_never_looks_complete(self):
        bad = [
            {"totalResults": 0, "vulnerabilities": []},  # No pagination metadata
            page([], total=2),
            page([record()], start=1, total=2),
            page([record(), record()], total=1),
            {**page([record()]), "resultsPerPage": True},
            {**page([record()]), "vulnerabilities": [{"oops": "missing CVE"}]},
        ]
        for payload in bad:
            with self.subTest(payload=payload), self.assertRaises(NvdError):
                validated_cve_page(payload, 0)

    def test_changed_total_during_pages_is_an_error(self):
        first = page([record()], total=2, size=1)
        second = page([record()], start=1, total=3, size=1)
        with self.assertRaisesRegex(NvdError, "total de CVE cambió"):
            list(iter_cve_pages_by_cpe(
                CPE_HARDWARE, Mock(), results_per_page=1,
                fetcher=Mock(side_effect=[first, second])
            ))


class GenericCveRecordValidationTests(SimpleTestCase):
    def test_accepts_any_valid_identifier_and_preserves_original_and_or(self):
        original = record()
        identifier, data = validated_cve_record(original)
        self.assertEqual(identifier, "CVE-2024-65432")
        self.assertEqual(data["nvd_record"], original)
        self.assertEqual(data["configurations"], original["configurations"])
        self.assertFalse(data["configurations"][0]["nodes"][0]["cpeMatch"][0]["vulnerable"])
        self.assertEqual(data["base_score"], Decimal("5.3"))
        self.assertEqual(data["severity"], "MEDIUM")
        self.assertEqual(data["nvd_record"]["weaknesses"][0]["description"][0]["value"],
                         "CWE-287")

    def test_not_analyzed_cve_can_have_no_configurations_or_cvss(self):
        original = record("CVE-2025-12345")
        original.pop("configurations")
        original.pop("metrics")
        identifier, fields = validated_cve_record(original)
        self.assertEqual(identifier, "CVE-2025-12345")
        self.assertEqual(fields["configurations"], [])
        self.assertIsNone(fields["base_score"])
        self.assertEqual(fields["metrics"], {})

    def test_rejects_invalid_ids_dates_and_structures(self):
        for field, value in (
            ("id", "not-a-cve"), ("id", "CVE-2024-1"),
            ("published", None), ("lastModified", "invalid"),
            ("configurations", None), ("descriptions", "not a list"),
            ("metrics", []), ("references", {}),
            ("configurations", [None]), ("references", [None]),
        ):
            candidate = record()
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(CveResponseError):
                validated_cve_record(candidate)
        with self.assertRaises(CveResponseError):
            validated_cve_record({"id": "CVE-2024-99999"})


class GenericCvePersistenceTests(TestCase):
    def test_upsert_preserves_one_official_cve_and_no_analyst_decisions(self):
        source = record()
        saved, created = store_official_cve_record(source)
        self.assertTrue(created)
        self.assertEqual(saved.fetch_status, Cve.FetchStatus.COMPLETED)
        self.assertEqual(saved.configurations, source["configurations"])
        self.assertEqual(saved.nvd_record, source)
        self.assertIsNotNone(saved.retrieved_at)
        again, created_again = store_official_cve_record(copy.deepcopy(source))
        self.assertFalse(created_again)
        self.assertEqual(again.pk, saved.pk)
        self.assertEqual(Cve.objects.count(), 1)
        self.assertEqual(Cpe.objects.count(), 0)
        self.assertEqual(AssetCpe.objects.count(), 0)
        self.assertEqual(AssetCveAssessment.objects.count(), 0)
        self.assertEqual(AssetCveFinding.objects.count(), 0)

    def test_older_revision_does_not_overwrite_newer_record(self):
        newer = record()
        newer["lastModified"] = "2025-01-01T00:00:00.000"
        stored, _ = store_official_cve_record(newer)
        older = record()
        older["descriptions"][0]["value"] = "Stale old description."
        again, created = store_official_cve_record(older)
        self.assertFalse(created)
        again.refresh_from_db()
        self.assertEqual(again.pk, stored.pk)
        self.assertEqual(again.description, "An example vulnerability.")
        self.assertEqual(again.last_modified.year, 2025)

    def test_invalid_record_never_creates_a_partial_database_row(self):
        with self.assertRaises(CveResponseError):
            store_official_cve_record({"id": "CVE-2025-12345"})
        self.assertEqual(Cve.objects.count(), 0)
