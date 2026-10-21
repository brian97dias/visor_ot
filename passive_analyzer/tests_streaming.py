"""Run after installing requirements-large-pcap.txt: python -m unittest tests_streaming."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import api


class LargeAnalysisApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / "example.json"
        self.path.write_text(json.dumps({
            "schema_version": "0.2",
            "capture": {"pcap_id": "example", "filename": "example.pcap",
                        "relative_path": "example.pcap"},
            "interfaces": [{
                "mac": "00:11:22:33:44:55",
                "ips": ["10.0.0.1"], "first_seen": "a", "last_seen": "b",
            }],
            "communications": [
                {"client_ip": "10.0.0.1", "server_ip": "10.0.0.2",
                 "transport_protocol": "TCP", "service_port": 502,
                 "service": "Modbus", "packet_count": i,
                 "first_seen": "a", "last_seen": "b"}
                for i in range(70)
            ],
        }), encoding="utf-8")

    def test_pagination_only_returns_one_page_and_preserves_totals(self):
        with patch.object(api, "OUTPUT_DIRECTORY", self.directory), patch.object(
            api, "get_pcap_by_id", return_value=self.directory / "example.pcap"
        ):
            result = api.get_analysis_observations(
                "example", type="communications", page=3,
                search="", min_packets=1,
            )
        self.assertEqual(result["communications_detected"], 70)
        self.assertEqual(result["interfaces_detected"], 1)
        self.assertEqual(result["count"], 69)
        self.assertEqual(result["page"], 3)
        self.assertEqual(len(result["results"]), 19)
        self.assertEqual(result["results"][0]["packet_count"], 51)

    def test_manifest_and_ndjson_have_verified_completion_marker(self):
        with patch.object(api, "OUTPUT_DIRECTORY", self.directory), patch.object(
            api, "get_pcap_by_id", return_value=self.directory / "example.pcap"
        ), patch.object(api, "get_analysis_hash", return_value="a" * 64):
            manifest = api.get_analysis_import_manifest("example")
            response = api.stream_analysis_import("example")

            async def collect():
                return [part async for part in response.body_iterator]

            chunks = asyncio.run(collect())
        rows = [json.loads(chunk) for chunk in chunks]
        self.assertEqual(manifest["schema_version"], "0.2")
        self.assertEqual(manifest["capture"]["pcap_id"], "example")
        self.assertEqual(len(rows), 72)
        self.assertEqual(rows[-1]["type"], "complete")
        self.assertEqual(rows[-1]["interfaces"], 1)
        self.assertEqual(rows[-1]["communications"], 70)


if __name__ == "__main__":
    unittest.main()
