"""Unit tests for the OSV advisory client using mocked HTTP responses and local caching."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests
from auditor.advisories.osv_client import (
    AdvisoryStatus,
    OSVClient,
    OSVQueryResult,
)


class TestOSVClient(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("requests.Session.post")
    def test_query_package_version_matched_advisory(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-1234-5678-90ab",
                    "summary": "Sample vulnerability in requests",
                    "aliases": ["CVE-2023-32681"],
                }
            ]
        }
        mock_post.return_value = mock_response

        client = OSVClient(cache_dir=self.cache_dir)
        result = client.query_package_version("PyPI", "requests", "2.28.0")

        self.assertEqual(result.status, AdvisoryStatus.MATCHED)
        self.assertEqual(len(result.advisories), 1)
        self.assertEqual(result.advisories[0]["id"], "GHSA-1234-5678-90ab")
        self.assertFalse(result.is_cached)

        # Second query should be a cache hit (no network call)
        mock_post.reset_mock()
        cached_result = client.query_package_version("PyPI", "requests", "2.28.0")
        self.assertEqual(cached_result.status, AdvisoryStatus.MATCHED)
        self.assertTrue(cached_result.is_cached)
        mock_post.assert_not_called()

    @patch("requests.Session.post")
    def test_query_package_version_no_advisories(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}  # Empty vulns
        mock_post.return_value = mock_response

        client = OSVClient(cache_dir=self.cache_dir)
        result = client.query_package_version("npm", "lodash", "4.17.21")

        self.assertEqual(result.status, AdvisoryStatus.NO_MATCH)
        self.assertEqual(len(result.advisories), 0)

    @patch("requests.Session.post")
    def test_query_package_retries_on_rate_limit(self, mock_post):
        # 1st call: 429 rate limit, 2nd call: 200 OK
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.text = "Rate limit exceeded"

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {"vulns": []}

        mock_post.side_effect = [resp_429, resp_200]

        client = OSVClient(cache_dir=self.cache_dir)
        with patch("time.sleep", return_value=None):
            result = client.query_package_version("PyPI", "urllib3", "1.26.5")

        self.assertEqual(result.status, AdvisoryStatus.NO_MATCH)
        self.assertEqual(mock_post.call_count, 2)

    def test_offline_mode_behavior(self):
        client = OSVClient(cache_dir=self.cache_dir, offline=True)

        # 1. Uncached package in offline mode
        result = client.query_package_version("PyPI", "unseen-pkg", "1.0.0")
        self.assertEqual(result.status, AdvisoryStatus.UNAVAILABLE_OFFLINE)

        # 2. Pre-populate cache directly
        cached_data = [{"id": "OSV-MOCK-1", "summary": "Cached vuln"}]
        client._write_to_cache("PyPI", "cached-pkg", "2.0.0", cached_data)

        # In offline mode, cached package is found and returned without network
        cached_result = client.query_package_version("PyPI", "cached-pkg", "2.0.0")
        self.assertEqual(cached_result.status, AdvisoryStatus.MATCHED)
        self.assertTrue(cached_result.is_cached)

    @patch("requests.Session.post")
    def test_batch_query_execution(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"vulns": [{"id": "ADV-1"}]},
                {"vulns": []},
            ]
        }
        mock_post.return_value = mock_response

        client = OSVClient(cache_dir=self.cache_dir)
        queries = [
            ("PyPI", "requests", "2.6.0"),
            ("npm", "express", "4.18.2"),
        ]
        results = client.query_batch(queries)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].status, AdvisoryStatus.MATCHED)
        self.assertEqual(results[1].status, AdvisoryStatus.NO_MATCH)


if __name__ == "__main__":
    unittest.main()

