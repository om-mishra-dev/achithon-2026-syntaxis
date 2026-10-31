"""Integration tests for CLI dependency scanning and reporting."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from auditor.cli import main


class TestCLIDependencyIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.temp_dir.name).resolve()

        # Create synthetic repo
        (self.repo_dir / "requirements.txt").write_text("requests==2.6.0\n", encoding="utf-8")
        (self.repo_dir / "package.json").write_text('{"dependencies": {"lodash": "4.17.15"}}', encoding="utf-8")
        (self.repo_dir / "app.py").write_text("import requests\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("auditor.advisories.osv_client.OSVClient.query_batch")
    def test_cli_scan_with_dependencies_matched(self, mock_query_batch):
        from auditor.advisories.osv_client import AdvisoryStatus, OSVQueryResult

        # Mock OSV response for requests 2.6.0
        mock_result = OSVQueryResult(
            ecosystem="PyPI",
            package_name="requests",
            version="2.6.0",
            status=AdvisoryStatus.MATCHED,
            advisories=[
                {
                    "id": "GHSA-m88x-9w9w-8888",
                    "aliases": ["CVE-2015-2296"],
                    "summary": "CRITICAL vulnerability in requests 2.6.0",
                    "database_specific": {"severity": "CRITICAL"},
                    "affected": [{"ranges": [{"events": [{"fixed": "2.7.0"}]}]}],
                }
            ],
            is_cached=False,
        )
        mock_query_batch.return_value = [mock_result]

        out_json = self.repo_dir / "report.json"
        exit_code = main(["scan", str(self.repo_dir), "--output", str(out_json)])

        self.assertEqual(exit_code, 0)
        self.assertTrue(out_json.exists())

        report = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["manifests_discovered_count"], 2)
        self.assertEqual(report["summary"]["manifests_parsed_count"], 2)
        self.assertGreaterEqual(report["summary"]["dependencies_total_count"], 2)
        self.assertGreaterEqual(len(report["findings"]), 1)

        # Check graph metrics
        self.assertIn("graph_metrics", report)
        self.assertGreaterEqual(report["graph_metrics"]["total_package_nodes"], 2)

    def test_cli_scan_with_no_deps_flag(self):
        out_json = self.repo_dir / "no_deps_report.json"
        exit_code = main(["scan", str(self.repo_dir), "--no-deps", "--output", str(out_json)])

        self.assertEqual(exit_code, 0)
        report = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["manifests_parsed_count"], 0)
        self.assertEqual(report["summary"]["dependencies_total_count"], 0)
        self.assertEqual(len(report["findings"]), 0)

    def test_cli_scan_offline_mode(self):
        out_json = self.repo_dir / "offline_report.json"
        exit_code = main(["scan", str(self.repo_dir), "--offline", "--output", str(out_json)])

        self.assertEqual(exit_code, 0)
        report = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertTrue(report["metadata"]["offline_mode"])


if __name__ == "__main__":
    unittest.main()

