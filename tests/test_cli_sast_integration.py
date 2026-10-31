"""Integration tests for CLI SAST and dependency co-execution."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auditor.cli import main


class TestCLISASTIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.temp_dir.name).resolve()

        # Vulnerable source
        (self.repo_dir / "server.py").write_text(
            """
import os

def run_user_cmd():
    cmd = request.args.get('c')
    os.system(cmd)
""",
            encoding="utf-8",
        )

        # Vulnerable dependency manifest
        (self.repo_dir / "requirements.txt").write_text("requests==2.6.0\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("auditor.advisories.osv_client.OSVClient.query_batch")
    def test_combined_sast_and_dependency_scan(self, mock_query_batch):
        from auditor.advisories.osv_client import AdvisoryStatus, OSVQueryResult

        mock_query_batch.return_value = [
            OSVQueryResult(
                ecosystem="PyPI",
                package_name="requests",
                version="2.6.0",
                status=AdvisoryStatus.MATCHED,
                advisories=[{"id": "GHSA-test-1", "database_specific": {"severity": "HIGH"}}],
            )
        ]

        out_json = self.repo_dir / "combined_report.json"
        exit_code = main(["scan", str(self.repo_dir), "--output", str(out_json)])

        self.assertEqual(exit_code, 0)
        report = json.loads(out_json.read_text(encoding="utf-8"))

        finding_types = [f["finding_type"] for f in report["findings"]]
        self.assertIn("SAST_VULNERABILITY", finding_types)
        self.assertIn("DEPENDENCY_VULNERABILITY", finding_types)

        # Verify summary counts
        self.assertEqual(report["summary"]["sast_findings_count"], 1)
        self.assertGreaterEqual(report["summary"]["advisory_matches_count"], 1)

        # Verify code graph metrics
        self.assertIn("code", report["graph_metrics"])
        self.assertEqual(report["graph_metrics"]["code"]["functions_count"], 1)

    def test_no_sast_flag_skips_sast_only(self):
        out_json = self.repo_dir / "no_sast.json"
        exit_code = main(["scan", str(self.repo_dir), "--no-sast", "--offline", "--output", str(out_json)])

        self.assertEqual(exit_code, 0)
        report = json.loads(out_json.read_text(encoding="utf-8"))
        finding_types = [f["finding_type"] for f in report["findings"]]
        self.assertNotIn("SAST_VULNERABILITY", finding_types)
        self.assertEqual(report["summary"]["sast_findings_count"], 0)


if __name__ == "__main__":
    unittest.main()

