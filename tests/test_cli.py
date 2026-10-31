"""Unit tests for the Command Line Interface."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auditor.cli import build_parser, main


class TestCLI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sample_dir = Path(self.temp_dir.name).resolve()

        # Add sample file
        (self.sample_dir / "sample.py").write_text("x = 42\n", encoding="utf-8")
        (self.sample_dir / "requirements.txt").write_text("urllib3>=1.26.0\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parser_version_and_flags(self):
        parser = build_parser()
        args = parser.parse_args(["scan", str(self.sample_dir), "--offline", "--format", "json"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target, str(self.sample_dir))
        self.assertTrue(args.offline)
        self.assertEqual(args.format, "json")

    def test_main_scan_execution(self):
        out_json = self.sample_dir / "out.json"
        exit_code = main(["scan", str(self.sample_dir), "--output", str(out_json)])

        self.assertEqual(exit_code, 0)
        self.assertTrue(out_json.exists())

        data = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertIn("scan_id", data)
        self.assertEqual(data["summary"]["scanned_files_count"], 2)
        self.assertEqual(data["summary"]["languages"]["python"], 1)

    def test_main_help_exit(self):
        exit_code = main([])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()

