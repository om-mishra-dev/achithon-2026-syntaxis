"""Unit tests for safety guards, path traversal prevention, and secret redaction."""

import os
import tempfile
import unittest
from pathlib import Path

from auditor.core.safety import (
    ensure_safe_subpath,
    is_safe_file_for_analysis,
    is_safe_subpath,
    redact_secrets,
)


class TestSafetyModule(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_is_safe_subpath_valid(self):
        valid_sub = self.base_path / "src" / "main.py"
        valid_sub.parent.mkdir(parents=True, exist_ok=True)
        valid_sub.write_text("print('hello')", encoding="utf-8")

        self.assertTrue(is_safe_subpath(self.base_path, valid_sub))
        self.assertEqual(ensure_safe_subpath(self.base_path, valid_sub), valid_sub.resolve())

    def test_is_safe_subpath_traversal_attack(self):
        malicious_path = self.base_path / ".." / "system32"
        self.assertFalse(is_safe_subpath(self.base_path, malicious_path))

        with self.assertRaises(ValueError):
            ensure_safe_subpath(self.base_path, malicious_path)

    def test_is_safe_file_for_analysis(self):
        test_file = self.base_path / "valid.py"
        test_file.write_text("x = 1", encoding="utf-8")

        safe, msg = is_safe_file_for_analysis(test_file)
        self.assertTrue(safe)
        self.assertEqual(msg, "OK")

        # Non-existent file
        non_existent = self.base_path / "missing.py"
        safe, msg = is_safe_file_for_analysis(non_existent)
        self.assertFalse(safe)
        self.assertIn("does not exist", msg)

        # File exceeding size limit
        large_file = self.base_path / "large.bin"
        large_file.write_bytes(b"A" * 1024)
        safe, msg = is_safe_file_for_analysis(large_file, max_size_bytes=512)
        self.assertFalse(safe)
        self.assertIn("exceeds maximum limit", msg)

    def test_redact_secrets(self):
        raw_text = """
        AWS_KEY = "AKIA1234567890ABCDEF"
        TOKEN = "ghp_123456789012345678901234567890123456"
        api_key = "abc1234567890123456"
        """
        redacted = redact_secrets(raw_text)
        self.assertNotIn("AKIA1234567890ABCDEF", redacted)
        self.assertIn("[REDACTED_AWS_ACCESS_KEY]", redacted)
        self.assertNotIn("ghp_123456789012345678901234567890123456", redacted)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", redacted)


if __name__ == "__main__":
    unittest.main()

