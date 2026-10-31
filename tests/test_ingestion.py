"""Unit tests for repository ingestion (local directories and Git URLs)."""

import tempfile
import unittest
from pathlib import Path

from auditor.ingestion.factory import get_ingester
from auditor.ingestion.git import GitIngester
from auditor.ingestion.local import LocalIngester


class TestIngestion(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_local_ingester_valid_directory(self):
        ingester = LocalIngester()
        with ingester.ingest(str(self.test_dir)) as result:
            self.assertEqual(result.working_dir, self.test_dir)
            self.assertFalse(result.is_temporary)
            self.assertEqual(result.original_target, str(self.test_dir))

    def test_local_ingester_non_existent_directory(self):
        ingester = LocalIngester()
        with self.assertRaises(FileNotFoundError):
            ingester.ingest(str(self.test_dir / "does_not_exist"))

    def test_local_ingester_file_target(self):
        dummy_file = self.test_dir / "file.txt"
        dummy_file.write_text("content", encoding="utf-8")
        ingester = LocalIngester()
        with self.assertRaises(NotADirectoryError):
            ingester.ingest(str(dummy_file))

    def test_git_ingester_url_validation(self):
        git_ingester = GitIngester()

        valid_urls = [
            "https://github.com/org/repo.git",
            "http://gitlab.com/project/subproject",
            "git@github.com:owner/repo.git",
            "ssh://git@github.com/org/repo",
        ]
        for url in valid_urls:
            self.assertTrue(git_ingester.validate_url(url), f"Expected '{url}' to be valid")

        invalid_urls = [
            "https://github.com/repo; rm -rf /",
            "https://github.com/repo && evil_cmd",
            "http://github.com/repo | cat /etc/passwd",
            "https://github.com/repo`id`",
            "not_a_url",
            "",
        ]
        for url in invalid_urls:
            self.assertFalse(git_ingester.validate_url(url), f"Expected '{url}' to be invalid")

    def test_ingester_factory_selection(self):
        local_ing = get_ingester(str(self.test_dir))
        self.assertIsInstance(local_ing, LocalIngester)

        git_ing = get_ingester("https://github.com/owner/repo.git")
        self.assertIsInstance(git_ing, GitIngester)


if __name__ == "__main__":
    unittest.main()

