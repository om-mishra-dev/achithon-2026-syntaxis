"""Unit tests for file discovery, language classification, and manifest detection."""

import tempfile
import unittest
from pathlib import Path

from auditor.scanner.discovery import FileDiscoveryService


class TestFileDiscovery(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name).resolve()

        # Create mock project structure
        # Python source
        src_py = self.root_path / "src"
        src_py.mkdir(parents=True, exist_ok=True)
        (src_py / "app.py").write_text("print('hello')", encoding="utf-8")
        (src_py / "utils.py").write_text("def add(a, b): return a + b", encoding="utf-8")

        # JS / TS source
        frontend = self.root_path / "frontend"
        frontend.mkdir(parents=True, exist_ok=True)
        (frontend / "index.ts").write_text("const msg: string = 'test';", encoding="utf-8")
        (frontend / "component.jsx").write_text("export const C = () => <div/>;", encoding="utf-8")

        # Manifests
        (self.root_path / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")
        (frontend / "package.json").write_text('{"name": "test-pkg"}', encoding="utf-8")

        # Ignored directories
        git_dir = self.root_path / ".git"
        git_dir.mkdir(parents=True, exist_ok=True)
        (git_dir / "config").write_text("core", encoding="utf-8")

        node_mods = frontend / "node_modules" / "some_pkg"
        node_mods.mkdir(parents=True, exist_ok=True)
        (node_mods / "index.js").write_text("module.exports = {};", encoding="utf-8")

        # Binary file
        (src_py / "compiled.pyc").write_bytes(b"\x00\x01\x02")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_discovery_classifications_and_ignores(self):
        service = FileDiscoveryService()
        result = service.discover(self.root_path)

        # Ensure .git and node_modules were ignored
        rel_paths = [f.relative_path for f in result.files]
        self.assertTrue(all(".git" not in p for p in rel_paths))
        self.assertTrue(all("node_modules" not in p for p in rel_paths))
        self.assertTrue(all(not p.endswith(".pyc") for p in rel_paths))

        # Check detected languages
        self.assertEqual(result.language_counts.get("python"), 2)
        self.assertEqual(result.language_counts.get("typescript"), 1)
        self.assertEqual(result.language_counts.get("javascript"), 1)

        # Check manifests
        manifest_rel = [mf.relative_path for mf in result.manifest_files]
        self.assertIn("requirements.txt", manifest_rel)
        self.assertTrue(any("package.json" in m for m in manifest_rel))


if __name__ == "__main__":
    unittest.main()

