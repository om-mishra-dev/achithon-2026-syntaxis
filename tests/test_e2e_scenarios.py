"""Phase F: End-to-end integration scenarios for the full SYNTAXIS audit pipeline."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent.resolve()


class TestScenarioA_Vulnerable(unittest.TestCase):
    """Scenario A: A vulnerable repository (CMD injection) is scanned and finding is detected."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # Create a file with a tainted command injection pattern
        vuln_code = (
            "import os\n"
            "from flask import request\n\n"
            "def run_cmd():\n"
            "    cmd = request.args.get('cmd')\n"
            "    os.system(cmd)\n"
        )
        (self.tmpdir / "server.py").write_text(vuln_code)
        self.out_path = self.tmpdir / "scan_result.json"

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_scan_detects_cmd_injection(self):
        from auditor.core.config import ScanConfig
        from auditor.cli import run_scan

        config = ScanConfig(
            target=str(self.tmpdir),
            output_formats=["json"],
            output_path=str(self.out_path),
            offline_mode=True,
            include_sast=True,
            include_deps=False,
            include_agents=False,
            enable_llm=False,
            verbose=False,
        )
        exit_code = run_scan(config)
        self.assertEqual(exit_code, 0)
        self.assertTrue(self.out_path.exists())

        data = json.loads(self.out_path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        cwe_ids = {f.get("cwe_id") for f in findings}
        self.assertIn(
            "CWE-78", cwe_ids,
            f"Expected CWE-78 finding, got cwe_ids={cwe_ids} from {len(findings)} findings"
        )

    def test_scan_reports_sast_finding_count(self):
        from auditor.core.config import ScanConfig
        from auditor.cli import run_scan

        config = ScanConfig(
            target=str(self.tmpdir),
            output_formats=["json"],
            output_path=str(self.out_path),
            offline_mode=True,
            include_sast=True,
            include_deps=False,
            include_agents=False,
            enable_llm=False,
            verbose=False,
        )
        run_scan(config)
        data = json.loads(self.out_path.read_text(encoding="utf-8"))
        sast_findings = [f for f in data.get("findings", [])
                         if f.get("finding_type") == "SAST_VULNERABILITY"]
        self.assertGreaterEqual(len(sast_findings), 1)


class TestScenarioB_Safe(unittest.TestCase):
    """Scenario B: A safe repository (no injection) produces no high-severity findings."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        safe_code = (
            "import subprocess\n\n"
            "def list_files():\n"
            "    result = subprocess.run(['ls', '-la'], shell=False, capture_output=True)\n"
            "    return result.stdout\n"
        )
        (self.tmpdir / "app.py").write_text(safe_code)
        self.out_path = self.tmpdir / "scan_result.json"

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_scan_produces_no_cmd_injection_finding(self):
        from auditor.core.config import ScanConfig
        from auditor.cli import run_scan

        config = ScanConfig(
            target=str(self.tmpdir),
            output_formats=["json"],
            output_path=str(self.out_path),
            offline_mode=True,
            include_sast=True,
            include_deps=False,
            include_agents=False,
            enable_llm=False,
            verbose=False,
        )
        run_scan(config)
        data = json.loads(self.out_path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        cwe_ids = {f.get("cwe_id") for f in findings}
        self.assertNotIn(
            "CWE-78", cwe_ids,
            f"Expected no CWE-78 finding on safe code, got {cwe_ids}"
        )

    def test_scan_zero_high_findings(self):
        from auditor.core.config import ScanConfig
        from auditor.cli import run_scan

        config = ScanConfig(
            target=str(self.tmpdir),
            output_formats=["json"],
            output_path=str(self.out_path),
            offline_mode=True,
            include_sast=True,
            include_deps=False,
            include_agents=False,
            enable_llm=False,
            verbose=False,
        )
        run_scan(config)
        data = json.loads(self.out_path.read_text(encoding="utf-8"))
        high_critical = [
            f for f in data.get("findings", [])
            if f.get("severity") in ("HIGH", "CRITICAL")
        ]
        self.assertEqual(len(high_critical), 0)


class TestScenarioC_DependencyVulnerability(unittest.TestCase):
    """Scenario C: Repository with a known-vulnerable dependency is detected using mocked OSV."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        (self.tmpdir / "requirements.txt").write_text("requests==2.6.0\n")
        (self.tmpdir / "app.py").write_text("import requests\n")
        self.out_path = self.tmpdir / "scan_result.json"

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def _mock_osv_query(self, package_queries):
        """Return mock OSVQueryResult objects for requests==2.6.0."""
        from auditor.advisories.osv_client import OSVQueryResult, AdvisoryStatus
        results = []
        for item in package_queries:
            # package_queries is List[Tuple[ecosystem, name, version]]
            if isinstance(item, (tuple, list)) and len(item) >= 3:
                ecosystem, name, version = item[0], item[1], item[2]
            else:
                ecosystem, name, version = "PyPI", str(item), ""

            if name.lower() in ("requests",) and version == "2.6.0":
                advisory = {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "summary": "SSRF vulnerability in requests",
                    "affected": [{
                        "package": {"name": "requests", "ecosystem": "PyPI"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [
                            {"introduced": "0"}, {"fixed": "2.31.0"}
                        ]}],
                        "versions": ["2.6.0"],
                    }],
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                }
                results.append(OSVQueryResult(
                    ecosystem="PyPI",
                    package_name=name,
                    version=version,
                    status=AdvisoryStatus.MATCHED,
                    advisories=[advisory],
                ))
            else:
                results.append(OSVQueryResult(
                    ecosystem=ecosystem if isinstance(ecosystem, str) else "PyPI",
                    package_name=name,
                    version=version,
                    status=AdvisoryStatus.NO_MATCH,
                    advisories=[],
                ))
        return results

    def test_dep_scan_detects_advisory(self):
        from auditor.core.config import ScanConfig
        from auditor.cli import run_scan
        from auditor.advisories import osv_client as osv_module

        config = ScanConfig(
            target=str(self.tmpdir),
            output_formats=["json"],
            output_path=str(self.out_path),
            offline_mode=False,  # needs to query OSV (mocked)
            include_sast=False,
            include_deps=True,
            include_agents=False,
            enable_llm=False,
            verbose=False,
        )

        with patch.object(osv_module.OSVClient, "query_batch", self._mock_osv_query):
            exit_code = run_scan(config)

        self.assertEqual(exit_code, 0)
        data = json.loads(self.out_path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        dep_findings = [
            f for f in findings
            if f.get("finding_type") == "DEPENDENCY_VULNERABILITY"
        ]
        self.assertGreater(len(dep_findings), 0,
                           f"Expected dep finding, got: {findings}")

    def test_dep_finding_has_advisory_id(self):
        from auditor.core.config import ScanConfig
        from auditor.cli import run_scan
        from auditor.advisories import osv_client as osv_module

        config = ScanConfig(
            target=str(self.tmpdir),
            output_formats=["json"],
            output_path=str(self.out_path),
            offline_mode=False,
            include_sast=False,
            include_deps=True,
            include_agents=False,
            enable_llm=False,
            verbose=False,
        )

        with patch.object(osv_module.OSVClient, "query_batch", self._mock_osv_query):
            run_scan(config)

        data = json.loads(self.out_path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        titles = " ".join(f.get("title", "") + " " + str(f.get("cve_id", "")) for f in findings)
        self.assertTrue(
            "GHSA-j8r2-6x86-q33q" in titles or "requests" in titles.lower(),
            f"Advisory ID not found in findings: {findings}"
        )


class TestScenarioD_SQLInjection(unittest.TestCase):
    """Scenario D: SQL injection via f-string detected by SAST."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        sql_code = (
            "from flask import request\n"
            "import sqlite3\n\n"
            "def search(db):\n"
            "    uid = request.args.get('id')\n"
            "    cur = db.cursor()\n"
            "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
            "    return cur.fetchall()\n"
        )
        (self.tmpdir / "app.py").write_text(sql_code)
        self.out_path = self.tmpdir / "scan_result.json"

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_sql_injection_detected(self):
        from auditor.core.config import ScanConfig
        from auditor.cli import run_scan

        config = ScanConfig(
            target=str(self.tmpdir),
            output_formats=["json"],
            output_path=str(self.out_path),
            offline_mode=True,
            include_sast=True,
            include_deps=False,
            include_agents=False,
            enable_llm=False,
            verbose=False,
        )
        run_scan(config)
        data = json.loads(self.out_path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        cwe_ids = {f.get("cwe_id") for f in findings}
        self.assertIn("CWE-89", cwe_ids,
                      f"Expected CWE-89, got cwe_ids={cwe_ids}")


class TestScenarioE_PathTraversal(unittest.TestCase):
    """Scenario E: Path traversal via open() with request.args detected by SAST."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        path_code = (
            "from flask import request\n\n"
            "def read_file():\n"
            "    path = request.args.get('f')\n"
            "    with open(path) as fh:\n"
            "        return fh.read()\n"
        )
        (self.tmpdir / "app.py").write_text(path_code)
        self.out_path = self.tmpdir / "scan_result.json"

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_path_traversal_detected(self):
        from auditor.core.config import ScanConfig
        from auditor.cli import run_scan

        config = ScanConfig(
            target=str(self.tmpdir),
            output_formats=["json"],
            output_path=str(self.out_path),
            offline_mode=True,
            include_sast=True,
            include_deps=False,
            include_agents=False,
            enable_llm=False,
            verbose=False,
        )
        run_scan(config)
        data = json.loads(self.out_path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        cwe_ids = {f.get("cwe_id") for f in findings}
        self.assertIn("CWE-22", cwe_ids,
                      f"Expected CWE-22, got cwe_ids={cwe_ids}")


if __name__ == "__main__":
    unittest.main()
