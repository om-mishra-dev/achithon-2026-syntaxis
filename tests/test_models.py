"""Unit tests for core data models and serialization."""

import json
import unittest

from auditor.core.models import (
    CodeLocation,
    Confidence,
    EvidenceItem,
    Finding,
    FindingType,
    ScanResult,
    ScanSummary,
    Severity,
)


class TestModels(unittest.TestCase):

    def test_finding_creation_and_serialization(self):
        location = CodeLocation(
            file_path="src/vulnerable.py",
            line=42,
            col=5,
            end_line=42,
            end_col=35,
            snippet="os.system(user_input)",
        )

        evidence = EvidenceItem(
            source_type="AST_NODE",
            description="Direct shell execution sink reachable from HTTP parameter",
            location=location,
        )

        finding = Finding(
            id="FINDING-001",
            title="Command Injection via os.system",
            description="Untrusted user input passed into os.system without sanitization",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            finding_type=FindingType.SAST_VULNERABILITY,
            cwe_id="CWE-78",
            locations=[location],
            evidence=[evidence],
            remediation_advice="Use subprocess.run with argument list instead of shell=True.",
        )

        finding_dict = finding.model_dump()
        self.assertEqual(finding_dict["id"], "FINDING-001")
        self.assertEqual(finding_dict["severity"], "HIGH")
        self.assertEqual(finding_dict["confidence"], "CONFIRMED")
        self.assertEqual(len(finding_dict["evidence"]), 1)

        # JSON round-trip
        json_str = finding.model_dump_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["cwe_id"], "CWE-78")

    def test_scan_result_model(self):
        summary = ScanSummary(
            total_files_discovered=10,
            scanned_files_count=8,
            skipped_files_count=2,
            languages={"python": 8},
            findings_count_by_severity={"HIGH": 1},
            duration_seconds=1.23,
        )

        result = ScanResult(
            scan_id="test-scan-123",
            target_path_or_url="/path/to/repo",
            summary=summary,
            findings=[],
        )

        json_out = result.model_dump_json()
        self.assertIn("test-scan-123", json_out)
        self.assertIn("/path/to/repo", json_out)


if __name__ == "__main__":
    unittest.main()

