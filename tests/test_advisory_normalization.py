"""Unit tests for advisory-to-finding normalization and deduplication."""

import unittest
from auditor.advisories.normalizer import (
    extract_fixed_version_and_range,
    map_severity,
    normalize_advisories_to_findings,
)
from auditor.advisories.osv_client import AdvisoryStatus, OSVQueryResult
from auditor.core.models import FindingType, Severity
from auditor.dependencies.models import DependencyRecord, ResolutionStatus


class TestAdvisoryNormalization(unittest.TestCase):

    def test_map_severity_from_cvss_and_database_specific(self):
        # Database specific CRITICAL
        vuln_crit = {"database_specific": {"severity": "CRITICAL"}}
        sev, score = map_severity(vuln_crit)
        self.assertEqual(sev, Severity.CRITICAL)

        # Database specific HIGH
        vuln_high = {"database_specific": {"severity": "HIGH"}}
        sev, score = map_severity(vuln_high)
        self.assertEqual(sev, Severity.HIGH)

        # CVSS score >= 9.0
        vuln_cvss = {"severity": [{"type": "CVSS_V3", "score": 9.8}]}
        sev, score = map_severity(vuln_cvss)
        self.assertEqual(sev, Severity.CRITICAL)
        self.assertEqual(score, 9.8)

        # Missing severity fallback
        sev_empty, score_empty = map_severity({})
        self.assertEqual(sev_empty, Severity.MEDIUM)
        self.assertIsNone(score_empty)

    def test_extract_fixed_version_and_range(self):
        vuln = {
            "affected": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.31.0"},
                            ],
                        }
                    ],
                }
            ]
        }
        fixed_ver, range_str = extract_fixed_version_and_range(vuln, "requests")
        self.assertEqual(fixed_ver, "2.31.0")
        self.assertIn("<2.31.0", range_str)

    def test_finding_normalization_and_deduplication(self):
        # Package declared in requirements.txt AND Pipfile.lock
        rec1 = DependencyRecord(
            name="requests",
            normalized_name="requests",
            ecosystem="PyPI",
            version="2.28.0",
            is_direct=True,
            source_manifest="requirements.txt",
            declaration_line=12,
            resolution_status=ResolutionStatus.RESOLVED,
        )
        rec2 = DependencyRecord(
            name="requests",
            normalized_name="requests",
            ecosystem="PyPI",
            version="2.28.0",
            is_direct=True,
            source_manifest="Pipfile.lock",
            declaration_line=4,
            resolution_status=ResolutionStatus.RESOLVED,
        )

        query_result = OSVQueryResult(
            ecosystem="PyPI",
            package_name="requests",
            version="2.28.0",
            status=AdvisoryStatus.MATCHED,
            advisories=[
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "aliases": ["CVE-2023-32681"],
                    "summary": "Requests vulnerable to unintended leak of Proxy-Authorization header",
                    "details": "Full description of CVE-2023-32681",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [{"events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]}],
                        }
                    ],
                }
            ],
        )

        findings = normalize_advisories_to_findings([query_result], [rec1, rec2])

        # Deduplication check: should create 1 unified finding
        self.assertEqual(len(findings), 1)
        finding = findings[0]

        self.assertEqual(finding.id, "DEP-GHSA-j8r2-6x86-q33q-requests")
        self.assertEqual(finding.cve_id, "CVE-2023-32681")
        self.assertEqual(finding.advisory_id, "GHSA-j8r2-6x86-q33q")
        self.assertEqual(finding.package_name, "requests")
        self.assertEqual(finding.current_version, "2.28.0")
        self.assertEqual(finding.fixed_version, "2.31.0")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.finding_type, FindingType.DEPENDENCY_VULNERABILITY)

        # Should preserve locations from both manifests
        self.assertEqual(len(finding.locations), 2)
        loc_files = [loc.file_path for loc in finding.locations]
        self.assertIn("requirements.txt", loc_files)
        self.assertIn("Pipfile.lock", loc_files)

        # Remediation advice check
        self.assertIn("Upgrade requests to version 2.31.0 or higher", finding.remediation_advice)


if __name__ == "__main__":
    unittest.main()

