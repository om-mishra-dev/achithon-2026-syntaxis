"""Phase E tests: patch generation strategies."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from auditor.remediation.models import (
    PatchStatus,
    RemediationRequest,
    RemediationStrategy,
)
from auditor.remediation.strategies import (
    CommandInjectionArglistStrategy,
    DependencyVersionUpgradeStrategy,
    PathTraversalValidationStrategy,
    SafeDeserializationStrategy,
    SQLParameterizationStrategy,
    UnsupportedStrategy,
    get_strategy,
)


# ── helpers ────────────────────────────────────────────────────────────────

def _sast_req(cwe: str, file: str = "app.py", excerpt: str = "x=1") -> RemediationRequest:
    return RemediationRequest(
        finding_id=f"SAST-{cwe}-app.py:10",
        cwe_id=cwe,
        finding_type="SAST_VULNERABILITY",
        target_file=file,
        source_excerpt=excerpt,
        existing_remediation_advice="Use safe API.",
    )


def _dep_req(pkg: str, fixed: str | None, manifest: str = "requirements.txt") -> RemediationRequest:
    return RemediationRequest(
        finding_id=f"DEP-{pkg}",
        finding_type="DEPENDENCY_VULNERABILITY",
        advisory_id="GHSA-xxxx",
        package_name=pkg,
        ecosystem="pypi",
        current_version="1.0.0",
        fixed_version=fixed,
        manifest_file=manifest,
    )


# ── SQL Injection ───────────────────────────────────────────────────────────

class TestSQLParameterizationStrategy(unittest.TestCase):

    def setUp(self):
        self.strategy = SQLParameterizationStrategy()

    def test_can_handle_cwe89_python(self):
        req = _sast_req("CWE-89")
        self.assertTrue(self.strategy.can_handle(req))

    def test_cannot_handle_other_cwe(self):
        req = _sast_req("CWE-78")
        self.assertFalse(self.strategy.can_handle(req))

    def test_fstring_sql_produces_proposal(self):
        code = 'def get(uid):\n    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        req = _sast_req("CWE-89", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertIn(proposal.status, (PatchStatus.PROPOSED, PatchStatus.REQUIRES_REVIEW))
        if proposal.proposed_content:
            self.assertIn("%s", proposal.proposed_content)
            self.assertNotIn(f"{uid}", proposal.proposed_content)  # f-expr replaced

    def test_safe_parameterized_not_rewritten(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
        req = _sast_req("CWE-89", excerpt=code)
        proposal = self.strategy.generate(req, code)
        # Parameterized query: no f-string/format match → REQUIRES_REVIEW or content unchanged
        if proposal.proposed_content:
            self.assertEqual(proposal.proposed_content, code)

    def test_proposal_has_explanation(self):
        code = 'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")\n'
        req = _sast_req("CWE-89", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertTrue(len(proposal.explanation) > 0)

    def test_proposal_linked_to_finding(self):
        code = 'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")\n'
        req = _sast_req("CWE-89", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertEqual(proposal.finding_id, req.finding_id)

    def test_diff_present_when_change_made(self):
        code = 'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")\n'
        req = _sast_req("CWE-89", excerpt=code)
        proposal = self.strategy.generate(req, code)
        if proposal.proposed_content and proposal.proposed_content != code:
            self.assertIsNotNone(proposal.unified_diff)
            self.assertIn("---", proposal.unified_diff)


# ── Command Injection ───────────────────────────────────────────────────────

class TestCommandInjectionStrategy(unittest.TestCase):

    def setUp(self):
        self.strategy = CommandInjectionArglistStrategy()

    def test_can_handle_cwe78_python(self):
        req = _sast_req("CWE-78")
        self.assertTrue(self.strategy.can_handle(req))

    def test_os_system_produces_requires_review(self):
        code = 'import os\ndef run(cmd):\n    os.system(cmd)\n'
        req = _sast_req("CWE-78", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertEqual(proposal.status, PatchStatus.REQUIRES_REVIEW)

    def test_os_system_does_not_blindly_produce_validated(self):
        """os.system rewrite must never be auto-validated."""
        code = 'import os\nos.system(user_input)\n'
        req = _sast_req("CWE-78", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertNotEqual(proposal.status, PatchStatus.VALIDATED)

    def test_subprocess_shell_true_produces_requires_review(self):
        code = 'import subprocess\nsubprocess.run(cmd, shell=True)\n'
        req = _sast_req("CWE-78", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertEqual(proposal.status, PatchStatus.REQUIRES_REVIEW)
        if proposal.proposed_content:
            self.assertNotIn("shell=True", proposal.proposed_content)

    def test_ambiguous_command_does_not_produce_dangerous_rewrite(self):
        """If command cannot be identified, must require review — not auto-fix."""
        code = 'import subprocess\nsubprocess.run(build_complex_cmd(args), shell=True)\n'
        req = _sast_req("CWE-78", excerpt=code)
        proposal = self.strategy.generate(req, code)
        # Must never produce PROPOSED (only REQUIRES_REVIEW or UNSUPPORTED)
        self.assertNotEqual(proposal.status, PatchStatus.PROPOSED)

    def test_warnings_present(self):
        code = 'import os\nos.system(cmd)\n'
        req = _sast_req("CWE-78", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertTrue(len(proposal.warnings) > 0)


# ── Path Traversal ──────────────────────────────────────────────────────────

class TestPathTraversalStrategy(unittest.TestCase):

    def setUp(self):
        self.strategy = PathTraversalValidationStrategy()

    def test_can_handle_cwe22_python(self):
        req = _sast_req("CWE-22")
        self.assertTrue(self.strategy.can_handle(req))

    def test_open_call_gets_guard_inserted(self):
        code = 'def read(path):\n    with open(path) as f:\n        return f.read()\n'
        req = _sast_req("CWE-22", excerpt=code)
        proposal = self.strategy.generate(req, code)
        if proposal.proposed_content:
            self.assertIn("resolve()", proposal.proposed_content)
            self.assertIn("startswith", proposal.proposed_content)

    def test_guard_requires_review(self):
        code = 'open(user_path)\n'
        req = _sast_req("CWE-22", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertEqual(proposal.status, PatchStatus.REQUIRES_REVIEW)

    def test_warning_about_base_dir_placeholder(self):
        code = 'open(user_path)\n'
        req = _sast_req("CWE-22", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertTrue(any("PERMITTED_BASE_DIR" in w or "base" in w.lower() for w in proposal.warnings))


# ── Unsafe Deserialization ───────────────────────────────────────────────────

class TestSafeDeserializationStrategy(unittest.TestCase):

    def setUp(self):
        self.strategy = SafeDeserializationStrategy()

    def test_can_handle_cwe502_python(self):
        req = _sast_req("CWE-502")
        self.assertTrue(self.strategy.can_handle(req))

    def test_yaml_load_replaced_with_safe_load(self):
        code = 'import yaml\ndata = yaml.load(stream, Loader=yaml.Loader)\n'
        req = _sast_req("CWE-502", excerpt=code)
        proposal = self.strategy.generate(req, code)
        if proposal.proposed_content:
            self.assertIn("yaml.safe_load", proposal.proposed_content)
            self.assertNotIn("yaml.load(", proposal.proposed_content)

    def test_pickle_loads_requires_review_not_auto_json(self):
        """pickle.loads cannot be blindly replaced with json.loads."""
        code = 'import pickle\ndata = pickle.loads(raw_bytes)\n'
        req = _sast_req("CWE-502", excerpt=code)
        proposal = self.strategy.generate(req, code)
        self.assertEqual(proposal.status, PatchStatus.REQUIRES_REVIEW)
        # Must warn that JSON may not be compatible
        self.assertTrue(any("json" in w.lower() or "compatible" in w.lower() for w in proposal.warnings))


# ── Dependency Remediation ───────────────────────────────────────────────────

class TestDependencyVersionUpgradeStrategy(unittest.TestCase):

    def setUp(self):
        self.strategy = DependencyVersionUpgradeStrategy()

    def test_can_handle_dep_with_fixed_version(self):
        req = _dep_req("requests", fixed="2.28.0")
        self.assertTrue(self.strategy.can_handle(req))

    def test_cannot_handle_without_fixed_version(self):
        req = _dep_req("requests", fixed=None)
        self.assertFalse(self.strategy.can_handle(req))

    def test_requirements_txt_updated(self):
        manifest = "flask==2.0.0\nrequests==2.25.0\nnumpy>=1.20\n"
        req = _dep_req("requests", fixed="2.28.0")
        proposal = self.strategy.generate(req, manifest)
        self.assertIn(proposal.status, (PatchStatus.PROPOSED, PatchStatus.REQUIRES_REVIEW))
        if proposal.proposed_content:
            self.assertIn("requests>=2.28.0", proposal.proposed_content)
            self.assertIn("flask==2.0.0", proposal.proposed_content)
            self.assertIn("numpy>=1.20", proposal.proposed_content)

    def test_missing_fixed_version_produces_review_required(self):
        manifest = "requests==2.25.0\n"
        req = _dep_req("requests", fixed=None)
        req.fixed_version = None  # explicit
        proposal = self.strategy.generate(req, manifest)
        self.assertEqual(proposal.status, PatchStatus.REQUIRES_REVIEW)
        self.assertIsNone(proposal.proposed_content)

    def test_invented_version_not_present(self):
        """Strategy must not invent a fixed version when advisory has none."""
        manifest = "requests==2.25.0\n"
        req = _dep_req("requests", fixed=None)
        proposal = self.strategy.generate(req, manifest)
        # proposed_content must be None when no fixed_version
        self.assertIsNone(proposal.proposed_content)

    def test_unrelated_packages_preserved(self):
        manifest = "flask==2.0.0\nrequests==2.25.0\nnumpy>=1.20\n"
        req = _dep_req("requests", fixed="2.28.0")
        proposal = self.strategy.generate(req, manifest)
        if proposal.proposed_content:
            self.assertIn("flask==2.0.0", proposal.proposed_content)
            self.assertIn("numpy>=1.20", proposal.proposed_content)

    def test_package_json_updated(self):
        manifest = '{"dependencies": {"axios": "0.21.0", "lodash": "4.17.20"}}'
        req = _dep_req("axios", fixed="0.21.4", manifest="package.json")
        proposal = self.strategy.generate(req, manifest)
        if proposal.proposed_content:
            self.assertIn("0.21.4", proposal.proposed_content)
            self.assertIn("lodash", proposal.proposed_content)


# ── Unsupported fallback ────────────────────────────────────────────────────

class TestUnsupportedStrategy(unittest.TestCase):

    def test_always_handles(self):
        req = _sast_req("CWE-999")
        s = UnsupportedStrategy()
        self.assertTrue(s.can_handle(req))

    def test_produces_unsupported_status(self):
        req = _sast_req("CWE-999")
        s = UnsupportedStrategy()
        proposal = s.generate(req, "")
        self.assertEqual(proposal.status, PatchStatus.UNSUPPORTED)

    def test_get_strategy_unsupported_finding(self):
        req = _sast_req("CWE-0000-UNKNOWN")
        req.cwe_id = "CWE-UNKNOWN"
        strategy = get_strategy(req)
        # Should fall back to unsupported
        proposal = strategy.generate(req, "")
        self.assertEqual(proposal.status, PatchStatus.UNSUPPORTED)


if __name__ == "__main__":
    unittest.main()

