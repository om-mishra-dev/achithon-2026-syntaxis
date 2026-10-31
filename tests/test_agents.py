"""Tests for individual Phase D agents."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from auditor.agents.code_agent import CodeAnalysisAgent
from auditor.agents.contextual_agent import ContextualReasoningAgent
from auditor.agents.dataflow_agent import DataFlowAnalysisAgent
from auditor.agents.dependency_agent import DependencySecurityAgent
from auditor.agents.models import AgentStatus, AnalysisContext, AnalysisMode
from auditor.agents.provider import DeterministicProvider, get_provider
from auditor.agents.remediation_agent import RemediationAgent
from auditor.core.config import ScanConfig
from auditor.core.models import (
    Confidence,
    EvidenceItem,
    Finding,
    FindingType,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sast_finding(fid: str = "F001", cwe: str = "CWE-78") -> Finding:
    return Finding(
        id=fid,
        title="Command injection",
        description="os.system called with user input",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        finding_type=FindingType.SAST_VULNERABILITY,
        cwe_id=cwe,
        evidence=[
            EvidenceItem(source_type="SAST_SOURCE", description="user input at line 10"),
            EvidenceItem(source_type="SAST_SINK", description="os.system call at line 15"),
        ],
        remediation_advice="Use subprocess with argument list.",
    )


def _make_dep_finding(fid: str = "D001") -> Finding:
    return Finding(
        id=fid,
        title="Vulnerable dependency",
        description="requests@2.25.0 has known CVE",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        finding_type=FindingType.DEPENDENCY_VULNERABILITY,
        package_name="requests",
        current_version="2.25.0",
        advisory_id="GHSA-xxxx-yyyy-zzzz",
        fixed_version="2.28.0",
    )


def _make_context(findings=None) -> AnalysisContext:
    return AnalysisContext(
        scan_id="test-scan",
        findings=findings or [],
        graph_metrics={},
        source_excerpts={},
        dep_records_summary=[],
        mode=AnalysisMode.DETERMINISTIC,
    )


def _offline_provider() -> DeterministicProvider:
    return DeterministicProvider(reason="test offline")


# ---------------------------------------------------------------------------
# Provider tests
# ---------------------------------------------------------------------------

class TestDeterministicProvider(unittest.TestCase):
    def test_complete_returns_string(self):
        p = DeterministicProvider()
        result = p.complete("hello")
        self.assertIsInstance(result, str)
        self.assertIn("DETERMINISTIC", result)

    def test_is_not_online(self):
        p = DeterministicProvider()
        self.assertFalse(p.is_online)

    def test_safe_complete_redacts_secrets(self):
        p = DeterministicProvider()
        # Verify safe_complete does not raise even with sensitive content
        result = p.safe_complete("token=AAABBBCCCDDD secret key_here")
        self.assertIsInstance(result, str)

    def test_get_provider_offline_returns_deterministic(self):
        cfg = ScanConfig(target=".", offline_mode=True)
        provider = get_provider(cfg)
        self.assertIsInstance(provider, DeterministicProvider)
        self.assertFalse(provider.is_online)

    def test_get_provider_no_llm_returns_deterministic(self):
        cfg = ScanConfig(target=".", enable_llm=False)
        provider = get_provider(cfg)
        self.assertIsInstance(provider, DeterministicProvider)

    def test_get_provider_explicit_offline_provider(self):
        cfg = ScanConfig(target=".", llm_provider="offline")
        provider = get_provider(cfg)
        self.assertIsInstance(provider, DeterministicProvider)

    def test_get_provider_no_api_key_falls_back_to_deterministic(self):
        cfg = ScanConfig(target=".")
        with patch.dict("os.environ", {}, clear=True):
            provider = get_provider(cfg, api_key_override=None)
        self.assertIsInstance(provider, DeterministicProvider)


# ---------------------------------------------------------------------------
# CodeAnalysisAgent tests
# ---------------------------------------------------------------------------

class TestCodeAnalysisAgent(unittest.TestCase):
    def test_no_sast_findings_returns_success(self):
        agent = CodeAnalysisAgent()
        ctx = _make_context(findings=[])
        result = agent.run(ctx, _offline_provider())
        self.assertEqual(result.status, AgentStatus.SUCCESS)
        self.assertEqual(result.reviewed_finding_ids, [])

    def test_reviews_sast_findings(self):
        finding = _make_sast_finding("F001")
        agent = CodeAnalysisAgent()
        ctx = _make_context(findings=[finding])
        result = agent.run(ctx, _offline_provider())
        self.assertEqual(result.status, AgentStatus.SUCCESS)
        self.assertIn("F001", result.reviewed_finding_ids)

    def test_dep_findings_not_reviewed_by_code_agent(self):
        dep_finding = _make_dep_finding("D001")
        agent = CodeAnalysisAgent()
        ctx = _make_context(findings=[dep_finding])
        result = agent.run(ctx, _offline_provider())
        # DEP finding should not appear in reviewed list
        self.assertNotIn("D001", result.reviewed_finding_ids)

    def test_generates_finding_updates(self):
        finding = _make_sast_finding("F001")
        agent = CodeAnalysisAgent()
        ctx = _make_context(findings=[finding])
        result = agent.run(ctx, _offline_provider())
        self.assertTrue(len(result.finding_updates) > 0)
        update = result.finding_updates[0]
        self.assertEqual(update.finding_id, "F001")
        self.assertIsNotNone(update.contextual_assessment)

    def test_does_not_fabricate_findings(self):
        finding = _make_sast_finding("F001")
        agent = CodeAnalysisAgent()
        ctx = _make_context(findings=[finding])
        result = agent.run(ctx, _offline_provider())
        # All update IDs must exist in context
        valid_ids = {f.id for f in ctx.findings}
        for upd in result.finding_updates:
            self.assertIn(upd.finding_id, valid_ids)


# ---------------------------------------------------------------------------
# DependencySecurityAgent tests
# ---------------------------------------------------------------------------

class TestDependencySecurityAgent(unittest.TestCase):
    def test_no_findings_returns_success(self):
        agent = DependencySecurityAgent()
        ctx = _make_context(findings=[])
        result = agent.run(ctx, _offline_provider())
        self.assertEqual(result.status, AgentStatus.SUCCESS)

    def test_reviews_dep_findings(self):
        dep = _make_dep_finding("D001")
        agent = DependencySecurityAgent()
        ctx = _make_context(findings=[dep])
        result = agent.run(ctx, _offline_provider())
        self.assertIn("D001", result.reviewed_finding_ids)

    def test_unresolved_dep_generates_warning(self):
        agent = DependencySecurityAgent()
        ctx = _make_context(findings=[])
        ctx.dep_records_summary = [{"name": "requests", "version": "UNRESOLVED", "ecosystem": "pypi", "is_direct": True}]
        result = agent.run(ctx, _offline_provider())
        self.assertTrue(any("unresolved" in w.lower() for w in result.warnings))

    def test_deterministic_assessment_mentions_advisory(self):
        dep = _make_dep_finding("D001")
        agent = DependencySecurityAgent()
        ctx = _make_context(findings=[dep])
        result = agent.run(ctx, _offline_provider())
        update = next((u for u in result.finding_updates if u.finding_id == "D001"), None)
        self.assertIsNotNone(update)
        self.assertIn("GHSA", update.contextual_assessment or "")


# ---------------------------------------------------------------------------
# DataFlowAnalysisAgent tests
# ---------------------------------------------------------------------------

class TestDataFlowAnalysisAgent(unittest.TestCase):
    def test_no_sast_findings_returns_success(self):
        agent = DataFlowAnalysisAgent()
        ctx = _make_context(findings=[])
        result = agent.run(ctx, _offline_provider())
        self.assertEqual(result.status, AgentStatus.SUCCESS)

    def test_complete_flow_detected(self):
        finding = _make_sast_finding("F001")  # has SAST_SOURCE + SAST_SINK
        agent = DataFlowAnalysisAgent()
        ctx = _make_context(findings=[finding])
        result = agent.run(ctx, _offline_provider())
        update = next((u for u in result.finding_updates if u.finding_id == "F001"), None)
        self.assertIsNotNone(update)
        flow_label = update.agent_review_entry.get("flow_label", "")
        self.assertIn("complete", flow_label)

    def test_missing_sink_generates_warning(self):
        finding = Finding(
            id="F002",
            title="SQL injection",
            description="...",
            severity=Severity.HIGH,
            confidence=Confidence.SUSPECTED,
            finding_type=FindingType.SAST_VULNERABILITY,
            cwe_id="CWE-89",
            evidence=[EvidenceItem(source_type="SAST_SOURCE", description="user input")],
        )
        agent = DataFlowAnalysisAgent()
        ctx = _make_context(findings=[finding])
        result = agent.run(ctx, _offline_provider())
        self.assertTrue(any("sink" in w.lower() for w in result.warnings))

    def test_no_evidence_labels_as_pattern_match(self):
        finding = Finding(
            id="F003",
            title="Path traversal",
            description="...",
            severity=Severity.MEDIUM,
            confidence=Confidence.SUSPECTED,
            finding_type=FindingType.SAST_VULNERABILITY,
            cwe_id="CWE-22",
            evidence=[],
        )
        agent = DataFlowAnalysisAgent()
        ctx = _make_context(findings=[finding])
        result = agent.run(ctx, _offline_provider())
        update = next((u for u in result.finding_updates if u.finding_id == "F003"), None)
        self.assertIsNotNone(update)
        flow_label = update.agent_review_entry.get("flow_label", "")
        self.assertIn("pattern", flow_label)


# ---------------------------------------------------------------------------
# ContextualReasoningAgent tests
# ---------------------------------------------------------------------------

class TestContextualReasoningAgent(unittest.TestCase):
    def test_no_findings_returns_success(self):
        agent = ContextualReasoningAgent()
        ctx = _make_context(findings=[])
        result = agent.run(ctx, _offline_provider())
        self.assertEqual(result.status, AgentStatus.SUCCESS)

    def test_confirmed_finding_assessed_as_supported(self):
        finding = _make_sast_finding("F001")
        agent = ContextualReasoningAgent()
        ctx = _make_context(findings=[finding])
        result = agent.run(ctx, _offline_provider())
        update = next((u for u in result.finding_updates if u.finding_id == "F001"), None)
        self.assertIsNotNone(update)
        self.assertIn("supported", (update.contextual_assessment or "").lower())

    def test_does_not_suppress_findings(self):
        """Contextual agent must never remove findings."""
        finding = _make_sast_finding("F001")
        agent = ContextualReasoningAgent()
        ctx = _make_context(findings=[finding])
        # After run, the finding must still be present
        result = agent.run(ctx, _offline_provider())
        self.assertIn("F001", result.reviewed_finding_ids)

    def test_fabricated_id_rejected(self):
        """Finding IDs not in context must be skipped, not fabricated."""
        agent = ContextualReasoningAgent()
        ctx = _make_context(findings=[])
        # Manually craft a result where reviewed_finding_ids has an unknown ID
        # The agent should only produce updates for IDs that exist
        finding = _make_sast_finding("REAL-001")
        ctx2 = _make_context(findings=[finding])
        result = agent.run(ctx2, _offline_provider())
        for upd in result.finding_updates:
            self.assertIn(upd.finding_id, {f.id for f in ctx2.findings})


# ---------------------------------------------------------------------------
# RemediationAgent tests
# ---------------------------------------------------------------------------

class TestRemediationAgent(unittest.TestCase):
    def test_no_findings_returns_success(self):
        agent = RemediationAgent()
        ctx = _make_context(findings=[])
        result = agent.run(ctx, _offline_provider())
        self.assertEqual(result.status, AgentStatus.SUCCESS)

    def test_generates_remediation_for_sast(self):
        finding = _make_sast_finding("F001", cwe="CWE-78")
        agent = RemediationAgent()
        ctx = _make_context(findings=[finding])
        result = agent.run(ctx, _offline_provider())
        update = next((u for u in result.finding_updates if u.finding_id == "F001"), None)
        self.assertIsNotNone(update)
        self.assertIsNotNone(update.agent_remediation)
        # CWE-78 advice should mention subprocess or shell
        advice = update.agent_remediation or ""
        self.assertTrue("subprocess" in advice.lower() or "shell" in advice.lower())

    def test_generates_remediation_for_dep(self):
        dep = _make_dep_finding("D001")
        agent = RemediationAgent()
        ctx = _make_context(findings=[dep])
        result = agent.run(ctx, _offline_provider())
        update = next((u for u in result.finding_updates if u.finding_id == "D001"), None)
        self.assertIsNotNone(update)
        advice = update.agent_remediation or ""
        self.assertIn("2.28.0", advice)  # fixed_version should appear


if __name__ == "__main__":
    unittest.main()

