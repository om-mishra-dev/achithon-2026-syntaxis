"""Remediation Agent — proposes evidence-grounded remediation advice.

Does NOT modify repository files, create patches, or run tests.
"""

from __future__ import annotations

from typing import List

from auditor.agents.base import BaseAgent
from auditor.agents.models import (
    AgentResult,
    AgentStatus,
    AnalysisContext,
    AnalysisMode,
    FindingUpdate,
)
from auditor.agents.provider import BaseProvider
from auditor.core.models import FindingType, Severity

# Template remediation advice keyed by CWE
_CWE_REMEDIATION: dict[str, str] = {
    "CWE-78": (
        "Avoid passing unsanitized user input to shell commands. "
        "Use subprocess with a list of arguments instead of shell=True, "
        "or apply shlex.quote() on every user-controlled token."
    ),
    "CWE-89": (
        "Use parameterized queries or prepared statements instead of string concatenation. "
        "Never interpolate user-supplied values directly into SQL."
    ),
    "CWE-22": (
        "Validate and sanitize file paths before use. "
        "Resolve paths with pathlib.Path.resolve() and confirm they remain under the allowed root."
    ),
    "CWE-502": (
        "Avoid deserializing untrusted data with pickle or yaml.load. "
        "Use safe alternatives such as json, yaml.safe_load, or msgpack."
    ),
    "CWE-79": (
        "Escape all user-supplied content before rendering in HTML. "
        "Use template auto-escaping or an established sanitization library."
    ),
}

_SEVERITY_UPGRADE_GUIDANCE: dict[Severity, str] = {
    Severity.CRITICAL: "Upgrade immediately; this issue is critical and likely exploitable.",
    Severity.HIGH: "Prioritize upgrade in the current sprint.",
    Severity.MEDIUM: "Plan an upgrade within the next release cycle.",
    Severity.LOW: "Schedule upgrade at your next convenience.",
    Severity.INFO: "Review advisory for applicability to your deployment.",
}


class RemediationAgent(BaseAgent):
    """Generates agent_remediation text for each finding without modifying files."""

    agent_id = "remediation"
    role = "Remediation Agent"

    def analyze(self, context: AnalysisContext, provider: BaseProvider) -> AgentResult:
        if not context.findings:
            return AgentResult(
                agent_id=self.agent_id,
                role=self.role,
                status=AgentStatus.SUCCESS,
                summary="No findings to remediate.",
            )

        reviewed_ids: List[str] = []
        warnings: List[str] = []
        finding_updates: List[FindingUpdate] = []

        for finding in context.findings:
            reviewed_ids.append(finding.id)

            if provider.is_online:
                existing_advice = finding.remediation_advice or ""
                prompt = (
                    f"You are a security remediation expert.\n"
                    f"Finding: {finding.title}\n"
                    f"CWE: {finding.cwe_id}\n"
                    f"Severity: {finding.severity.value}\n"
                    f"Type: {finding.finding_type.value}\n"
                    f"Package: {finding.package_name or 'N/A'} @ {finding.current_version or 'N/A'}\n"
                    f"Fixed version: {finding.fixed_version or 'N/A'}\n"
                    f"Existing advice: {existing_advice[:200]}\n\n"
                    f"Provide a concrete, actionable 2–3 sentence remediation recommendation. "
                    f"Do NOT suggest modifying files directly; recommend code patterns instead."
                )
                try:
                    llm_response = provider.safe_complete(prompt)
                    finding_updates.append(
                        FindingUpdate(
                            finding_id=finding.id,
                            agent_remediation=llm_response[:600],
                            agent_review_entry={
                                "agent": self.agent_id,
                                "mode": AnalysisMode.LLM,
                                "summary": "LLM remediation advice generated.",
                            },
                        )
                    )
                except Exception as exc:
                    warnings.append(f"LLM remediation failed for {finding.id}: {exc}")
                    # Fall back to deterministic
                    remediation = self._deterministic_remediation(finding)
                    finding_updates.append(
                        FindingUpdate(
                            finding_id=finding.id,
                            agent_remediation=remediation,
                            agent_review_entry={
                                "agent": self.agent_id,
                                "mode": AnalysisMode.DETERMINISTIC,
                                "warning": str(exc),
                            },
                        )
                    )
            else:
                remediation = self._deterministic_remediation(finding)
                finding_updates.append(
                    FindingUpdate(
                        finding_id=finding.id,
                        agent_remediation=remediation,
                        agent_review_entry={
                            "agent": self.agent_id,
                            "mode": AnalysisMode.DETERMINISTIC,
                            "summary": "Rule-based remediation advice generated.",
                        },
                    )
                )

        summary = f"Remediation advice generated for {len(reviewed_ids)} finding(s)."
        return AgentResult(
            agent_id=self.agent_id,
            role=self.role,
            status=AgentStatus.SUCCESS,
            summary=summary,
            reviewed_finding_ids=reviewed_ids,
            warnings=warnings,
            finding_updates=finding_updates,
        )

    def _deterministic_remediation(self, finding) -> str:
        """Build rule-based remediation from CWE lookup and severity guidance."""
        parts: List[str] = []

        # Use existing remediation_advice if present
        if finding.remediation_advice:
            parts.append(finding.remediation_advice)

        # Add CWE-specific guidance
        if finding.cwe_id and finding.cwe_id in _CWE_REMEDIATION:
            cwe_advice = _CWE_REMEDIATION[finding.cwe_id]
            if cwe_advice not in parts:
                parts.append(cwe_advice)

        # Add dependency-specific upgrade guidance
        if finding.finding_type == FindingType.DEPENDENCY_VULNERABILITY:
            if finding.fixed_version:
                parts.append(f"Upgrade {finding.package_name} to version {finding.fixed_version} or later.")
            elif finding.advisory_id:
                parts.append(
                    f"Check {finding.advisory_id} for patched versions and upgrade as soon as possible."
                )

        # Add severity-level urgency
        severity_note = _SEVERITY_UPGRADE_GUIDANCE.get(finding.severity, "")
        if severity_note:
            parts.append(severity_note)

        return " ".join(parts) if parts else "Review this finding and apply appropriate mitigation."

