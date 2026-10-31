"""Dependency Security Agent — reviews dependency declarations and OSV findings."""

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
from auditor.core.models import Finding, FindingType


class DependencySecurityAgent(BaseAgent):
    """Examines dependency records, resolution status, and OSV advisory matches.

    Constraints:
    - Distinguishes unresolved constraints from verified vulnerable versions.
    - Does NOT fabricate new findings.
    """

    agent_id = "dependency_security"
    role = "Dependency Security Agent"

    def analyze(self, context: AnalysisContext, provider: BaseProvider) -> AgentResult:
        dep_findings: List[Finding] = [
            f for f in context.findings if f.finding_type == FindingType.DEPENDENCY_VULNERABILITY
        ]
        dep_summary = context.dep_records_summary

        reviewed_ids = [f.id for f in dep_findings]
        warnings: List[str] = []
        finding_updates: List[FindingUpdate] = []

        # Identify unresolved dependencies from summary
        unresolved = [d for d in dep_summary if d.get("version") in (None, "", "UNRESOLVED")]
        if unresolved:
            warnings.append(
                f"{len(unresolved)} dependency record(s) have unresolved versions "
                "and could not be checked against advisories."
            )

        if not dep_findings and not dep_summary:
            return AgentResult(
                agent_id=self.agent_id,
                role=self.role,
                status=AgentStatus.SUCCESS,
                summary="No dependency records or findings present.",
                reviewed_finding_ids=[],
                warnings=warnings,
            )

        if provider.is_online and dep_findings:
            for finding in dep_findings:
                prompt = (
                    f"You are a security analysis assistant reviewing a dependency vulnerability.\n"
                    f"Package: {finding.package_name} @ {finding.current_version}\n"
                    f"Advisory: {finding.advisory_id}\n"
                    f"CVE: {finding.cve_id}\n"
                    f"Severity: {finding.severity.value}\n"
                    f"Affected range: {finding.affected_range}\n"
                    f"Fixed version: {finding.fixed_version}\n\n"
                    f"Provide a 1–2 sentence assessment of the attack surface and the "
                    f"recommended upgrade path."
                )
                try:
                    llm_response = provider.safe_complete(prompt)
                    finding_updates.append(
                        FindingUpdate(
                            finding_id=finding.id,
                            contextual_assessment=llm_response[:500],
                            agent_review_entry={
                                "agent": self.agent_id,
                                "mode": AnalysisMode.LLM,
                                "summary": "LLM attack-surface review applied.",
                            },
                        )
                    )
                except Exception as exc:
                    warnings.append(f"LLM call failed for {finding.id}: {exc}")
        else:
            for finding in dep_findings:
                advisory_str = finding.advisory_id or "unknown advisory"
                fixed_str = finding.fixed_version or "no fixed version recorded"
                assessment = (
                    f"Dependency {finding.package_name}@{finding.current_version} "
                    f"matched {advisory_str}. Recommended action: upgrade to {fixed_str}."
                )
                finding_updates.append(
                    FindingUpdate(
                        finding_id=finding.id,
                        contextual_assessment=assessment,
                        agent_review_entry={
                            "agent": self.agent_id,
                            "mode": AnalysisMode.DETERMINISTIC,
                            "advisory_id": finding.advisory_id,
                            "summary": "Deterministic dependency review applied.",
                        },
                    )
                )

        summary = (
            f"Reviewed {len(dep_findings)} dependency finding(s) across "
            f"{len(dep_summary)} declared package(s). "
            f"Unresolved versions: {len(unresolved)}."
        )

        return AgentResult(
            agent_id=self.agent_id,
            role=self.role,
            status=AgentStatus.SUCCESS,
            summary=summary,
            reviewed_finding_ids=reviewed_ids,
            warnings=warnings,
            finding_updates=finding_updates,
        )

