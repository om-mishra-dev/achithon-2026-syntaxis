"""Code Analysis Agent — reviews SAST and AST call-graph evidence."""

from __future__ import annotations

from collections import Counter
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


class CodeAnalysisAgent(BaseAgent):
    """Examines AST, call-graph, and deterministic SAST evidence.

    Constraints:
    - NEVER fabricates new findings; only annotates existing ones.
    - Applies redact_secrets() before sending any content to the provider.
    """

    agent_id = "code_analysis"
    role = "Code Analysis Agent"

    def analyze(self, context: AnalysisContext, provider: BaseProvider) -> AgentResult:
        sast_findings: List[Finding] = [
            f for f in context.findings if f.finding_type == FindingType.SAST_VULNERABILITY
        ]

        if not sast_findings:
            return AgentResult(
                agent_id=self.agent_id,
                role=self.role,
                status=AgentStatus.SUCCESS,
                summary="No SAST findings present; code analysis skipped.",
                reviewed_finding_ids=[],
            )

        cwe_counts = Counter(f.cwe_id for f in sast_findings if f.cwe_id)
        sev_counts = Counter(f.severity.value for f in sast_findings)
        reviewed_ids = [f.id for f in sast_findings]

        finding_updates: List[FindingUpdate] = []

        if provider.is_online:
            # LLM-assisted: build a concise evidence prompt (no secrets)
            for finding in sast_findings:
                snippet = ""
                if finding.locations:
                    fp = finding.locations[0].file_path
                    snippet = context.source_excerpts.get(fp, "")[:400]

                prompt = (
                    f"You are a security analysis assistant. A deterministic SAST rule detected:\n"
                    f"Title: {finding.title}\n"
                    f"CWE: {finding.cwe_id}\n"
                    f"Severity: {finding.severity.value}\n"
                    f"Description: {finding.description}\n"
                    f"Code excerpt (redacted):\n{snippet}\n\n"
                    f"Provide a 1–2 sentence contextual assessment of this finding "
                    f"and a specific remediation recommendation."
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
                                "summary": "LLM contextual review applied.",
                            },
                        )
                    )
                except Exception as exc:
                    finding_updates.append(
                        FindingUpdate(
                            finding_id=finding.id,
                            agent_review_entry={
                                "agent": self.agent_id,
                                "mode": AnalysisMode.LLM,
                                "warning": f"LLM call failed: {exc}",
                            },
                        )
                    )
        else:
            # Deterministic mode: annotate with rule-based summaries
            for finding in sast_findings:
                assessment = (
                    f"Deterministic SAST rule matched {finding.cwe_id or 'unknown CWE'} "
                    f"with {finding.confidence.value} confidence. "
                    f"Evidence: {len(finding.evidence)} item(s) collected."
                )
                finding_updates.append(
                    FindingUpdate(
                        finding_id=finding.id,
                        contextual_assessment=assessment,
                        agent_review_entry={
                            "agent": self.agent_id,
                            "mode": AnalysisMode.DETERMINISTIC,
                            "summary": "Deterministic code analysis applied.",
                        },
                    )
                )

        cwe_summary = ", ".join(f"{cwe}×{cnt}" for cwe, cnt in cwe_counts.most_common(5))
        summary = (
            f"Reviewed {len(sast_findings)} SAST finding(s). "
            f"Severity: {dict(sev_counts)}. "
            f"CWEs: {cwe_summary or 'N/A'}."
        )

        return AgentResult(
            agent_id=self.agent_id,
            role=self.role,
            status=AgentStatus.SUCCESS,
            summary=summary,
            reviewed_finding_ids=reviewed_ids,
            finding_updates=finding_updates,
        )

