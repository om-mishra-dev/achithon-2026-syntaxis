"""Contextual Reasoning Agent — evaluates plausibility of candidate findings."""

from __future__ import annotations

from typing import List, Set

from auditor.agents.base import BaseAgent
from auditor.agents.models import (
    AgentResult,
    AgentStatus,
    AnalysisContext,
    AnalysisMode,
    FindingUpdate,
)
from auditor.agents.provider import BaseProvider
from auditor.core.models import Confidence, Finding

# Minimum evidence items required to mark a finding as "supported"
_MIN_EVIDENCE_SUPPORTED = 1


class ContextualReasoningAgent(BaseAgent):
    """Evaluates whether candidate findings are plausible given available evidence.

    Constraints:
    - NEVER suppresses deterministic findings; only adds contextual_assessment.
    - Validates that all referenced finding IDs exist in context.findings.
    - Cannot invent new findings.
    """

    agent_id = "contextual_reasoning"
    role = "Contextual Reasoning Agent"

    def analyze(self, context: AnalysisContext, provider: BaseProvider) -> AgentResult:
        if not context.findings:
            return AgentResult(
                agent_id=self.agent_id,
                role=self.role,
                status=AgentStatus.SUCCESS,
                summary="No findings to assess contextually.",
            )

        valid_ids: Set[str] = {f.id for f in context.findings}
        reviewed_ids: List[str] = []
        warnings: List[str] = []
        finding_updates: List[FindingUpdate] = []

        for finding in context.findings:
            # Guard: validate finding.id exists (defend against fabricated references)
            if finding.id not in valid_ids:
                warnings.append(
                    f"Skipped unknown finding ID '{finding.id}' — not in analysis context."
                )
                continue

            reviewed_ids.append(finding.id)

            if provider.is_online:
                prompt = (
                    f"You are evaluating whether a security finding is plausible.\n"
                    f"Title: {finding.title}\n"
                    f"Severity: {finding.severity.value}\n"
                    f"Confidence: {finding.confidence.value}\n"
                    f"Evidence count: {len(finding.evidence)}\n"
                    f"Description: {finding.description[:300]}\n\n"
                    f"Reply with one of: 'supported', 'needs_review', 'insufficient_evidence'. "
                    f"Then provide a single sentence of justification."
                )
                try:
                    llm_response = provider.safe_complete(prompt)
                    assessment = llm_response[:500]
                    finding_updates.append(
                        FindingUpdate(
                            finding_id=finding.id,
                            contextual_assessment=assessment,
                            agent_review_entry={
                                "agent": self.agent_id,
                                "mode": AnalysisMode.LLM,
                                "assessment_raw": assessment,
                            },
                        )
                    )
                except Exception as exc:
                    warnings.append(f"LLM call failed for {finding.id}: {exc}")
                    finding_updates.append(
                        FindingUpdate(
                            finding_id=finding.id,
                            agent_review_entry={
                                "agent": self.agent_id,
                                "mode": AnalysisMode.LLM,
                                "warning": str(exc),
                            },
                        )
                    )
            else:
                # Deterministic heuristic: confidence + evidence count
                if finding.confidence == Confidence.CONFIRMED and len(finding.evidence) >= _MIN_EVIDENCE_SUPPORTED:
                    label = "supported"
                elif finding.confidence == Confidence.SUSPECTED or len(finding.evidence) >= _MIN_EVIDENCE_SUPPORTED:
                    label = "needs_review"
                else:
                    label = "insufficient_evidence"

                assessment = (
                    f"Heuristic assessment: {label}. "
                    f"Confidence={finding.confidence.value}, "
                    f"evidence_items={len(finding.evidence)}."
                )
                finding_updates.append(
                    FindingUpdate(
                        finding_id=finding.id,
                        contextual_assessment=assessment,
                        agent_review_entry={
                            "agent": self.agent_id,
                            "mode": AnalysisMode.DETERMINISTIC,
                            "label": label,
                            "evidence_count": len(finding.evidence),
                        },
                    )
                )

        summary = (
            f"Contextual assessment of {len(reviewed_ids)}/{len(context.findings)} finding(s) completed."
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

