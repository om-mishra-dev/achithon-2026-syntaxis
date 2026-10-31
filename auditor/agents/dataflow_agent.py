"""Data-Flow Analysis Agent — reviews taint-analysis evidence in SAST findings."""

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
from auditor.core.models import Finding, FindingType

# Evidence source_type labels produced by SAST taint tracker
_SOURCE_TYPES_INDICATING_SOURCE = {"SAST_SOURCE", "TAINT_SOURCE"}
_SOURCE_TYPES_INDICATING_SINK = {"SAST_SINK", "TAINT_SINK"}


class DataFlowAnalysisAgent(BaseAgent):
    """Reviews source-to-sink evidence in SAST findings.

    Explicitly reports missing cross-function flow evidence rather than guessing.
    """

    agent_id = "data_flow"
    role = "Data-Flow Analysis Agent"

    def analyze(self, context: AnalysisContext, provider: BaseProvider) -> AgentResult:
        sast_findings: List[Finding] = [
            f for f in context.findings if f.finding_type == FindingType.SAST_VULNERABILITY
        ]

        if not sast_findings:
            return AgentResult(
                agent_id=self.agent_id,
                role=self.role,
                status=AgentStatus.SUCCESS,
                summary="No SAST findings to review for data-flow evidence.",
            )

        reviewed_ids: List[str] = []
        warnings: List[str] = []
        finding_updates: List[FindingUpdate] = []

        complete_flows = 0
        incomplete_flows = 0

        for finding in sast_findings:
            reviewed_ids.append(finding.id)
            evidence_types: Set[str] = {ev.source_type for ev in finding.evidence}

            has_source = bool(evidence_types & _SOURCE_TYPES_INDICATING_SOURCE)
            has_sink = bool(evidence_types & _SOURCE_TYPES_INDICATING_SINK)
            has_complete_flow = has_source and has_sink

            if has_complete_flow:
                complete_flows += 1
                flow_label = "complete source-to-sink flow documented"
            elif has_source:
                incomplete_flows += 1
                flow_label = "taint source identified; sink evidence absent (inter-procedural gap possible)"
                warnings.append(
                    f"Finding {finding.id}: sink evidence absent — cross-function flow cannot be confirmed."
                )
            elif has_sink:
                incomplete_flows += 1
                flow_label = "sink identified; explicit source evidence absent"
                warnings.append(
                    f"Finding {finding.id}: source evidence absent — taint origin unconfirmed."
                )
            else:
                incomplete_flows += 1
                flow_label = "no explicit taint-flow evidence; finding based on pattern matching"

            if provider.is_online:
                prompt = (
                    f"You are reviewing data-flow evidence for a security finding.\n"
                    f"Finding: {finding.title} ({finding.cwe_id})\n"
                    f"Evidence types present: {sorted(evidence_types)}\n"
                    f"Flow status: {flow_label}\n\n"
                    f"Describe in 1–2 sentences whether the data-flow path is "
                    f"confirmed and what additional evidence would strengthen it."
                )
                try:
                    llm_response = provider.safe_complete(prompt)
                    finding_updates.append(
                        FindingUpdate(
                            finding_id=finding.id,
                            agent_review_entry={
                                "agent": self.agent_id,
                                "mode": AnalysisMode.LLM,
                                "flow_label": flow_label,
                                "llm_assessment": llm_response[:400],
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
                                "flow_label": flow_label,
                                "warning": str(exc),
                            },
                        )
                    )
            else:
                finding_updates.append(
                    FindingUpdate(
                        finding_id=finding.id,
                        agent_review_entry={
                            "agent": self.agent_id,
                            "mode": AnalysisMode.DETERMINISTIC,
                            "flow_label": flow_label,
                            "has_source": has_source,
                            "has_sink": has_sink,
                        },
                    )
                )

        summary = (
            f"Data-flow review of {len(sast_findings)} SAST finding(s): "
            f"{complete_flows} with complete source-to-sink evidence, "
            f"{incomplete_flows} with incomplete or absent flow evidence."
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

