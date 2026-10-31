
"""Agent Orchestrator — coordinates all specialized security-analysis agents."""

from __future__ import annotations

import copy
import time
from typing import Dict, List, Optional

from auditor.agents.base import BaseAgent
from auditor.agents.code_agent import CodeAnalysisAgent
from auditor.agents.contextual_agent import ContextualReasoningAgent
from auditor.agents.dataflow_agent import DataFlowAnalysisAgent
from auditor.agents.dependency_agent import DependencySecurityAgent
from auditor.agents.models import (
    AgentResult,
    AgentStatus,
    AnalysisContext,
    AnalysisMode,
    FindingUpdate,
    OrchestratorResult,
)
from auditor.agents.provider import BaseProvider
from auditor.agents.remediation_agent import RemediationAgent
from auditor.core.config import ScanConfig
from auditor.core.models import Finding


def _build_agent_pipeline() -> List[BaseAgent]:
    """Return agents in their fixed invocation order."""
    return [
        CodeAnalysisAgent(),
        DependencySecurityAgent(),
        DataFlowAnalysisAgent(),
        ContextualReasoningAgent(),
        RemediationAgent(),
    ]


def _apply_updates(findings: List[Finding], updates: List[FindingUpdate], valid_ids: set) -> None:
    """Apply FindingUpdate objects to the findings list in-place.

    Only updates findings whose IDs appear in valid_ids to prevent fabrication.
    """
    id_to_finding: Dict[str, Finding] = {f.id: f for f in findings}

    for update in updates:
        if update.finding_id not in valid_ids:
            # Reject fabricated / unknown finding IDs
            continue
        finding = id_to_finding.get(update.finding_id)
        if finding is None:
            continue

        if update.contextual_assessment is not None:
            finding.contextual_assessment = update.contextual_assessment

        if update.agent_remediation is not None:
            finding.agent_remediation = update.agent_remediation

        if update.agent_review_entry is not None:
            finding.agent_reviews.append(update.agent_review_entry)


class AgentOrchestrator:
    """Coordinates the analysis workflow and combines results from all agents.

    Safety guarantees:
    - Agent exceptions are caught individually; findings are never erased.
    - Works with deep-copied findings so partial failures leave originals intact.
    - Offline mode makes zero network calls.
    """

    def __init__(self, config: ScanConfig, provider: BaseProvider) -> None:
        self._config = config
        self._provider = provider
        self._agents: List[BaseAgent] = _build_agent_pipeline()

    def run(
        self,
        context: AnalysisContext,
        findings: List[Finding],
    ) -> OrchestratorResult:
        """Run all agents against the context, applying their updates to findings."""
        # Work on a deep copy so any exception preserves the original findings
        working_findings = copy.deepcopy(findings)
        valid_ids = {f.id for f in working_findings}

        agent_results: List[AgentResult] = []
        executed = 0
        skipped = 0
        failed = 0
        warnings: List[str] = []

        # Determine orchestrator mode label
        mode_label = (
            "LLM_ASSISTED" if self._provider.is_online else "OFFLINE_DETERMINISTIC"
        )

        for agent in self._agents:
            t0 = time.monotonic()
            try:
                result: AgentResult = agent.run(context, self._provider)

                if result.status == AgentStatus.SKIPPED:
                    skipped += 1
                elif result.status == AgentStatus.FAILED:
                    failed += 1
                    warnings.append(
                        f"Agent '{agent.agent_id}' failed: {result.summary}"
                    )
                else:
                    executed += 1

                # Apply finding updates — only if agent did not outright fail
                if result.status != AgentStatus.FAILED:
                    _apply_updates(working_findings, result.finding_updates, valid_ids)

                agent_results.append(result)

            except Exception as exc:
                # Safety net: agent.run() already catches exceptions internally,
                # but this outer guard ensures the loop always continues.
                failed += 1
                duration = round(time.monotonic() - t0, 4)
                err_result = AgentResult(
                    agent_id=agent.agent_id,
                    role=agent.role,
                    status=AgentStatus.FAILED,
                    summary=f"Unhandled orchestrator-level exception: {exc}",
                    warnings=[str(exc)],
                    duration_seconds=duration,
                    analysis_mode=AnalysisMode.DETERMINISTIC,
                )
                agent_results.append(err_result)
                warnings.append(
                    f"Orchestrator caught exception for agent '{agent.agent_id}': {exc}"
                )

        return OrchestratorResult(
            scan_id=context.scan_id,
            agent_results=agent_results,
            updated_findings=working_findings,
            agents_executed_count=executed,
            agents_skipped_count=skipped,
            agents_failed_count=failed,
            orchestrator_mode=mode_label,
            warnings=warnings,
        )

