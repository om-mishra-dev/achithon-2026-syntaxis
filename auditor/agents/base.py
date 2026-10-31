"""Abstract base class for all analysis agents."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from auditor.agents.models import AgentResult, AgentStatus, AnalysisContext, AnalysisMode
from auditor.agents.provider import BaseProvider


class BaseAgent(ABC):
    """All agents extend this class and implement analyze()."""

    agent_id: str = "base"
    role: str = "Base Agent"

    def run(self, context: AnalysisContext, provider: BaseProvider) -> AgentResult:
        """Execute the agent, wrapping analyze() with timing and error handling."""
        t0 = time.monotonic()
        mode = AnalysisMode.LLM if provider.is_online else AnalysisMode.DETERMINISTIC
        try:
            result = self.analyze(context, provider)
            result.duration_seconds = round(time.monotonic() - t0, 4)
            result.analysis_mode = mode
            return result
        except Exception as exc:
            return AgentResult(
                agent_id=self.agent_id,
                role=self.role,
                status=AgentStatus.FAILED,
                summary=f"Agent raised an unhandled exception: {exc}",
                warnings=[str(exc)],
                duration_seconds=round(time.monotonic() - t0, 4),
                analysis_mode=mode,
            )

    @abstractmethod
    def analyze(self, context: AnalysisContext, provider: BaseProvider) -> AgentResult:
        """Perform analysis and return a result.  Must not modify context in place."""
        ...

