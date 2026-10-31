"""Shared data models for the multi-agent orchestration layer."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from auditor.core.models import Finding


class AgentStatus(str, Enum):
    SUCCESS = "SUCCESS"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


class AnalysisMode(str, Enum):
    LLM = "LLM"
    DETERMINISTIC = "DETERMINISTIC"


class AnalysisContext(BaseModel):
    """Read-only snapshot of scan evidence passed to every agent."""

    scan_id: str
    findings: List[Finding] = Field(default_factory=list)
    graph_metrics: Dict[str, Any] = Field(default_factory=dict)
    # file_path -> short redacted excerpt (max 500 chars)
    source_excerpts: Dict[str, str] = Field(default_factory=dict)
    dep_records_summary: List[Dict[str, Any]] = Field(default_factory=list)
    mode: AnalysisMode = AnalysisMode.DETERMINISTIC


class FindingUpdate(BaseModel):
    """Targeted update an agent may apply to an existing finding."""

    finding_id: str
    contextual_assessment: Optional[str] = None
    agent_remediation: Optional[str] = None
    agent_review_entry: Optional[Dict[str, Any]] = None


class AgentResult(BaseModel):
    """Result returned by a single agent after analysis."""

    agent_id: str
    role: str
    status: AgentStatus
    summary: str
    reviewed_finding_ids: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    analysis_mode: AnalysisMode = AnalysisMode.DETERMINISTIC
    finding_updates: List[FindingUpdate] = Field(default_factory=list)


class OrchestratorResult(BaseModel):
    """Combined output of the orchestrator after running all agents."""

    scan_id: str
    agent_results: List[AgentResult] = Field(default_factory=list)
    updated_findings: List[Finding] = Field(default_factory=list)
    agents_executed_count: int = 0
    agents_skipped_count: int = 0
    agents_failed_count: int = 0
    orchestrator_mode: str = "OFFLINE_DETERMINISTIC"
    warnings: List[str] = Field(default_factory=list)

