"""Configuration management for scan executions."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    target: str = Field(..., description="Target repository path or GitHub/Git URL")
    output_formats: List[str] = Field(
        default_factory=lambda: ["terminal"],
        description="List of formats: 'terminal', 'json', 'markdown', 'sarif'"
    )
    output_path: Optional[str] = Field(
        None,
        description="Path to save report output file (if not specified, outputs to stdout or default file)"
    )
    offline_mode: bool = Field(
        False,
        description="Run in offline mode without querying external advisory APIs (OSV) or LLM endpoints"
    )
    include_sast: bool = Field(True, description="Enable static application security testing")
    include_deps: bool = Field(True, description="Enable dependency manifest vulnerability checking")
    include_agents: bool = Field(True, description="Enable AI agent contextual analysis")
    enable_llm: bool = Field(True, description="Enable LLM provider calls when credentials exist; if False, uses deterministic fallback")
    llm_provider: str = Field("auto", description="LLM provider name: 'auto', 'offline', 'mock', 'openai', etc.")
    llm_model: Optional[str] = Field(None, description="Specific LLM model identifier")
    agent_timeout_seconds: int = Field(15, description="Per-agent execution timeout in seconds")
    max_depth: int = Field(15, description="Max directory search depth")
    timeout_seconds: int = Field(120, description="Total timeout for scanning operations")
    verbose: bool = Field(False, description="Enable verbose debug logging")

