"""Core data models for the Vulnerability and Dependency Graph Auditor."""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"


class FindingType(str, Enum):
    DEPENDENCY_VULNERABILITY = "DEPENDENCY_VULNERABILITY"
    SAST_VULNERABILITY = "SAST_VULNERABILITY"
    SECRET_LEAK = "SECRET_LEAK"
    CODE_SMELL = "CODE_SMELL"


class CodeLocation(BaseModel):
    file_path: str
    line: int
    col: int = 1
    end_line: Optional[int] = None
    end_col: Optional[int] = None
    snippet: Optional[str] = None


class EvidenceItem(BaseModel):
    source_type: str = Field(
        ...,
        description="Type of evidence: e.g., 'AST_NODE', 'CALL_GRAPH_PATH', 'OSV_RECORD', 'MANIFEST_ENTRY'"
    )
    description: str
    location: Optional[CodeLocation] = None
    raw_evidence: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    finding_type: FindingType
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    package_name: Optional[str] = None
    ecosystem: Optional[str] = None
    advisory_id: Optional[str] = None
    current_version: Optional[str] = None
    fixed_version: Optional[str] = None
    affected_range: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = Field(default_factory=list)
    locations: List[CodeLocation] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    remediation_advice: Optional[str] = None
    proposed_patch: Optional[str] = None
    agent_reviews: List[Dict[str, Any]] = Field(default_factory=list)
    contextual_assessment: Optional[str] = None
    agent_remediation: Optional[str] = None


class DiscoveredFile(BaseModel):
    path: str
    relative_path: str
    language: Optional[str] = None
    size_bytes: int
    is_manifest: bool = False
    manifest_type: Optional[str] = None


class ScanSummary(BaseModel):
    total_files_discovered: int = 0
    scanned_files_count: int = 0
    skipped_files_count: int = 0
    languages: Dict[str, int] = Field(default_factory=dict)
    findings_count_by_severity: Dict[str, int] = Field(default_factory=dict)
    duration_seconds: float = 0.0
    manifests_discovered_count: int = 0
    manifests_parsed_count: int = 0
    dependencies_total_count: int = 0
    direct_dependencies_count: int = 0
    transitive_dependencies_count: int = 0
    packages_checked_advisories_count: int = 0
    advisory_matches_count: int = 0
    advisory_lookup_failures_count: int = 0
    cache_hits_count: int = 0
    source_files_discovered_count: int = 0
    source_files_parsed_count: int = 0
    source_files_failed_count: int = 0
    sast_findings_count: int = 0
    sast_rules_executed_count: int = 0
    agents_executed_count: int = 0
    agents_skipped_count: int = 0
    agents_failed_count: int = 0


class ScanResult(BaseModel):
    scan_id: str
    target_path_or_url: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    summary: ScanSummary
    findings: List[Finding] = Field(default_factory=list)
    graph_metrics: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    agent_traces: List[Dict[str, Any]] = Field(default_factory=list)
    orchestrator_mode: str = "OFFLINE_DETERMINISTIC"

