"""Data models for Phase E remediation patch generation and validation."""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PatchStatus(str, Enum):
    PROPOSED = "proposed"
    REJECTED = "rejected"
    APPLIED_IN_ISOLATION = "applied_in_isolation"
    VALIDATED = "validated"
    VALIDATION_FAILED = "validation_failed"
    VALIDATION_INCOMPLETE = "validation_incomplete"
    REQUIRES_REVIEW = "requires_review"
    UNSUPPORTED = "unsupported"


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    INCOMPLETE = "incomplete"


class RemediationStrategy(str, Enum):
    SQL_PARAMETERIZATION = "sql_parameterization"
    COMMAND_INJECTION_ARGLIST = "command_injection_arglist"
    PATH_TRAVERSAL_VALIDATION = "path_traversal_validation"
    SAFE_DESERIALIZATION = "safe_deserialization"
    DEPENDENCY_VERSION_UPGRADE = "dependency_version_upgrade"
    LLM_ASSISTED = "llm_assisted"
    REVIEW_REQUIRED = "review_required"
    UNSUPPORTED = "unsupported"


class ValidationCheck(BaseModel):
    check_name: str
    status: CheckStatus
    detail: str = ""
    output: Optional[str] = None


class RemediationRequest(BaseModel):
    """Input to the patch generator for a single finding."""

    finding_id: str
    cwe_id: Optional[str] = None
    advisory_id: Optional[str] = None
    finding_type: str  # "SAST_VULNERABILITY" | "DEPENDENCY_VULNERABILITY"
    target_file: Optional[str] = None          # relative path within repo
    source_excerpt: Optional[str] = None       # bounded, redacted code context
    sink_line: Optional[int] = None
    existing_remediation_advice: Optional[str] = None
    # Dependency-specific
    package_name: Optional[str] = None
    ecosystem: Optional[str] = None
    current_version: Optional[str] = None
    fixed_version: Optional[str] = None        # from advisory; None = unknown
    manifest_file: Optional[str] = None        # relative path to manifest


class PatchProposal(BaseModel):
    """A proposed fix for a single finding."""

    patch_id: str
    finding_id: str
    strategy: RemediationStrategy
    status: PatchStatus = PatchStatus.PROPOSED
    target_file: Optional[str] = None         # relative path
    original_hash: Optional[str] = None       # SHA-256 of original file
    original_content: Optional[str] = None    # stored for comparison only
    proposed_content: Optional[str] = None    # full patched file content
    unified_diff: Optional[str] = None        # unified diff string
    explanation: str = ""
    warnings: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    generated_by: str = "deterministic"       # "deterministic" | "llm"
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


class PatchValidationResult(BaseModel):
    """Outcome of validating a PatchProposal in an isolated workspace."""

    patch_id: str
    finding_id: str
    overall_status: PatchStatus
    checks: List[ValidationCheck] = Field(default_factory=list)
    security_reanalysis_cleared: Optional[bool] = None  # None = not performed
    regression_detected: Optional[bool] = None
    failure_reason: Optional[str] = None
    requires_human_review: bool = True
    warnings: List[str] = Field(default_factory=list)


class RemediationReport(BaseModel):
    """Top-level report produced by the remediate command."""

    scan_id: str
    target: str
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    proposals: List[PatchProposal] = Field(default_factory=list)
    validation_results: List[PatchValidationResult] = Field(default_factory=list)
    unsupported_finding_ids: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

