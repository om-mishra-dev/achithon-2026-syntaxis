"""auditor.remediation — Phase E patch generation and validation package."""

from auditor.remediation.models import (
    CheckStatus,
    PatchProposal,
    PatchStatus,
    PatchValidationResult,
    RemediationReport,
    RemediationRequest,
    RemediationStrategy,
    ValidationCheck,
)
from auditor.remediation.patch_generator import PatchGenerator
from auditor.remediation.patch_validator import PatchValidator
from auditor.remediation.isolated_workspace import IsolatedWorkspace, IsolatedWorkspaceError

__all__ = [
    "CheckStatus",
    "IsolatedWorkspace",
    "IsolatedWorkspaceError",
    "PatchGenerator",
    "PatchProposal",
    "PatchStatus",
    "PatchValidationResult",
    "PatchValidator",
    "RemediationReport",
    "RemediationRequest",
    "RemediationStrategy",
    "ValidationCheck",
]

