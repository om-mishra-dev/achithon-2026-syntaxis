"""Patch generator — builds RemediationRequests from Findings and runs strategies."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List, Optional

from auditor.core.models import Finding, FindingType
from auditor.core.safety import redact_secrets
from auditor.remediation.isolated_workspace import compute_file_hash
from auditor.remediation.models import (
    PatchProposal,
    PatchStatus,
    RemediationRequest,
    RemediationStrategy,
)
from auditor.remediation.strategies import get_strategy

# Maximum source-excerpt length sent to any strategy (prevents oversized prompts)
MAX_EXCERPT_CHARS = 2000


def _bounded_excerpt(content: str) -> str:
    return redact_secrets(content[:MAX_EXCERPT_CHARS])


def _request_from_sast_finding(
    finding: Finding,
    repo_root: str | Path,
) -> Optional[RemediationRequest]:
    """Build a RemediationRequest from a SAST finding."""
    if not finding.locations:
        return None
    loc = finding.locations[0]
    rel_path = loc.file_path

    # Read bounded source excerpt
    excerpt: Optional[str] = None
    full_path = Path(repo_root) / rel_path
    if full_path.exists():
        try:
            raw = full_path.read_text(encoding="utf-8", errors="replace")
            excerpt = _bounded_excerpt(raw)
        except Exception:
            pass

    return RemediationRequest(
        finding_id=finding.id,
        cwe_id=finding.cwe_id,
        finding_type=finding.finding_type.value,
        target_file=rel_path,
        source_excerpt=excerpt,
        sink_line=loc.line,
        existing_remediation_advice=finding.remediation_advice,
    )


def _request_from_dep_finding(
    finding: Finding,
    repo_root: str | Path,
    manifest_files: Optional[List[str]] = None,
) -> Optional[RemediationRequest]:
    """Build a RemediationRequest from a dependency vulnerability finding."""
    if not finding.package_name:
        return None

    # Try to identify manifest file from evidence
    manifest_file: Optional[str] = None
    for ev in finding.evidence:
        raw = ev.raw_evidence or {}
        mf = raw.get("manifest_file")
        if mf:
            manifest_file = mf
            break
    if not manifest_file and manifest_files:
        manifest_file = manifest_files[0]

    return RemediationRequest(
        finding_id=finding.id,
        advisory_id=finding.advisory_id,
        finding_type=finding.finding_type.value,
        package_name=finding.package_name,
        ecosystem=finding.ecosystem,
        current_version=finding.current_version,
        fixed_version=finding.fixed_version,
        manifest_file=manifest_file,
        existing_remediation_advice=finding.remediation_advice,
    )


class PatchGenerator:
    """Generates PatchProposals for eligible findings."""

    def __init__(self, repo_root: str | Path) -> None:
        self._repo_root = Path(repo_root).resolve()

    def generate_for_finding(
        self,
        finding: Finding,
        manifest_files: Optional[List[str]] = None,
    ) -> PatchProposal:
        """Generate the best possible patch proposal for a single finding."""
        if finding.finding_type == FindingType.SAST_VULNERABILITY:
            request = _request_from_sast_finding(finding, self._repo_root)
        elif finding.finding_type == FindingType.DEPENDENCY_VULNERABILITY:
            request = _request_from_dep_finding(finding, self._repo_root, manifest_files)
        else:
            request = None

        if request is None:
            from auditor.remediation.strategies import _make_patch_id
            return PatchProposal(
                patch_id=_make_patch_id(),
                finding_id=finding.id,
                strategy=RemediationStrategy.UNSUPPORTED,
                status=PatchStatus.UNSUPPORTED,
                explanation="Insufficient evidence to build a remediation request.",
                warnings=["Missing source location or package metadata."],
                generated_by="deterministic",
            )

        strategy = get_strategy(request)
        original_content = self._read_original(request)
        proposal = strategy.generate(request, original_content)

        # Record original hash for stale-check in validator
        if request.target_file:
            full = self._repo_root / request.target_file
            if full.exists():
                proposal.original_hash = compute_file_hash(full)
        elif request.manifest_file:
            full = self._repo_root / request.manifest_file
            if full.exists():
                proposal.original_hash = compute_file_hash(full)

        return proposal

    def generate_all(
        self,
        findings: List[Finding],
        manifest_files: Optional[List[str]] = None,
    ) -> List[PatchProposal]:
        proposals = []
        for finding in findings:
            proposal = self.generate_for_finding(finding, manifest_files)
            proposals.append(proposal)
        return proposals

    def _read_original(self, request: RemediationRequest) -> str:
        """Read the original file from repo, bounded and redacted."""
        target = request.target_file or request.manifest_file
        if not target:
            return ""
        full = self._repo_root / target
        if not full.exists():
            return ""
        try:
            raw = full.read_text(encoding="utf-8", errors="replace")
            # Do not redact manifest files (need exact content for diff)
            if request.finding_type == "DEPENDENCY_VULNERABILITY":
                return raw[:MAX_EXCERPT_CHARS * 2]
            return raw
        except Exception:
            return ""

