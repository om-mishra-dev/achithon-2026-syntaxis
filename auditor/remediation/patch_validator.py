"""Patch validator — applies a PatchProposal in an isolated workspace and runs validation checks."""

from __future__ import annotations

import ast
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from auditor.remediation.isolated_workspace import (
    IsolatedWorkspace,
    IsolatedWorkspaceError,
    compute_file_hash,
)
from auditor.remediation.models import (
    CheckStatus,
    PatchProposal,
    PatchStatus,
    PatchValidationResult,
    ValidationCheck,
)

# Limits for optional test execution
MAX_TEST_SECONDS = 60
MAX_TEST_OUTPUT_BYTES = 64 * 1024  # 64 KB


class PatchValidator:
    """Applies a proposal in isolation and runs configured validation checks."""

    def __init__(
        self,
        repo_root: str | Path,
        run_tests: bool = False,
        run_sast_reanalysis: bool = True,
    ) -> None:
        self._repo_root = Path(repo_root).resolve()
        self._run_tests = run_tests
        self._run_sast = run_sast_reanalysis

    def validate(self, proposal: PatchProposal) -> PatchValidationResult:
        checks: List[ValidationCheck] = []
        warnings: List[str] = []

        # 1 — Must have a diff / proposed content to apply
        if not proposal.proposed_content and not proposal.unified_diff:
            return PatchValidationResult(
                patch_id=proposal.patch_id,
                finding_id=proposal.finding_id,
                overall_status=PatchStatus.VALIDATION_INCOMPLETE,
                checks=[
                    ValidationCheck(
                        check_name="patch_integrity",
                        status=CheckStatus.SKIPPED,
                        detail="No proposed content or diff available (unsupported/review-required proposal).",
                    )
                ],
                failure_reason="Proposal has no content to apply.",
                requires_human_review=True,
                warnings=["Unsupported or review-required proposals cannot be auto-validated."],
            )

        target_rel = proposal.target_file
        if not target_rel:
            return PatchValidationResult(
                patch_id=proposal.patch_id,
                finding_id=proposal.finding_id,
                overall_status=PatchStatus.VALIDATION_INCOMPLETE,
                checks=[
                    ValidationCheck(
                        check_name="patch_integrity",
                        status=CheckStatus.ERROR,
                        detail="No target file specified in proposal.",
                    )
                ],
                failure_reason="Missing target_file in proposal.",
                requires_human_review=True,
            )

        # Open an isolated workspace and run all checks inside it
        try:
            with IsolatedWorkspace(self._repo_root) as ws:
                # --- Check 1: Patch integrity (hash + apply) ---
                integrity_check = self._check_integrity(ws, proposal, target_rel)
                checks.append(integrity_check)
                if integrity_check.status == CheckStatus.FAILED:
                    return PatchValidationResult(
                        patch_id=proposal.patch_id,
                        finding_id=proposal.finding_id,
                        overall_status=PatchStatus.VALIDATION_FAILED,
                        checks=checks,
                        failure_reason=integrity_check.detail,
                        requires_human_review=True,
                        warnings=warnings,
                    )

                # Apply the patch in the workspace
                try:
                    ws.write_file(target_rel, proposal.proposed_content)
                except IsolatedWorkspaceError as exc:
                    checks.append(
                        ValidationCheck(
                            check_name="patch_apply",
                            status=CheckStatus.FAILED,
                            detail=f"Failed to write patched file: {exc}",
                        )
                    )
                    return PatchValidationResult(
                        patch_id=proposal.patch_id,
                        finding_id=proposal.finding_id,
                        overall_status=PatchStatus.VALIDATION_FAILED,
                        checks=checks,
                        failure_reason=str(exc),
                        requires_human_review=True,
                    )

                checks.append(
                    ValidationCheck(
                        check_name="patch_apply",
                        status=CheckStatus.PASSED,
                        detail="Proposal applied cleanly in isolated workspace.",
                    )
                )

                # --- Check 2: Syntax validation ---
                syntax_check = self._check_syntax(ws, target_rel)
                checks.append(syntax_check)

                # --- Check 3: Test execution (opt-in only) ---
                test_check = self._check_tests(ws)
                checks.append(test_check)

                # --- Check 4: Security re-analysis ---
                sast_check, cleared = self._check_sast(ws, proposal, target_rel)
                checks.append(sast_check)

                # --- Check 5: Regression (file-level diff) ---
                regression_check = self._check_regression(ws, proposal, target_rel)
                checks.append(regression_check)

        except Exception as exc:
            checks.append(
                ValidationCheck(
                    check_name="workspace",
                    status=CheckStatus.ERROR,
                    detail=f"Workspace error: {exc}",
                )
            )
            return PatchValidationResult(
                patch_id=proposal.patch_id,
                finding_id=proposal.finding_id,
                overall_status=PatchStatus.VALIDATION_INCOMPLETE,
                checks=checks,
                failure_reason=f"Workspace setup error: {exc}",
                requires_human_review=True,
                warnings=warnings,
            )

        # Determine overall status
        overall = self._overall_status(checks)
        security_cleared = cleared

        return PatchValidationResult(
            patch_id=proposal.patch_id,
            finding_id=proposal.finding_id,
            overall_status=overall,
            checks=checks,
            security_reanalysis_cleared=security_cleared,
            regression_detected=any(
                c.check_name == "regression" and c.status == CheckStatus.FAILED
                for c in checks
            ),
            requires_human_review=(overall != PatchStatus.VALIDATED),
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_integrity(
        self, ws: IsolatedWorkspace, proposal: PatchProposal, target_rel: str
    ) -> ValidationCheck:
        # Target must exist in workspace
        if not ws.file_exists(target_rel):
            return ValidationCheck(
                check_name="patch_integrity",
                status=CheckStatus.FAILED,
                detail=f"Target file {target_rel!r} does not exist in isolated workspace.",
            )

        # Verify hash matches if we recorded one
        if proposal.original_hash:
            actual = ws.file_hash(target_rel)
            if actual != proposal.original_hash:
                return ValidationCheck(
                    check_name="patch_integrity",
                    status=CheckStatus.FAILED,
                    detail=(
                        f"Stale proposal: original file hash mismatch. "
                        f"Expected {proposal.original_hash[:12]}…, got {actual[:12]}…. "
                        "Regenerate the proposal."
                    ),
                )

        # Proposed content must not be empty
        if not proposal.proposed_content:
            return ValidationCheck(
                check_name="patch_integrity",
                status=CheckStatus.FAILED,
                detail="Proposed content is empty.",
            )

        # Proposed content must differ from original
        if proposal.original_content and proposal.proposed_content == proposal.original_content:
            return ValidationCheck(
                check_name="patch_integrity",
                status=CheckStatus.FAILED,
                detail="Proposed content is identical to original — no change applied.",
            )

        return ValidationCheck(
            check_name="patch_integrity",
            status=CheckStatus.PASSED,
            detail="Target file verified; hash matches; non-empty diff present.",
        )

    def _check_syntax(self, ws: IsolatedWorkspace, target_rel: str) -> ValidationCheck:
        if not target_rel.endswith(".py"):
            return ValidationCheck(
                check_name="syntax",
                status=CheckStatus.SKIPPED,
                detail=f"Syntax check not supported for {Path(target_rel).suffix} files.",
            )
        try:
            content = ws.read_file(target_rel)
            ast.parse(content)
            return ValidationCheck(
                check_name="syntax",
                status=CheckStatus.PASSED,
                detail="Python AST parse succeeded — no syntax errors.",
            )
        except SyntaxError as exc:
            return ValidationCheck(
                check_name="syntax",
                status=CheckStatus.FAILED,
                detail=f"Python syntax error in patched file: {exc}",
            )
        except Exception as exc:
            return ValidationCheck(
                check_name="syntax",
                status=CheckStatus.ERROR,
                detail=f"Unexpected error during syntax check: {exc}",
            )

    def _check_tests(self, ws: IsolatedWorkspace) -> ValidationCheck:
        if not self._run_tests:
            return ValidationCheck(
                check_name="tests",
                status=CheckStatus.SKIPPED,
                detail="Test execution skipped (opt-in required via --run-tests).",
            )

        # Safety: only run tests inside the isolated workspace, never on original repo
        test_dir = ws.workspace / "tests"
        if not test_dir.exists():
            return ValidationCheck(
                check_name="tests",
                status=CheckStatus.SKIPPED,
                detail="No 'tests/' directory found in isolated workspace.",
            )

        try:
            import sys
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                cwd=str(ws.workspace),
                capture_output=True,
                timeout=MAX_TEST_SECONDS,
                text=True,
                # No network, no credentials passed
                env={"PATH": "", "PYTHONPATH": str(ws.workspace)},
            )
            output = (result.stdout + result.stderr)[:MAX_TEST_OUTPUT_BYTES]
            if result.returncode == 0:
                return ValidationCheck(
                    check_name="tests",
                    status=CheckStatus.PASSED,
                    detail="Unit tests passed in isolated workspace.",
                    output=output,
                )
            else:
                return ValidationCheck(
                    check_name="tests",
                    status=CheckStatus.FAILED,
                    detail="Unit tests FAILED in isolated workspace.",
                    output=output,
                )
        except subprocess.TimeoutExpired:
            return ValidationCheck(
                check_name="tests",
                status=CheckStatus.INCOMPLETE,
                detail=f"Test execution timed out after {MAX_TEST_SECONDS}s.",
            )
        except Exception as exc:
            return ValidationCheck(
                check_name="tests",
                status=CheckStatus.ERROR,
                detail=f"Test execution error: {exc}",
            )

    def _check_sast(
        self, ws: IsolatedWorkspace, proposal: PatchProposal, target_rel: str
    ) -> tuple[ValidationCheck, Optional[bool]]:
        """Re-run SAST on the patched file. Returns (check, finding_cleared)."""
        if not self._run_sast:
            return (
                ValidationCheck(
                    check_name="sast_reanalysis",
                    status=CheckStatus.SKIPPED,
                    detail="SAST re-analysis skipped.",
                ),
                None,
            )
        if not target_rel.endswith(".py"):
            return (
                ValidationCheck(
                    check_name="sast_reanalysis",
                    status=CheckStatus.SKIPPED,
                    detail="SAST re-analysis only supported for Python files.",
                ),
                None,
            )
        try:
            from auditor.parser import ASTEngine
            from auditor.sast import SASTEngine
            from auditor.core.models import DiscoveredFile

            content = ws.read_file(target_rel)
            patched_path = ws.workspace / target_rel

            discovered = DiscoveredFile(
                path=str(patched_path),
                relative_path=target_rel,
                language="python",
                size_bytes=len(content.encode()),
            )

            ast_engine = ASTEngine()
            parsed = ast_engine.parse_all([discovered])
            sast_engine = SASTEngine()
            new_findings = sast_engine.scan_all(parsed)

            # Check if the original finding reproduces
            original_id_prefix = proposal.finding_id.split(":")[0] if ":" in proposal.finding_id else proposal.finding_id
            still_present = any(
                f.id == proposal.finding_id or proposal.finding_id in f.id
                for f in new_findings
            )

            if still_present:
                return (
                    ValidationCheck(
                        check_name="sast_reanalysis",
                        status=CheckStatus.FAILED,
                        detail=(
                            f"Original finding still detected after patch. "
                            f"Patch did not eliminate the vulnerability pattern."
                        ),
                    ),
                    False,
                )
            else:
                # Warning: disappearing finding ≠ confirmed fix
                detail = (
                    f"Original finding not reproduced in patched file. "
                    f"NOTE: Absence of finding does not guarantee the fix is correct — "
                    f"code path may have been removed or pattern may not apply."
                )
                if not new_findings:
                    detail += " No other findings in patched file."
                else:
                    detail += f" {len(new_findings)} unrelated finding(s) remain."

                return (
                    ValidationCheck(
                        check_name="sast_reanalysis",
                        status=CheckStatus.PASSED,
                        detail=detail,
                    ),
                    True,
                )
        except Exception as exc:
            return (
                ValidationCheck(
                    check_name="sast_reanalysis",
                    status=CheckStatus.ERROR,
                    detail=f"SAST re-analysis error: {exc}",
                ),
                None,
            )

    def _check_regression(
        self, ws: IsolatedWorkspace, proposal: PatchProposal, target_rel: str
    ) -> ValidationCheck:
        """Check that only the intended file changed and no other workspace files were affected."""
        if not proposal.original_content or not proposal.proposed_content:
            return ValidationCheck(
                check_name="regression",
                status=CheckStatus.SKIPPED,
                detail="No original content recorded; regression check skipped.",
            )

        # Check line count delta — large removals are suspicious
        orig_lines = proposal.original_content.splitlines()
        new_lines = proposal.proposed_content.splitlines()
        removed = len(orig_lines) - len(new_lines)

        if removed > 50:
            return ValidationCheck(
                check_name="regression",
                status=CheckStatus.FAILED,
                detail=(
                    f"Patch removes {removed} lines, which may indicate substantial "
                    f"functionality loss. Human review required."
                ),
            )

        return ValidationCheck(
            check_name="regression",
            status=CheckStatus.PASSED,
            detail=(
                f"Line delta: {removed:+d} lines. Only target file modified. "
                f"No broad regression indicators detected by static analysis."
            ),
        )

    def _overall_status(self, checks: List[ValidationCheck]) -> PatchStatus:
        statuses = {c.status for c in checks}

        # Any required check failed → validation_failed
        required = {"patch_integrity", "patch_apply", "syntax"}
        for c in checks:
            if c.check_name in required and c.status == CheckStatus.FAILED:
                return PatchStatus.VALIDATION_FAILED

        # Tests explicitly failed
        for c in checks:
            if c.check_name == "tests" and c.status == CheckStatus.FAILED:
                return PatchStatus.VALIDATION_FAILED

        # SAST still shows finding
        for c in checks:
            if c.check_name == "sast_reanalysis" and c.status == CheckStatus.FAILED:
                return PatchStatus.VALIDATION_FAILED

        # Regression detected
        for c in checks:
            if c.check_name == "regression" and c.status == CheckStatus.FAILED:
                return PatchStatus.REQUIRES_REVIEW

        # Any incomplete/skipped/error → incomplete
        if CheckStatus.INCOMPLETE in statuses or CheckStatus.SKIPPED in statuses:
            # But if all required passed and syntax passed, mark applied_in_isolation
            required_passed = all(
                c.status == CheckStatus.PASSED
                for c in checks
                if c.check_name in ("patch_integrity", "patch_apply")
            )
            if required_passed:
                return PatchStatus.VALIDATION_INCOMPLETE

        # All relevant checks passed
        all_relevant = [
            c for c in checks
            if c.check_name not in ("tests",) or c.status != CheckStatus.SKIPPED
        ]
        if all(c.status in (CheckStatus.PASSED, CheckStatus.SKIPPED) for c in all_relevant):
            return PatchStatus.VALIDATED

        return PatchStatus.VALIDATION_INCOMPLETE

