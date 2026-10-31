"""PHANTOM CLI package — shared utilities and legacy entry-points.

The original monolithic CLI is preserved as ``auditor.cli_legacy``.
This package exposes the new Rich-based UI components under ``auditor.cli.ui``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

# Re-export legacy entry-points so pyproject.toml scripts still work
from auditor.cli_legacy import main, run_scan, run_evaluate, run_remediate, build_parser  # noqa: F401

if TYPE_CHECKING:
    from auditor.core.models import ScanResult


def _write_scan_markdown_compat(result: "ScanResult", md_path: Path) -> None:
    """Write a simple Markdown scan report (no Rich dependency)."""
    lines = [
        "# PHANTOM Scan Report",
        "",
        f"**Scan ID:** `{result.scan_id}`  ",
        f"**Target:** `{result.target_path_or_url}`  ",
        f"**Timestamp:** {result.timestamp}  ",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Files Analyzed | {result.summary.scanned_files_count} |",
        f"| Duration | {result.summary.duration_seconds:.2f}s |",
        "",
        "### Severity Breakdown",
        "",
    ]
    for sev, cnt in result.summary.findings_count_by_severity.items():
        lines.append(f"- **{sev}**: {cnt}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("_No security findings detected._")
    else:
        for f in result.findings:
            if f.locations:
                loc = f.locations[0]
                heading = f"### [{f.severity.value}] {f.title} - `{loc.file_path}:{loc.line}`"
            else:
                heading = f"### [{f.severity.value}] {f.title}"
            lines.append(heading)
            lines.append("")
            lines.append(f"> **Type:** {f.finding_type.value}  ")
            if f.cwe_id:
                lines.append(f"> **CWE:** {f.cwe_id}  ")
            lines.append(f"> **Remediation:** {f.remediation_advice}")
            lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
