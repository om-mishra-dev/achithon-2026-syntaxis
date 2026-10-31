"""PHANTOM scan summary view — printed at the end of every scan."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.columns import Columns
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .console import console
from .theme import C, sev_style


def print_scan_summary(
    result: Any,
    report_paths: list[str] | None = None,
    next_cmd: str | None = None,
) -> None:
    """Render the final scan summary panel.

    *result* is a ``ScanResult`` model instance.
    """
    s = result.summary
    findings = result.findings or []

    # Build left column: metadata
    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="label", min_width=22)
    meta.add_column(style="value")

    target_label = Path(result.target_path_or_url).name or result.target_path_or_url
    meta.add_row("Repository", f"[path]{target_label}[/]")
    meta.add_row("Files analyzed", str(s.scanned_files_count))
    meta.add_row("Duration", f"{s.duration_seconds:.2f}s")
    meta.add_row("Mode", "[ok]ONLINE[/]" if not result.metadata.get("offline_mode") else "[warn]OFFLINE[/]")

    if s.dependencies_total_count:
        meta.add_row("Dependencies", str(s.dependencies_total_count))
    if s.agents_executed_count:
        meta.add_row(
            "AI Agents",
            f"[ok]{s.agents_executed_count} executed[/]  "
            f"[muted]{s.agents_skipped_count} skipped[/]",
        )

    # Build right column: severity breakdown
    sev_tbl = Table.grid(padding=(0, 2))
    sev_tbl.add_column(style="label")
    sev_tbl.add_column(justify="right")

    sev_counts = s.findings_count_by_severity
    total = sum(sev_counts.values())
    sev_tbl.add_row("Total findings", f"[value]{total}[/]")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cnt = sev_counts.get(sev, 0)
        if cnt:
            sev_tbl.add_row(
                sev.capitalize(),
                f"[{sev_style(sev)}]{cnt}[/]",
            )

    if not total:
        verdict_text = "[ok]No vulnerabilities detected[/]"
    elif sev_counts.get("CRITICAL", 0) or sev_counts.get("HIGH", 0):
        verdict_text = "[err]Action required — critical/high findings present[/]"
    else:
        verdict_text = "[warn]Review recommended[/]"

    # Combine columns
    grid = Table.grid(padding=(0, 4), expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(meta, sev_tbl)

    body_parts: list[Any] = [grid]

    # Report paths
    if report_paths:
        body_parts.append(Rule(style="phantom.dim"))
        rpt = Table.grid(padding=(0, 2))
        rpt.add_column(style="label", min_width=22)
        rpt.add_column(style="path")
        for p in report_paths:
            rpt.add_row("Report", p)
        body_parts.append(rpt)

    # Verdict + next step
    body_parts.append(Rule(style="phantom.dim"))
    body_parts.append(Text.from_markup(verdict_text))
    if next_cmd:
        body_parts.append(
            Text.from_markup(f"[muted]Next:[/]  [code]{next_cmd}[/]")
        )

    from rich.console import Group
    console.print()
    console.print(
        Panel(
            Group(*body_parts),
            title="[phantom]Scan Complete[/]",
            title_align="left",
            border_style="phantom.dim",
            padding=(0, 1),
        )
    )


def print_remediation_summary(report: Any, report_paths: list[str] | None = None) -> None:
    """Render remediaton pipeline result summary."""
    proposals = report.proposals or []
    eligible   = [p for p in proposals if p.status.value != "unsupported"]
    validated  = [p for p in proposals if p.status.value in ("validated", "applied_in_isolation")]
    unsupported= [p for p in proposals if p.status.value == "unsupported"]

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="label", min_width=22)
    grid.add_column(style="value")
    grid.add_row("Total proposals", str(len(proposals)))
    grid.add_row("Eligible",        f"[ok]{len(eligible)}[/]")
    grid.add_row("Validated",       f"[ok]{len(validated)}[/]")
    grid.add_row("Unsupported",     f"[muted]{len(unsupported)}[/]")

    body: list[Any] = [grid]
    if report_paths:
        from rich.rule import Rule
        body.append(Rule(style="phantom.dim"))
        rpt = Table.grid(padding=(0, 2))
        rpt.add_column(style="label", min_width=22)
        rpt.add_column(style="path")
        for p in report_paths:
            rpt.add_row("Report", p)
        body.append(rpt)

    from rich.console import Group
    console.print()
    console.print(
        Panel(
            Group(*body),
            title="[phantom]Remediation Complete[/]",
            title_align="left",
            border_style="phantom.dim",
            padding=(0, 1),
        )
    )


def print_evaluation_summary(run: Any, report_paths: list[str] | None = None) -> None:
    """Render evaluation benchmark result summary."""
    m = run.metrics

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="label", min_width=22)
    grid.add_column(style="value")
    grid.add_row("Cases run",  str(run.total_cases))
    grid.add_row("TP / TN",   f"[ok]{m.true_positives}[/] / [ok]{m.true_negatives}[/]")
    grid.add_row("FP / FN",   f"[warn]{m.false_positives}[/] / [warn]{m.false_negatives}[/]")
    grid.add_row("Precision",  f"[value]{m.precision:.4f}[/]")
    grid.add_row("Recall",     f"[value]{m.recall:.4f}[/]")
    grid.add_row("F1 Score",   f"[phantom]{m.f1_score:.4f}[/]")
    grid.add_row("Accuracy",   f"[value]{m.accuracy:.4f}[/]")
    grid.add_row("Duration",   f"{run.total_duration_seconds:.2f}s")

    body: list[Any] = [grid]
    if report_paths:
        from rich.rule import Rule
        body.append(Rule(style="phantom.dim"))
        rpt = Table.grid(padding=(0, 2))
        rpt.add_column(style="label", min_width=22)
        rpt.add_column(style="path")
        for p in report_paths:
            rpt.add_row("Report", p)
        body.append(rpt)

    from rich.console import Group
    console.print()
    console.print(
        Panel(
            Group(*body),
            title="[phantom]Evaluation Complete[/]",
            title_align="left",
            border_style="phantom.dim",
            padding=(0, 1),
        )
    )

