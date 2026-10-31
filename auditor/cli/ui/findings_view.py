"""PHANTOM findings table and detail views."""

from __future__ import annotations

from typing import Any, Sequence

from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .console import console
from .theme import C, sev_markup, sev_style


def _sev_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
        sev.upper(), 5
    )


def print_findings_table(findings: list[Any]) -> None:
    """Render a compact findings summary table.

    *findings* must be objects with attributes:
    ``id``, ``severity``, ``cwe_id``, ``title``, ``locations``.
    """
    if not findings:
        console.print(
            Panel(
                "[ok]No security findings detected.[/]\n"
                "[muted]This does not guarantee the absence of all vulnerabilities.[/]",
                title="[phantom]Security Findings[/]",
                title_align="left",
                border_style="ok",
                padding=(0, 1),
            )
        )
        return

    sorted_findings = sorted(findings, key=lambda f: _sev_order(f.severity.value))

    tbl = Table(
        show_header=True,
        header_style=f"bold {C.PHANTOM}",
        border_style="phantom.dim",
        box=_box(),
        padding=(0, 1),
        expand=False,
        min_width=76,
    )
    tbl.add_column("#", style="muted", width=4, justify="right")
    tbl.add_column("Severity", width=10)
    tbl.add_column("CWE", style="code", width=10)
    tbl.add_column("Vulnerability", style="value")
    tbl.add_column("Location", style="path")

    for idx, f in enumerate(sorted_findings, 1):
        sev = f.severity.value
        loc = ""
        if f.locations:
            loc_obj = f.locations[0]
            loc = f"{loc_obj.file_path}:{loc_obj.line}"
        tbl.add_row(
            str(idx),
            f"[{sev_style(sev)}]{sev}[/]",
            f.cwe_id or "—",
            f.title,
            loc,
        )

    console.print()
    console.print(
        Panel(
            tbl,
            title=f"[phantom]Security Findings[/]  [muted]({len(findings)} total)[/]",
            title_align="left",
            border_style="phantom.dim",
            padding=(0, 0),
        )
    )
    console.print(
        f"  [muted]Use[/] [code]phantom scan --format json -o report.json .[/] [muted]for machine-readable output.[/]"
    )


def print_finding_detail(finding: Any) -> None:
    """Render a detailed single-finding view with evidence and remediation."""
    sev = finding.severity.value
    lines: list[str] = []

    # Header row
    lines.append(f"[label]Finding ID  [/][code]{finding.id}[/]")
    lines.append(f"[label]Severity    [/][{sev_style(sev)}]{sev}[/]")
    if finding.cwe_id:
        lines.append(f"[label]CWE         [/][code]{finding.cwe_id}[/]")
    if finding.cve_id:
        lines.append(f"[label]CVE         [/][code]{finding.cve_id}[/]")
    lines.append(f"[label]Category    [/][value]{finding.finding_type.value}[/]")

    if finding.locations:
        for loc in finding.locations:
            lines.append(f"[label]Location    [/][path]{loc.file_path}:{loc.line}[/]")

    lines.append("")
    lines.append(f"[label]Description[/]")
    lines.append(f"  {finding.description or finding.title}")
    lines.append("")
    lines.append(f"[label]Remediation[/]")
    lines.append(f"  [ok]{finding.remediation_advice}[/]")

    body = "\n".join(lines)
    console.print(
        Panel(
            body,
            title=f"[{sev_style(sev)}]{finding.title}[/]",
            title_align="left",
            border_style=sev_style(sev),
            padding=(0, 1),
        )
    )


def _box():
    """Return Rich box for findings table (plain ASCII fallback-safe)."""
    from rich.box import SIMPLE_HEAVY
    return SIMPLE_HEAVY

