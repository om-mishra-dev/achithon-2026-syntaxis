"""PHANTOM reusable data tables (dependency graph, file tree, etc.)."""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .console import console
from .theme import C


def print_dependency_table(dep_records: list[Any], advisory_count: int = 0) -> None:
    """Print a summary dependency table."""
    if not dep_records:
        console.print("[muted]  No dependency manifests found.[/]")
        return

    tbl = Table(
        show_header=True,
        header_style=f"bold {C.PHANTOM}",
        border_style="phantom.dim",
        padding=(0, 1),
        expand=False,
        min_width=70,
    )
    tbl.add_column("Package", style="value")
    tbl.add_column("Version", style="code", width=14)
    tbl.add_column("Ecosystem", style="label", width=12)
    tbl.add_column("Type", style="muted", width=10)

    vulns = {getattr(r, "name", ""): True for r in dep_records
             if getattr(r, "advisory_ids", [])}

    for r in dep_records[:20]:
        name = getattr(r, "normalized_name", str(r))
        ver  = getattr(r, "version", "?") or "?"
        eco  = getattr(r, "ecosystem", "")
        kind = "direct" if getattr(r, "is_direct", False) else "transitive"
        has_vuln = vulns.get(name)
        name_str = f"[err]{name} [!][/]" if has_vuln else name
        tbl.add_row(name_str, ver, eco, kind)

    if len(dep_records) > 20:
        tbl.add_row(f"[muted]... {len(dep_records) - 20} more[/]", "", "", "")

    title = f"[phantom]Dependencies[/]  [muted]({len(dep_records)} total"
    if advisory_count:
        title += f", [err]{advisory_count} vulnerable[/]"
    title += ")[/]"

    console.print(
        Panel(tbl, title=title, title_align="left", border_style="phantom.dim", padding=(0, 0))
    )


def print_file_tree(root_label: str, files: list[str], max_items: int = 20) -> None:
    """Print a Rich Tree showing discovered source files."""
    tree = Tree(f"[path]{root_label}[/]", guide_style="phantom.dim")
    shown = files[:max_items]
    for f in shown:
        tree.add(f"[dim]{f}[/]")
    if len(files) > max_items:
        tree.add(f"[muted]... {len(files) - max_items} more files[/]")
    console.print(tree)


def print_agent_table(agent_results: list[dict[str, Any]]) -> None:
    """Print a table of agent execution results."""
    if not agent_results:
        return

    tbl = Table(
        show_header=True,
        header_style=f"bold {C.PHANTOM}",
        border_style="phantom.dim",
        padding=(0, 1),
        expand=False,
    )
    tbl.add_column("Agent", style="value")
    tbl.add_column("Mode", style="label", width=22)
    tbl.add_column("Status", width=10)
    tbl.add_column("Duration", style="muted", width=8, justify="right")
    tbl.add_column("Summary", style="dim")

    for ar in agent_results:
        status = ar.get("status", "?")
        status_str = "[ok]OK[/]" if status == "completed" else f"[warn]{status}[/]"
        tbl.add_row(
            ar.get("role", ar.get("agent_id", "")),
            ar.get("mode", ""),
            status_str,
            f"{ar.get('duration_seconds', 0):.1f}s",
            (ar.get("summary") or "")[:60],
        )

    console.print(
        Panel(
            tbl,
            title="[phantom]AI Agents[/]",
            title_align="left",
            border_style="phantom.dim",
            padding=(0, 0),
        )
    )

