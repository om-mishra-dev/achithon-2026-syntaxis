"""PHANTOM reusable panel components."""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .console import console
from .theme import C


def info_panel(title: str, rows: list[tuple[str, str]], width: int | None = None) -> None:
    """Render a borderless key-value info grid inside a labelled panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="label", min_width=20)
    grid.add_column(style="value")
    for label, value in rows:
        grid.add_row(f"{label}", value)

    panel = Panel(
        grid,
        title=f"[phantom]{title}[/]",
        title_align="left",
        border_style="phantom.dim",
        padding=(0, 1),
        width=width,
    )
    console.print(panel)


def error_panel(message: str, hint: str | None = None) -> None:
    """Render a formatted error panel."""
    body = f"[err]{message}[/]"
    if hint:
        body += f"\n\n[muted]{hint}[/]"
    console.print(
        Panel(
            body,
            title="[err]Error[/]",
            title_align="left",
            border_style="err",
            padding=(0, 1),
        )
    )


def warning_panel(message: str, hint: str | None = None) -> None:
    """Render a formatted warning panel."""
    body = f"[warn]{message}[/]"
    if hint:
        body += f"\n\n[muted]{hint}[/]"
    console.print(
        Panel(
            body,
            title="[warn]Warning[/]",
            title_align="left",
            border_style="warn",
            padding=(0, 1),
        )
    )


def success_panel(message: str, next_cmd: str | None = None) -> None:
    """Render a success panel with optional next-step suggestion."""
    body = f"[ok]{message}[/]"
    if next_cmd:
        body += f"\n\n[muted]Next:[/]  [code]{next_cmd}[/]"
    console.print(
        Panel(
            body,
            title="[ok]Success[/]",
            title_align="left",
            border_style="ok",
            padding=(0, 1),
        )
    )

