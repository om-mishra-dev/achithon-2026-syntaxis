"""PHANTOM scan progress display.

Uses Rich's Live + Progress to show real-time task status without fabricating
percentages.  Each step is updated as it completes.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Generator

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)

from .console import console
from .theme import C


def _make_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style=f"bold {C.PHANTOM}"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28, style=C.ACCENT_DIM, complete_style=C.PHANTOM),
        TextColumn("[muted]{task.fields[note]}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,   # keep completed steps visible
        expand=False,
    )


class ScanProgress:
    """Context manager that wraps the multi-step scan progress display.

    Usage::

        with ScanProgress() as sp:
            sp.start_step("Ingesting repository")
            do_ingest()
            sp.done_step("Ingesting repository", note="42 files")

            sp.start_step("Running SAST")
            do_sast()
            sp.done_step("Running SAST", note="3 findings")
    """

    # Step labels kept consistent across the codebase
    STEPS = [
        "Repository ingestion",
        "File discovery",
        "Dependency analysis",
        "AST parsing",
        "SAST analysis",
        "Agent analysis",
        "Generating report",
    ]

    def __init__(self, steps: list[str] | None = None) -> None:
        self._steps = steps or self.STEPS
        self._progress: Progress | None = None
        self._task_ids: dict[str, TaskID] = {}
        self._start_times: dict[str, float] = {}

    def __enter__(self) -> "ScanProgress":
        self._progress = _make_progress()
        self._progress.start()
        # Pre-create all tasks as pending
        for step in self._steps:
            tid = self._progress.add_task(
                f"[dim][ ] {step}[/]", total=1, completed=0, note=""
            )
            self._task_ids[step] = tid
        return self

    def __exit__(self, *_) -> None:
        if self._progress:
            self._progress.stop()

    def start_step(self, step: str, note: str = "") -> None:
        """Mark a step as actively running."""
        if not self._progress:
            return
        self._start_times[step] = time.monotonic()
        tid = self._task_ids.get(step)
        if tid is not None:
            self._progress.update(
                tid,
                description=f"[info][>] {step}[/]",
                note=note,
            )

    def done_step(self, step: str, note: str = "") -> None:
        """Mark a step as successfully completed."""
        if not self._progress:
            return
        elapsed = time.monotonic() - self._start_times.get(step, time.monotonic())
        tid = self._task_ids.get(step)
        if tid is not None:
            self._progress.update(
                tid,
                completed=1,
                description=f"[ok][+] {step}[/]",
                note=note,
            )

    def skip_step(self, step: str, note: str = "skipped") -> None:
        """Mark a step as intentionally skipped."""
        if not self._progress:
            return
        tid = self._task_ids.get(step)
        if tid is not None:
            self._progress.update(
                tid,
                completed=1,
                description=f"[muted][-] {step}[/]",
                note=f"[muted]{note}[/]",
            )

    def fail_step(self, step: str, note: str = "failed") -> None:
        """Mark a step as failed."""
        if not self._progress:
            return
        tid = self._task_ids.get(step)
        if tid is not None:
            self._progress.update(
                tid,
                completed=1,
                description=f"[err][!] {step}[/]",
                note=f"[err]{note}[/]",
            )


@contextmanager
def simple_spinner(label: str) -> Generator[None, None, None]:
    """Lightweight spinner for a single indeterminate task."""
    prog = Progress(
        SpinnerColumn(spinner_name="dots", style=f"bold {C.PHANTOM}"),
        TextColumn(f"[info]{label}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    with prog:
        prog.add_task(label, total=None)
        yield

