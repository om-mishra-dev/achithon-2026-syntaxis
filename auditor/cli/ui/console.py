"""Central Rich Console instances for PHANTOM.

Import ``console`` for normal output and ``err_console`` for errors/warnings.
Both consoles share the PHANTOM theme.  Color detection and no-color mode are
handled automatically by Rich; a CI environment with ``NO_COLOR`` set will get
plain text automatically.

Usage::

    from auditor.cli.ui.console import console, err_console
    console.print("[phantom]PHANTOM[/] is ready")
    err_console.print("[err]Error:[/] something went wrong")
"""

from __future__ import annotations

import os

from rich.console import Console

from .theme import THEME

# Respect NO_COLOR / TERM=dumb / CI non-interactive environments
_force_plain = (
    os.environ.get("NO_COLOR") is not None
    or os.environ.get("TERM") == "dumb"
)

console = Console(
    theme=THEME,
    highlight=False,          # we apply our own markup selectively
    markup=True,
    emoji=False,              # keep output CI-safe
    no_color=_force_plain,
    soft_wrap=False,
    width=None,               # auto-detect; falls back to 80 in CI
)

err_console = Console(
    theme=THEME,
    highlight=False,
    markup=True,
    emoji=False,
    stderr=True,
    no_color=_force_plain,
    soft_wrap=False,
    width=None,
)


def quiet_mode() -> bool:
    """Return True when --quiet is active (consumers set PHANTOM_QUIET=1)."""
    return os.environ.get("PHANTOM_QUIET", "0") == "1"


def set_quiet(value: bool) -> None:
    """Programmatically enable or disable quiet mode."""
    os.environ["PHANTOM_QUIET"] = "1" if value else "0"

