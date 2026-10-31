"""PHANTOM startup banner and branding.

Call ``print_banner()`` once at CLI entry when not in quiet mode.
"""

from __future__ import annotations

from rich.align import Align
from rich.console import Console
from rich.padding import Padding
from rich.rule import Rule
from rich.text import Text

from .console import console, quiet_mode
from .theme import C

# ---------------------------------------------------------------------------
# ASCII ghost-shield logo (80-column safe, plain ASCII)
# ---------------------------------------------------------------------------

_LOGO = r"""
    ____  _   _    _    _   _ _____ ___  __  __
   |  _ \| | | |  / \  | \ | |_   _/ _ \|  \/  |
   | |_) | |_| | / _ \ |  \| | | || | | | |\/| |
   |  __/|  _  |/ ___ \| |\  | | || |_| | |  | |
   |_|   |_| |_/_/   \_\_| \_| |_| \___/|_|  |_|
"""

_GHOST = r"""
         .-.
        (o o)    AI-Powered Security Intelligence
        | O |    Multi-Agent Codebase Auditor
        `~~~'
"""

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def print_banner(version: str, offline: bool = False, quiet: bool = False) -> None:
    """Print the full PHANTOM startup banner.

    Does nothing when *quiet* is True or when PHANTOM_QUIET env-var is set.
    """
    if quiet or quiet_mode():
        return

    con = console

    con.print()
    con.rule(style="phantom.dim")

    # Logo block
    logo_text = Text(_LOGO, style=f"bold {C.PHANTOM}", justify="left")
    con.print(Align(logo_text, align="center"))

    # Ghost + subtitle
    ghost_text = Text(_GHOST, style=f"{C.ACCENT}", justify="left")
    con.print(Align(ghost_text, align="center"))

    con.rule(style="phantom.dim")

    # Status line
    mode_style = "warn" if offline else "ok"
    mode_label = "OFFLINE" if offline else "ONLINE"
    con.print(
        f"  [label]Version[/]  [value]{version}[/]   "
        f"[label]Mode[/]  [{mode_style}]{mode_label}[/]   "
        f"[label]Status[/]  [ok]Ready[/]",
    )

    con.rule(style="phantom.dim")

    # Quick-start hint
    con.print(
        "  [muted]Run a scan:[/]  [code]phantom scan .[/]   "
        "[muted]Get help:[/]  [code]phantom --help[/]",
    )
    con.print()


def print_section(title: str) -> None:
    """Print a short section header rule."""
    console.print(Rule(f"[phantom]{title}[/]", style="phantom.dim"))


def print_quiet_start(cmd: str, version: str) -> None:
    """One-line banner for quiet / CI mode."""
    console.print(f"[phantom]PHANTOM[/] [muted]v{version}[/] [label]{cmd}[/]")

