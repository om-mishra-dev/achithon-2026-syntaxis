"""PHANTOM visual theme — colour palette and Rich style constants.

All colour tokens are defined once here so every UI module draws from the
same palette.  The palette is inspired by deep-terminal charcoal with
purple/violet PHANTOM accents — readable on both dark and light backgrounds
when Rich colour detection degrades gracefully.
"""

from __future__ import annotations

from rich.theme import Theme

# ---------------------------------------------------------------------------
# Colour tokens (Rich colour names or hex strings)
# ---------------------------------------------------------------------------

class _Colours:
    # Brand / accent
    PHANTOM      = "bright_magenta"   # primary brand purple
    ACCENT       = "medium_purple1"   # softer violet accent
    ACCENT_DIM   = "purple"           # dim purple for borders/labels

    # Semantic
    SUCCESS      = "bright_green"
    WARNING      = "yellow"
    ERROR        = "bright_red"
    INFO         = "bright_blue"
    MUTED        = "grey62"
    DIM          = "grey42"

    # Severity
    CRITICAL     = "bright_red"
    HIGH         = "red"
    MEDIUM       = "yellow"
    LOW          = "cyan"
    SAFE         = "bright_green"

    # UI chrome
    BORDER       = "grey30"
    HEADER_BG    = "grey11"
    LABEL        = "grey70"
    VALUE        = "white"

    # Code
    CODE         = "bright_cyan"
    PATH         = "pale_turquoise1"

C = _Colours()

# ---------------------------------------------------------------------------
# Rich Theme
# ---------------------------------------------------------------------------

THEME = Theme(
    {
        # brand
        "phantom"            : C.PHANTOM,
        "phantom.accent"     : C.ACCENT,
        "phantom.dim"        : C.ACCENT_DIM,

        # semantic
        "ok"                 : C.SUCCESS,
        "warn"               : C.WARNING,
        "err"                : C.ERROR,
        "info"               : C.INFO,
        "muted"              : C.MUTED,
        "dim"                : C.DIM,

        # severity
        "sev.critical"       : f"bold {C.CRITICAL}",
        "sev.high"           : f"bold {C.HIGH}",
        "sev.medium"         : C.MEDIUM,
        "sev.low"            : C.LOW,
        "sev.info"           : C.MUTED,

        # labels / values
        "label"              : C.LABEL,
        "value"              : C.VALUE,
        "code"               : C.CODE,
        "path"               : C.PATH,

        # progress
        "progress.description": C.INFO,
        "progress.elapsed"   : C.MUTED,

        # panel border defaults
        "rule.line"          : C.BORDER,
        "repr.url"           : C.CODE,
    },
    inherit=True,
)

# ---------------------------------------------------------------------------
# Severity → style helper
# ---------------------------------------------------------------------------

_SEV_STYLE: dict[str, str] = {
    "CRITICAL" : "sev.critical",
    "HIGH"     : "sev.high",
    "MEDIUM"   : "sev.medium",
    "LOW"      : "sev.low",
    "INFO"     : "sev.info",
}

_SEV_ICON: dict[str, str] = {
    "CRITICAL" : "[bold red]CRITICAL[/]",
    "HIGH"     : "[bold red]HIGH    [/]",
    "MEDIUM"   : "[yellow]MEDIUM  [/]",
    "LOW"      : "[cyan]LOW     [/]",
    "INFO"     : "[grey62]INFO    [/]",
}


def sev_style(severity: str) -> str:
    """Return the Rich style string for *severity*."""
    return _SEV_STYLE.get(severity.upper(), "white")


def sev_markup(severity: str) -> str:
    """Return a pre-coloured severity badge markup string."""
    return _SEV_ICON.get(severity.upper(), severity)

