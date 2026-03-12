"""TTY-aware colored output backed by the ``rich`` library.

Public API (unchanged from the manual ANSI version):
    critical(text)  → bold red
    high(text)      → bold yellow
    success(text)   → green
    info(text)      → cyan
    dim(text)       → dim/gray
    bold(text)      → bold white
    banner(text)    → bold cyan
    severity(label) → colored severity label (CRITICAL/HIGH/MEDIUM/LOW)

All functions return a plain ``str`` containing ANSI escapes when stdout is a
TTY (or ``FORCE_COLOR`` is set), and undecorated text otherwise.  The ``Tee``
class in full_analysis.py strips ANSI from file output.

Also exports a shared ``console`` for modules that want to use rich Tables,
Panels, etc. directly.
"""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.theme import Theme

# ─── Color support detection ─────────────────────────────────────────────────

_NO_COLOR = os.environ.get("NO_COLOR")
_FORCE_COLOR = os.environ.get("FORCE_COLOR")

if _NO_COLOR:
    _USE_COLOR = False
elif _FORCE_COLOR:
    _USE_COLOR = True
else:
    try:
        _USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    except Exception:
        _USE_COLOR = False

# Shared rich Console — available for any module to print tables, panels, etc.
_THEME = Theme({
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "success": "green",
    "info": "cyan",
    "banner": "bold cyan",
})
console = Console(theme=_THEME, force_terminal=_USE_COLOR, no_color=not _USE_COLOR)

# ─── ANSI codes (used in f-strings where rich markup isn't practical) ────────

if _USE_COLOR:
    _RED = "\033[1;31m"
    _YELLOW = "\033[1;33m"
    _GREEN = "\033[32m"
    _CYAN = "\033[36m"
    _DIM = "\033[2m"
    _BOLD = "\033[1m"
    _BOLD_CYAN = "\033[1;36m"
    _BG_RED = "\033[1;41;97m"
    _RESET = "\033[0m"
else:
    _RED = _YELLOW = _GREEN = _CYAN = ""
    _DIM = _BOLD = _BOLD_CYAN = _BG_RED = _RESET = ""


# ─── Convenience formatters (same signatures as before) ──────────────────────

def critical(text: str) -> str:
    return f"{_RED}{text}{_RESET}"


def high(text: str) -> str:
    return f"{_YELLOW}{text}{_RESET}"


def success(text: str) -> str:
    return f"{_GREEN}{text}{_RESET}"


def info(text: str) -> str:
    return f"{_CYAN}{text}{_RESET}"


def dim(text: str) -> str:
    return f"{_DIM}{text}{_RESET}"


def bold(text: str) -> str:
    return f"{_BOLD}{text}{_RESET}"


def banner(text: str) -> str:
    return f"{_BOLD_CYAN}{text}{_RESET}"


def severity(label: str) -> str:
    """Colorize a severity label."""
    if label == "CRITICAL":
        return f"{_BG_RED} {label} {_RESET}"
    if label == "HIGH":
        return f"{_RED} {label} {_RESET}"
    if label == "MEDIUM":
        return f"{_YELLOW} {label} {_RESET}"
    return f"{_DIM} {label} {_RESET}"
