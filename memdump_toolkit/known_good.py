"""Known-good hash management: bundled + downloadable hash sets.

Provides a curated set of SHA-256 hashes for common Windows system DLLs,
used to de-prioritize known-legitimate binaries in analysis results.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import click

KNOWN_GOOD_DIR = Path.home() / ".memdump-toolkit" / "known-good"
BUNDLED_HASHES_FILE = Path(__file__).parent / "data" / "known_good_hashes.txt"


def load_hash_file(path: str | Path) -> set[str]:
    """Load SHA-256 hashes from a file (one hex digest per line).

    Supports CSV format (SHA-256 in first column, comma-separated)
    and plain text (one hash per line). Lines starting with # are skipped.
    """
    hashes: set[str] = set()
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith('"SHA') or line.startswith('"sha'):
                continue
            token = line.split(",")[0].strip('" ').lower()
            if len(token) == 64:
                try:
                    int(token, 16)
                    hashes.add(token)
                except ValueError:
                    continue
    return hashes


def load_bundled_hashes() -> set[str]:
    """Load the bundled known-good hash set shipped with the package."""
    if BUNDLED_HASHES_FILE.exists():
        return load_hash_file(BUNDLED_HASHES_FILE)
    return set()


def load_user_hashes() -> set[str]:
    """Load user-downloaded known-good hashes from ~/.memdump-toolkit/known-good/."""
    hashes: set[str] = set()
    if not KNOWN_GOOD_DIR.exists():
        return hashes
    for f in KNOWN_GOOD_DIR.iterdir():
        if f.suffix in (".txt", ".csv"):
            hashes |= load_hash_file(f)
    return hashes


def resolve_known_good(value: str | None, auto_fetch: bool = False) -> set[str] | None:
    """Resolve --known-good value.

    - None -> no known-good filtering
    - "auto" -> load bundled + user hashes
    - file path -> load from that file
    """
    if value is None:
        return None
    if value != "auto":
        path = Path(value)
        if not path.is_file():
            raise click.ClickException(f"Hash file not found: {value}")
        return load_hash_file(value)
    # "auto" mode: load bundled set + any user-added hash files
    hashes = load_bundled_hashes() | load_user_hashes()
    if hashes:
        click.echo(f"Loaded {len(hashes)} known-good hashes (bundled + user)")
        return hashes
    click.echo("Warning: no known-good hashes available. Use 'memdump-toolkit fetch-rules' or provide a hash file.", err=True)
    return None
