"""YARA rule management: fetch, update, and resolve rule directories."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import click

RULES_DIR = Path.home() / ".memdump-toolkit" / "rules"

RULESETS: dict[str, dict[str, str]] = {
    "signature-base": {
        "repo": "https://github.com/Neo23x0/signature-base.git",
        "subdir": "yara",
        "description": "Cobalt Strike, Go implants, webshells (Neo23x0)",
    },
    "yara-rules": {
        "repo": "https://github.com/Yara-Rules/rules.git",
        "subdir": ".",
        "description": "Broad malware families, packers, exploits",
    },
    "gcti": {
        "repo": "https://github.com/chronicle/GCTI.git",
        "subdir": "YARA",
        "description": "APT-focused, high quality (Google)",
    },
    "reversinglabs": {
        "repo": "https://github.com/reversinglabs/reversinglabs-yara-rules.git",
        "subdir": "yara",
        "description": "Large malware family signature set",
    },
    "eset": {
        "repo": "https://github.com/eset/malware-ioc.git",
        "subdir": ".",
        "description": "ESET research publications",
    },
    "elastic": {
        "repo": "https://github.com/elastic/protections-artifacts.git",
        "subdir": "yara/rules",
        "description": "Elastic threat research",
    },
}

def resolve_yara_dir(yara_dir: str | None, auto_fetch: bool = False) -> str | None:
    """Resolve --yara-rules value.

    - None → no YARA scanning
    - "auto" → use default rules dir; auto-fetch if missing
    - anything else → use as explicit path
    """
    if yara_dir is None:
        return None
    if yara_dir != "auto":
        return yara_dir
    if RULES_DIR.exists() and any(RULES_DIR.iterdir()):
        return str(RULES_DIR)
    # No rules installed — offer to fetch
    if auto_fetch or click.confirm(
        "No YARA rules found. Download community rulesets now (~500 MB)?",
        default=True,
    ):
        fetch_rulesets(None)
        if RULES_DIR.exists() and any(RULES_DIR.iterdir()):
            return str(RULES_DIR)
        click.echo("Warning: YARA rule download failed, skipping YARA scan.", err=True)
        return None
    # User declined
    return None


def list_installed() -> list[dict[str, Any]]:
    """Return info about installed rulesets."""
    installed = []
    if not RULES_DIR.exists():
        return installed
    for name, meta in RULESETS.items():
        repo_dir = RULES_DIR / name
        if repo_dir.exists():
            rule_count = sum(
                1 for _ in repo_dir.rglob("*.yar")
            ) + sum(
                1 for _ in repo_dir.rglob("*.yara")
            )
            installed.append({
                "name": name,
                "description": meta["description"],
                "path": str(repo_dir),
                "rule_files": rule_count,
            })
    return installed


def fetch_rulesets(names: list[str] | None = None) -> None:
    """Clone or update YARA rulesets into RULES_DIR."""
    targets = names if names else list(RULESETS.keys())

    for name in targets:
        if name not in RULESETS:
            click.echo(f"Unknown ruleset: {name}", err=True)
            click.echo(f"Available: {', '.join(RULESETS.keys())}", err=True)
            continue

        meta = RULESETS[name]
        dest = RULES_DIR / name

        if dest.exists():
            click.echo(f"Updating {name}...")
            result = subprocess.run(
                ["git", "-C", str(dest), "pull", "--ff-only"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                click.echo(f"  Failed to update {name}: {result.stderr.strip()}", err=True)
            else:
                click.echo(f"  {name} up to date.")
        else:
            click.echo(f"Cloning {name} ({meta['description']})...")
            RULES_DIR.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", meta["repo"], str(dest)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                click.echo(f"  Failed to clone {name}: {result.stderr.strip()}", err=True)
            else:
                rule_count = sum(1 for _ in dest.rglob("*.yar")) + sum(
                    1 for _ in dest.rglob("*.yara")
                )
                click.echo(f"  {name} installed ({rule_count} rule files).")

    # Summary
    installed = list_installed()
    if installed:
        total = sum(r["rule_files"] for r in installed)
        click.echo(f"\n{len(installed)} ruleset(s) installed, {total} rule files total.")
        click.echo(f"Rules directory: {RULES_DIR}")
