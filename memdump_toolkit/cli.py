"""Unified CLI for memdump-toolkit, powered by click."""

from __future__ import annotations

import click
from typing import Any


def _resolve_yara(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
    """Click callback: resolve --yara-rules 'auto' to default rules dir."""
    from memdump_toolkit.fetch_rules import resolve_yara_dir
    auto_fetch = ctx.params.get("auto_fetch", False)
    return resolve_yara_dir(value, auto_fetch=auto_fetch)


def _common_options(f) -> Any:
    """Shared options for all subcommands."""
    f = click.option("-o", "--output", "out_dir", default=None,
                     help="Output directory")(f)
    f = click.option("-v", "--verbose", is_flag=True,
                     help="Enable debug logging")(f)
    f = click.option("--auto-fetch", "auto_fetch", is_flag=True, is_eager=True,
                     help="Auto-download missing resources without prompting")(f)
    f = click.option("--yara-rules", "yara_dir", default=None,
                     callback=_resolve_yara, is_eager=False,
                     help="YARA rules dir, or 'auto' for ~/.memdump-toolkit/rules/")(f)
    return f


def _known_good_option(f) -> Any:
    """--known-good option (only for commands that run binary analysis)."""
    f = click.option("--known-good", "known_good_path", default=None,
                     help="File of known-good SHA-256 hashes, or 'auto' for bundled set")(f)
    return f


@click.group()
@click.version_option(package_name="memdump-toolkit")
def cli():
    """Memory dump forensic analysis toolkit."""


@cli.command()
@click.argument("dump", type=click.Path(exists=True))
@_common_options
def extract(dump, out_dir, verbose, auto_fetch, yara_dir):
    """Extract listed + hidden PE modules from a minidump."""
    if yara_dir:
        click.echo("Warning: --yara-rules is not used by this command", err=True)
    from memdump_toolkit.extract_dlls import run
    run(dump, out_dir, verbose)


@cli.command()
@click.argument("dump", type=click.Path(exists=True))
@_common_options
def detect(dump, out_dir, verbose, auto_fetch, yara_dir):
    """Detect DLL injection indicators."""
    if yara_dir:
        click.echo("Warning: --yara-rules is not used by this command", err=True)
    from memdump_toolkit.detect_injection import run
    run(dump, out_dir, verbose)


@cli.command("go-scan")
@click.argument("dump", type=click.Path(exists=True))
@_common_options
def go_scan(dump, out_dir, verbose, auto_fetch, yara_dir):
    """Identify Go-compiled implants in a minidump."""
    from memdump_toolkit.identify_go_implants import run
    run(dump, out_dir, verbose, yara_dir)


@cli.command("go-info")
@click.argument("binary", type=click.Path(exists=True))
@_common_options
def go_info(binary, out_dir, verbose, auto_fetch, yara_dir):
    """Extract Go binary metadata (build info, symbols, capabilities)."""
    if yara_dir:
        click.echo("Warning: --yara-rules is not used by this command", err=True)
    from memdump_toolkit.go_info import run
    run(binary, out_dir=out_dir, verbose=verbose)


@cli.command()
@click.argument("input_file", metavar="INPUT", type=click.Path(exists=True))
@click.option("--dump", "is_dump", is_flag=True,
              help="Treat input as a minidump instead of a binary")
@_common_options
def config(input_file, is_dump, out_dir, verbose, auto_fetch, yara_dir):
    """Extract embedded configuration from a binary or minidump."""
    from memdump_toolkit.extract_config import run
    run(input_file, out_dir=out_dir, is_dump_mode=is_dump,
        verbose=verbose, yara_rules_dir=yara_dir)


@cli.command("dotnet-scan")
@click.argument("dump", type=click.Path(exists=True))
@_common_options
def dotnet_scan(dump, out_dir, verbose, auto_fetch, yara_dir):
    """Analyze .NET assemblies in a minidump."""
    from memdump_toolkit.analyze_dotnet import run
    run(dump, out_dir=out_dir, verbose=verbose, yara_rules_dir=yara_dir)


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@_common_options
def inspect(binary, out_dir, verbose, auto_fetch, yara_dir):
    """Inspect any binary (auto-detects language and dispatches analyzer)."""
    from memdump_toolkit.inspect_binary import run
    run(binary, out_dir=out_dir, verbose=verbose, yara_rules_dir=yara_dir)


@cli.command("binary-scan")
@click.argument("dump", type=click.Path(exists=True))
@_common_options
@_known_good_option
def binary_scan(dump, out_dir, verbose, yara_dir, auto_fetch, known_good_path):
    """Universal binary analysis (score all DLLs, language-agnostic)."""
    from memdump_toolkit.known_good import resolve_known_good
    from memdump_toolkit.analyze_binary import run
    known_good = resolve_known_good(known_good_path, auto_fetch=auto_fetch)
    run(dump, out_dir=out_dir, verbose=verbose, yara_rules_dir=yara_dir,
        known_good=known_good)


@cli.command("c2-hunt")
@click.argument("dump", type=click.Path(exists=True))
@_common_options
def c2_hunt(dump, out_dir, verbose, auto_fetch, yara_dir):
    """Hunt for C2 indicators in raw process memory."""
    if yara_dir:
        click.echo("Warning: --yara-rules is not used by this command", err=True)
    from memdump_toolkit.c2_hunt import run
    run(dump, out_dir, verbose)


@cli.command()
@click.argument("dump", type=click.Path(exists=True))
@_common_options
@_known_good_option
def full(dump, out_dir, verbose, yara_dir, auto_fetch, known_good_path):
    """Run the complete 5-step analysis pipeline."""
    from memdump_toolkit.known_good import resolve_known_good
    from memdump_toolkit.full_analysis import run
    known_good = resolve_known_good(known_good_path, auto_fetch=auto_fetch)
    run(dump, out_dir, verbose, yara_dir, known_good=known_good)


@cli.command("fetch-rules")
@click.option("--ruleset", "-r", "rulesets", multiple=True,
              help="Specific ruleset(s) to fetch (default: all)")
@click.option("--list", "list_only", is_flag=True, help="List installed rulesets")
def fetch_rules(rulesets, list_only):
    """Fetch or update YARA rulesets from community repositories."""
    from memdump_toolkit.fetch_rules import RULESETS, fetch_rulesets, list_installed
    if list_only:
        installed = list_installed()
        if not installed:
            click.echo("No rulesets installed. Run 'memdump-toolkit fetch-rules' to download.")
            return
        for r in installed:
            click.echo(f"  {r['name']:<20s} {r['rule_files']:>4d} rules  {r['description']}")
        return
    if not rulesets:
        click.echo(f"Fetching all {len(RULESETS)} rulesets...")
    fetch_rulesets(list(rulesets) if rulesets else None)


def main():
    cli()
