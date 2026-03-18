"""Unified CLI for memdump-toolkit, powered by click."""

from __future__ import annotations

import click
from typing import Any


def _resolve_out_dir(dump_path: str, out_dir: str | None) -> str:
    """Resolve output directory, mirroring the logic in each run() function."""
    import os
    if out_dir:
        return out_dir
    return os.path.join(os.path.dirname(os.path.abspath(dump_path)) or ".", "output")


def _write_html(out_dir: str, binary_results=None, injection_report=None, c2_results=None, executive_data=None, triage_data=None, report_name: str = "report.html") -> None:
    """Generate HTML report from whatever results are available."""
    import os
    try:
        from memdump_toolkit.html_report import generate
        path = generate(out_dir, binary_results or [], c2_results, injection_report, executive_data, triage_data, report_name)
        click.echo(f"HTML report: {path}")
    except Exception as e:
        click.echo(f"Warning: HTML report failed: {e}", err=True)


def _resolve_yara_options(
    yara: bool, yara_rules: str | None, update_yara: bool,
) -> str | None:
    """Resolve the three YARA flags into a single rules directory path.

    Priority: --yara-rules (explicit path) > --yara (community rules dir).
    --update-yara fetches/updates community repos before resolving.
    """
    from memdump_toolkit.fetch_rules import RULES_DIR, fetch_rulesets

    if update_yara:
        click.echo("Updating community YARA rulesets...")
        fetch_rulesets(None)

    if yara_rules or yara:
        try:
            import yara  # noqa: F401
        except ImportError:
            click.echo(
                "Error: yara-python is not installed. Install it with:\n"
                "  pip install 'memdump-toolkit[yara]'",
                err=True,
            )
            return None

    if yara_rules:
        return yara_rules

    if yara:
        if not RULES_DIR.exists() or not any(RULES_DIR.iterdir()):
            click.echo(
                "No community rules found. Run with --update-yara to download, "
                "or use --yara-rules to specify a path.",
                err=True,
            )
            return None
        return str(RULES_DIR)

    return None


def _base_options(f) -> Any:
    """Output and verbosity options — applied to all subcommands."""
    f = click.option("-o", "--output", "out_dir", default=None,
                     help="Output directory")(f)
    f = click.option("-v", "--verbose", is_flag=True,
                     help="Enable debug logging")(f)
    return f


def _yara_options(f) -> Any:
    """YARA scanning options — applied to commands that support YARA."""
    f = click.option("--yara", "yara", is_flag=True,
                     help="Run YARA scan using community rules (~/.memdump-toolkit/rules/)")(f)
    f = click.option("--yara-rules", "yara_rules", default=None, metavar="DIR",
                     help="Run YARA scan using rules from this directory")(f)
    f = click.option("--update-yara", "update_yara", is_flag=True,
                     help="Download/update community YARA rule repos before scanning")(f)
    return f


@click.group()
@click.version_option(package_name="memdump-toolkit")
def cli():
    """Memory dump forensic analysis toolkit — Vision Security Labs."""


@cli.command()
@click.argument("dump", type=click.Path(exists=True))
@_base_options
def extract(dump, out_dir, verbose):
    """Extract listed + hidden PE modules from a minidump."""
    from memdump_toolkit.extract_dlls import run
    run(dump, out_dir, verbose)


@cli.command()
@click.argument("dump", type=click.Path(exists=True))
@_base_options
def detect(dump, out_dir, verbose):
    """Detect DLL injection indicators."""
    import os
    from memdump_toolkit.detect_injection import run
    resolved = _resolve_out_dir(dump, out_dir)
    os.makedirs(resolved, exist_ok=True)
    report = run(dump, resolved, verbose)
    _write_html(resolved, injection_report=report)


@cli.command("go-scan")
@click.argument("dump", type=click.Path(exists=True))
@_base_options
@_yara_options
def go_scan(dump, out_dir, verbose, yara, yara_rules, update_yara):
    """Identify Go-compiled implants in a minidump."""
    import os
    from memdump_toolkit.identify_go_implants import run
    rules_dir = _resolve_yara_options(yara, yara_rules, update_yara)
    resolved = _resolve_out_dir(dump, out_dir)
    os.makedirs(resolved, exist_ok=True)
    results = run(dump, resolved, verbose, rules_dir)
    _write_html(resolved, binary_results=results or [])


@cli.command("go-info")
@click.argument("binary", type=click.Path(exists=True))
@_base_options
def go_info(binary, out_dir, verbose):
    """Extract Go binary metadata (build info, symbols, capabilities)."""
    from memdump_toolkit.go_info import run
    run(binary, out_dir=out_dir, verbose=verbose)


@cli.command()
@click.argument("input_file", metavar="INPUT", type=click.Path(exists=True))
@click.option("--dump", "is_dump", is_flag=True,
              help="Treat input as a minidump instead of a binary")
@_base_options
@_yara_options
def config(input_file, is_dump, out_dir, verbose, yara, yara_rules, update_yara):
    """Extract embedded configuration from a binary or minidump."""
    from memdump_toolkit.extract_config import run
    rules_dir = _resolve_yara_options(yara, yara_rules, update_yara)
    run(input_file, out_dir=out_dir, is_dump_mode=is_dump,
        verbose=verbose, yara_rules_dir=rules_dir)


@cli.command("dotnet-scan")
@click.argument("dump", type=click.Path(exists=True))
@_base_options
@_yara_options
def dotnet_scan(dump, out_dir, verbose, yara, yara_rules, update_yara):
    """Analyze .NET assemblies in a minidump."""
    import os
    from memdump_toolkit.analyze_dotnet import run
    rules_dir = _resolve_yara_options(yara, yara_rules, update_yara)
    resolved = _resolve_out_dir(dump, out_dir)
    os.makedirs(resolved, exist_ok=True)
    results = run(dump, out_dir=resolved, verbose=verbose, yara_rules_dir=rules_dir)
    _write_html(resolved, binary_results=results or [])


def _normalize_inspect_result(result: dict) -> dict:
    """Convert inspect_binary result format to the html_report binary-result format."""
    from memdump_toolkit.analyze_binary import compute_risk_score
    lang = result.get("language", "native")
    analysis = result.get("analysis", {})
    lang_key = {"go": "go_analysis", "dotnet": "dotnet_analysis"}.get(lang, "config")
    normalized: dict = {
        "file": result.get("filepath", result.get("filename", "")),
        "size": result.get("size", 0),
        "source": "inspect",
        "language": lang,
        "hashes": {
            "md5": result.get("md5", ""),
            "sha256": result.get("sha256", ""),
        },
        "yara_matches": result.get("yara_matches", []),
        "risk_score": analysis.get("risk_score", 0),
        "risk_factors": analysis.get("risk_factors", []),
        "offensive_tools": analysis.get("offensive_tools", []),
        lang_key: analysis,
    }
    # Language analyzers (Go, native) don't compute risk scores — derive it now
    if not normalized["risk_score"]:
        score, factors = compute_risk_score(normalized)
        normalized["risk_score"] = score
        normalized["risk_factors"] = factors
    return normalized


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@_base_options
@_yara_options
def inspect(binary, out_dir, verbose, yara, yara_rules, update_yara):
    """Inspect any binary (auto-detects language and dispatches analyzer)."""
    import os
    from memdump_toolkit.inspect_binary import run
    rules_dir = _resolve_yara_options(yara, yara_rules, update_yara)
    resolved = _resolve_out_dir(binary, out_dir)
    os.makedirs(resolved, exist_ok=True)
    result = run(binary, out_dir=resolved, verbose=verbose, yara_rules_dir=rules_dir)
    if result:
        import pathlib
        from memdump_toolkit.html_report import generate_inspect
        stem = pathlib.Path(binary).stem
        normalized = _normalize_inspect_result(result)
        html_path = generate_inspect(resolved, normalized, report_name=f"report_{stem}.html")
        click.echo(f"HTML report: {html_path}")


@cli.command("binary-scan")
@click.argument("dump", type=click.Path(exists=True))
@_base_options
@_yara_options
def binary_scan(dump, out_dir, verbose, yara, yara_rules, update_yara):
    """Universal binary analysis (score all DLLs, language-agnostic)."""
    import os
    from memdump_toolkit.analyze_binary import run
    rules_dir = _resolve_yara_options(yara, yara_rules, update_yara)
    resolved = _resolve_out_dir(dump, out_dir)
    os.makedirs(resolved, exist_ok=True)
    results = run(dump, out_dir=resolved, verbose=verbose, yara_rules_dir=rules_dir)
    _write_html(resolved, binary_results=results)


@cli.command("c2-hunt")
@click.argument("dump", type=click.Path(exists=True))
@_base_options
def c2_hunt(dump, out_dir, verbose):
    """Hunt for C2 indicators in raw process memory."""
    from memdump_toolkit.c2_hunt import run
    run(dump, out_dir, verbose)


@cli.command()
@click.argument("dump", type=click.Path(exists=True))
@_base_options
@_yara_options
def full(dump, out_dir, verbose, yara, yara_rules, update_yara):
    """Run the complete 5-step analysis pipeline."""
    from memdump_toolkit.full_analysis import run
    rules_dir = _resolve_yara_options(yara, yara_rules, update_yara)
    run(dump, out_dir, verbose, rules_dir)


@cli.command()
@click.argument("results_dir", type=click.Path(exists=True))
def report(results_dir):
    """Regenerate interactive HTML report from existing analysis output.

    RESULTS_DIR is a directory containing JSON files from a previous
    'full' pipeline run (binary_analysis.json, injection_report.json, etc.).
    """
    import json
    import os
    from memdump_toolkit.html_report import generate

    def _load(name: str) -> Any:
        path = os.path.join(results_dir, name)
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return None

    binary_results = _load("binary_analysis.json") or []
    injection_report = _load("injection_report.json")
    c2_results = _load("c2_hunt.json")
    executive_data = _load("executive_summary.json")
    triage_data = _load("triage_summary.json")

    if not binary_results and not injection_report and not c2_results:
        raise click.ClickException(
            f"No analysis JSON files found in {results_dir}. "
            "Run 'memdump-toolkit full' first."
        )

    path = generate(results_dir, binary_results, c2_results, injection_report, executive_data, triage_data)
    click.echo(f"HTML report: {path}")


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
