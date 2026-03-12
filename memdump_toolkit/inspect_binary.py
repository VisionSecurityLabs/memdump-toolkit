"""Unified binary inspection — auto-detects language and dispatches to the right analyzer.

Usage:
    memdump-toolkit inspect binary.dll

Pipeline:
  1. Read file, compute hashes
  2. Detect language (Go, .NET, Rust, Delphi, Nim, or native)
  3. Dispatch to language-specific analyzer
  4. Always run YARA scan
  5. Print unified report
"""

from __future__ import annotations

import json
import os
from typing import Any

from memdump_toolkit.colors import banner, bold, critical, dim, high, info, severity
from memdump_toolkit.pe_utils import compute_hashes, logger, scan_with_yara, severity_label, setup_logging


# ─── Language Detection ───────────────────────────────────────────────────────

def _detect_language(data: bytes) -> tuple[str, str]:
    """Return (language, detail) for the binary.

    Checks in order:
      1. Go   — structural magic ``\\xff Go buildinf:``
      2. .NET — CLR data directory (has_clr_header)
      3. Rust/Delphi/Nim — LANG_SIGNATURES byte patterns
      4. Native — fallback
    """
    # Go: structural magic in the binary
    if b"\xff Go buildinf:" in data:
        # Try to pull the version for the detail string
        import re
        m = re.search(rb"go1\.\d+(?:\.\d+)?", data[data.find(b"\xff Go buildinf:"):
                                                      data.find(b"\xff Go buildinf:") + 64])
        version = m.group().decode() if m else "unknown"
        return "go", version

    # .NET: CLR header check (no external deps)
    from memdump_toolkit.analyze_dotnet import has_clr_header
    if has_clr_header(data):
        return "dotnet", ".NET"

    # Rust / Delphi / Nim: byte-pattern signatures (require 2+ matches)
    from memdump_toolkit.constants import LANG_SIGNATURES
    for lang, patterns in LANG_SIGNATURES.items():
        matches = sum(1 for pat in patterns if pat in data)
        if matches >= 2:
            return lang, lang.capitalize()

    return "native", "Native"


# ─── .NET Standalone Analysis ─────────────────────────────────────────────────

def _analyze_dotnet_binary(data: bytes, filename: str) -> dict[str, Any]:
    """Lightweight .NET analysis for a standalone binary (no minidump required).

    Reuses the string-scanning helpers and constants already in analyze_dotnet.
    Does NOT call analyze_dotnet.analyze() which requires a MinidumpFile.
    """
    from memdump_toolkit.analyze_dotnet import (
        analyze_dotnet_binary,
    )
    # analyze_dotnet_binary() accepts data directly and does full string scanning,
    # obfuscator detection, offensive tool detection, suspicious API / P/Invoke
    # detection — all without needing a minidump.
    result = analyze_dotnet_binary(filepath=filename, data=data)
    return result


def _print_dotnet_section(result: dict[str, Any]) -> None:
    """Print .NET-specific section of the unified report."""
    meta = result.get("metadata", {})

    asm_name = meta.get("assembly_name")
    if asm_name:
        version = meta.get("assembly_version", "")
        print(f"  {bold('Assembly:')}   {asm_name}" + (f" v{version}" if version else ""))
    if meta.get("type_count"):
        print(f"  {bold('Types:')}      {meta['type_count']}")
    if meta.get("method_count"):
        print(f"  {bold('Methods:')}    {meta['method_count']}")

    il_only = result.get("il_only")
    if il_only is not None:
        print(f"  {bold('IL-Only:')}    {il_only}")
    if result.get("native_entry_point"):
        print(f"  {high('Native entry point (mixed-mode assembly)')}")

    risk = result.get("risk_score", 0)
    label = severity_label(risk)
    print(f"  {bold('Risk Score:')} {risk}/100  {severity(label)}")

    if result.get("offensive_tools"):
        print(f"\n  {critical('*** OFFENSIVE TOOL DETECTED ***')}")
        for t in result["offensive_tools"]:
            print(f"    {critical(t['tool'])}: matched '{t['signature']}'")

    if result.get("obfuscators"):
        print(f"\n  {info('Obfuscators/Packers:')}")
        for o in result["obfuscators"]:
            print(f"    {high(o['obfuscator'])}: matched '{o['signature']}'")

    susp_pinvoke = result.get("suspicious_pinvoke", {})
    if susp_pinvoke:
        print(f"\n  {info('Suspicious P/Invoke:')}")
        for cat, funcs in susp_pinvoke.items():
            print(f"    {high(f'[{cat}]')} {', '.join(funcs)}")

    susp_apis = result.get("suspicious_apis", {})
    if susp_apis:
        print(f"\n  {info('Suspicious .NET APIs:')}")
        for cat, apis in susp_apis.items():
            print(f"    {high(f'[{cat}]')} {', '.join(apis)}")

    pinvokes = meta.get("pinvoke_imports", [])
    if pinvokes:
        count = len(pinvokes)
        print(f"\n  {info('All P/Invoke Imports')} {dim(f'({count}):')}")
        for p in pinvokes[:20]:
            print(f"    {p['module']}!{p['function']}")

    refs = meta.get("assembly_refs", [])
    if refs:
        count = len(refs)
        print(f"\n  {info('Referenced Assemblies')} {dim(f'({count}):')}")
        for ref in refs[:15]:
            print(f"    {ref}")

    resources = meta.get("resources", [])
    if resources:
        count = len(resources)
        print(f"\n  {info('Embedded Resources')} {dim(f'({count}):')}")
        for r in resources[:10]:
            print(f"    {r['name']}")


# ─── Go Analysis ──────────────────────────────────────────────────────────────

def _analyze_go_binary(data: bytes, filename: str) -> dict[str, Any]:
    from memdump_toolkit.go_info import analyze
    return analyze(data, filename=filename)


def _print_go_section(result: dict[str, Any]) -> None:
    """Print Go-specific section (reuses go_info internals)."""
    from memdump_toolkit.go_info import (
        _CAPABILITY_LABELS,
        _print_report,
    )
    # _print_report prints its own header/bar — suppress by printing fields manually
    module_path = result.get("module_path") or "(not found)"
    go_version = result.get("go_version") or "(not found)"
    binary_type = result.get("binary_type", "")

    print(f"  {bold('Module:')}       {module_path}")
    print(f"  {bold('Go Version:')}   {go_version}")
    if binary_type:
        print(f"  {bold('Type:')}         {binary_type}")

    deps = result.get("dependencies", [])
    print(f"\n  {info('Dependencies')} {dim(f'({len(deps)}):')}")
    for dep in deps:
        print(f"    {dep}")

    caps = result.get("capabilities", [])
    if caps:
        print(f"\n  {info('Capabilities:')}")
        labels = [_CAPABILITY_LABELS.get(c, c) for c in caps]
        row_size = 3
        for i in range(0, len(labels), row_size):
            row = labels[i:i + row_size]
            bullet = high("\u25cf")
            print("    " + "".join(f"{bullet} {lbl:<22}" for lbl in row))
    else:
        print(f"\n  {info('Capabilities:')} {dim('(none detected)')}")

    src_files = result.get("source_files", [])
    print(f"\n  {info('Source Files')} {dim(f'({len(src_files)}):')}")
    for sf in src_files:
        print(f"    {sf}")

    by_pkg = result.get("functions_by_package", {})
    if by_pkg:
        print(f"\n  {info('Functions by Package:')}")
        for pkg, fns in sorted(by_pkg.items()):
            suffix = "s" if len(fns) != 1 else ""
            print(f"    {bold(pkg)} {dim(f'({len(fns)} function{suffix})')}")


# ─── Config / String-Based Analysis (Rust, Delphi, Nim, Native) ───────────────

def _analyze_config_binary(filepath: str, data: bytes,
                            yara_rules_dir: str | None) -> dict[str, Any]:
    from memdump_toolkit.extract_config import extract_config_from_binary
    return extract_config_from_binary(filepath, data=data, memory_mapped=False,
                                      yara_rules_dir=yara_rules_dir, quiet=True)


def _print_config_section(result: dict[str, Any]) -> None:
    """Print the network/crypto/c2 section from extract_config output."""
    net = result.get("network", {})
    if net.get("ip_ports"):
        print(f"\n  {info('IP:Port Combinations:')}")
        for ip in net["ip_ports"]:
            print(f"    {high(ip)}")
    urls = net.get("urls", [])
    if urls:
        count = len(urls)
        print(f"\n  {info('URLs')} {dim(f'({count}):')}")
        for u in urls[:15]:
            print(f"    {u}")
    if net.get("hostnames"):
        print(f"\n  {info('Hostnames:')}")
        for h in net["hostnames"]:
            print(f"    {h}")
    if net.get("named_pipes"):
        print(f"\n  {info('Named Pipes:')}")
        for p in net["named_pipes"]:
            print(f"    {high(p)}")
    ips = net.get("ips", [])
    if ips:
        count = len(ips)
        print(f"\n  {info('IP Addresses')} {dim(f'({count}):')}")
        for entry in ips[:15]:
            ctx = f"  ctx: {dim(entry['context'])}" if entry.get("context") else ""
            print(f"    {entry['ip']:20s}{ctx}")

    crypto = result.get("crypto", {})
    pem_certs = crypto.get("pem_certificates", [])
    if pem_certs:
        count = len(pem_certs)
        print(f"\n  {info('PEM Certificates')} {dim(f'({count}):')}")
        for cert in pem_certs[:3]:
            print(f"    {cert[:80]}...")
    hex_keys = crypto.get("possible_hex_keys", [])
    if hex_keys:
        count = len(hex_keys)
        print(f"\n  {info('Possible Hex Keys')} {dim(f'({count}):')}")
        for k in hex_keys[:10]:
            print(f"    {high(k)}")

    c2 = result.get("c2", {})
    if c2.get("user_agents"):
        print(f"\n  {info('User-Agent Strings:')}")
        for ua in c2["user_agents"]:
            print(f"    {ua[:100]}")
    if c2.get("timing_strings"):
        print(f"\n  {info('Timing/Sleep Configuration:')}")
        for s in c2["timing_strings"][:10]:
            print(f"    {s}")
    if c2.get("embedded_json"):
        print(f"\n  {info('Embedded JSON Configs:')}")
        for j in c2["embedded_json"]:
            print(f"    {j[:200]}")

    fb = result.get("flatbuffers", {})
    if fb.get("flatbuffers_types"):
        print(f"\n  {info('FlatBuffers Config Types:')}")
        for t in fb["flatbuffers_types"]:
            print(f"    {t}")


# ─── Unified Report ──────────────────────────────────────────────────────────

def _print_header(filename: str, size: int, hashes: dict[str, str],
                   language: str, detail: str) -> None:
    bar = banner("\u2550" * 70)
    print(f"\n{bar}")
    print(banner(f"BINARY INSPECTION: {filename}"))
    print(f"{bar}")
    print(f"  {bold('Size:')}     {size:,} bytes")
    print(f"  {bold('MD5:')}      {hashes['md5']}")
    print(f"  {bold('SHA256:')}   {hashes['sha256']}")
    lang_label = language.upper() if language in ("go", "dotnet", "native") else language.capitalize()
    if language == "go":
        print(f"  {bold('Language:')} Go ({detail})")
    elif language == "dotnet":
        print(f"  {bold('Language:')} .NET")
    else:
        print(f"  {bold('Language:')} {lang_label}")
    print()


def _print_yara_section(yara_matches: list[dict[str, Any]]) -> None:
    if not yara_matches:
        return
    print(f"\n  {info('YARA Matches')} {dim(f'({len(yara_matches)}):')}")
    for ym in yara_matches:
        tags = ", ".join(ym.get("tags", []))
        tag_str = f"  {dim(f'[{tags}]')}" if tags else ""
        ruleset = ym.get("ruleset", "")
        source_str = f"  {dim(f'({ruleset})')}" if ruleset else ""
        print(f"    Rule: {high(ym['rule'])}{tag_str}{source_str}")


# ─── Entry Point ─────────────────────────────────────────────────────────────

def run(
    filepath: str,
    out_dir: str | None = None,
    verbose: bool = False,
    yara_rules_dir: str | None = None,
) -> dict[str, Any]:
    """Inspect any binary: auto-detect language, dispatch, print unified report.

    Args:
        filepath:      Path to the binary file.
        out_dir:       If provided, write ``inspect_report.json`` here.
        verbose:       Enable debug logging.
        yara_rules_dir: Directory with .yar/.yara rules for YARA scan.

    Returns:
        Structured result dict suitable for JSON serialisation.
    """
    setup_logging(verbose)

    if not os.path.isfile(filepath):
        logger.error("File not found: %s", filepath)
        return {}

    filename = os.path.basename(filepath)
    logger.debug("Reading %s", filepath)

    with open(filepath, "rb") as fh:
        data = fh.read()

    # ── Step 1: hashes ───────────────────────────────────────────────────────
    hashes = compute_hashes(data)
    size = len(data)

    # ── Step 2: language detection ───────────────────────────────────────────
    language, detail = _detect_language(data)
    logger.debug("Detected language: %s (%s)", language, detail)

    # ── Step 3: print header ─────────────────────────────────────────────────
    _print_header(filename, size, hashes, language, detail)

    # ── Step 4: dispatch ─────────────────────────────────────────────────────
    lang_result: dict[str, Any] = {}

    if language == "go":
        lang_result = _analyze_go_binary(data, filename)
        _print_go_section(lang_result)

    elif language == "dotnet":
        lang_result = _analyze_dotnet_binary(data, filename)
        _print_dotnet_section(lang_result)

    else:
        # Rust, Delphi, Nim, Native — string/config extraction
        lang_result = _analyze_config_binary(filepath, data, yara_rules_dir)
        _print_config_section(lang_result)

    # ── Step 5: YARA scan (always, unless Go/dotnet already ran it) ──────────
    # For Go we always run YARA separately (go_info doesn't do YARA).
    # For dotnet and config, yara may have already been run inside the analyzer.
    # Re-run only for Go and native paths so the header section is always shown.
    yara_matches: list[dict[str, Any]] = []
    if language == "go":
        yara_matches = scan_with_yara(data, yara_rules_dir)
    else:
        # Reuse what the sub-analyzer produced (avoid double scan)
        yara_matches = lang_result.get("yara_matches", [])

    _print_yara_section(yara_matches)
    print()  # trailing newline

    # ── Build unified result dict ────────────────────────────────────────────
    result: dict[str, Any] = {
        "filename": filename,
        "filepath": filepath,
        "size": size,
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
        "language": language,
        "language_detail": detail,
        "analysis": lang_result,
        "yara_matches": yara_matches,
    }

    # ── Save JSON report if out_dir provided ─────────────────────────────────
    if out_dir is not None:
        os.makedirs(out_dir, exist_ok=True)
        report_path = os.path.join(out_dir, "inspect_report.json")
        with open(report_path, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        print(f"JSON report: {report_path}")

    return result
