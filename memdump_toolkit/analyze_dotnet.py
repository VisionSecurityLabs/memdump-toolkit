"""Identify and analyze .NET assemblies in a process dump.

Detection strategy:
  1. CLR header check (data directory entry 14) — no dependencies
  2. dnfile metadata parsing when available — assembly info, types, P/Invoke
  3. String-based fallback — obfuscator signatures, offensive tool markers, API patterns

This handles memory-dumped PEs gracefully: metadata is often partially paged out,
so string scanning supplements structured parsing.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import logging as _logging

import pefile

from minidump.minidumpfile import MinidumpFile

# Suppress dnfile warnings for corrupt memory-dumped .NET assemblies
_logging.getLogger("dnfile").setLevel(_logging.ERROR)

from memdump_toolkit.constants import (
    DOTNET_OBFUSCATORS, DOTNET_OFFENSIVE_TOOLS,
    DOTNET_SUSPICIOUS_APIS, DOTNET_SUSPICIOUS_PINVOKE,
    MAX_SCAN_SIZE, PAGE_SIZE, TRUSTED_PATH_FRAGMENTS,
)
from memdump_toolkit.pe_utils import (
    check_pe_header, compute_hashes, get_known_bases, is_trusted_path,
    logger, read_module_memory, read_pe_data, safe_filename,
    scan_with_yara, severity_label, setup_logging, write_csv,
)


# Framework assemblies that naturally contain "suspicious" APIs — suppress scoring
_FRAMEWORK_ASSEMBLIES: set[str] = {
    "mscorlib", "system", "system.core", "system.data", "system.xml",
    "system.web", "system.net", "system.net.http", "system.io",
    "system.security", "system.runtime", "system.reflection",
    "system.configuration", "system.transactions", "system.drawing",
    "system.windows.forms", "windowsbase", "presentationcore",
    "presentationframework", "microsoft.csharp",
}


# ─── CLR Detection (no external deps) ──────────────────────────────────────

def has_clr_header(data: bytes) -> bool:
    """Check if PE has a CLR header (COM_DESCRIPTOR data directory) using pefile."""
    if len(data) < 0x80 or data[:2] != b"MZ":
        return False
    try:
        pe = pefile.PE(data=data, fast_load=True)
        # COM_DESCRIPTOR is data directory index 14
        clr_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        result = clr_entry.VirtualAddress != 0 and clr_entry.Size != 0
        pe.close()
        return result
    except Exception:
        return False


def _get_clr_flags(data: bytes) -> int | None:
    """Read CLR header flags (offset 16 into the CLR header)."""
    if len(data) < 0x80 or data[:2] != b"MZ":
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        clr_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        clr_rva = clr_entry.VirtualAddress
        pe.close()
        if clr_rva == 0:
            return None
        # For memory-mapped PEs, RVA == offset
        if clr_rva + 20 > len(data):
            return None
        import struct
        return struct.unpack_from("<I", data, clr_rva + 16)[0]
    except Exception:
        return None


# ─── dnfile Metadata Extraction ────────────────────────────────────────────

def _extract_metadata_dnfile(data: bytes) -> dict[str, Any] | None:
    """Extract .NET metadata using dnfile. Returns None if not available."""
    try:
        import dnfile
    except ImportError:
        logger.debug("dnfile not installed, skipping metadata extraction")
        return None

    meta: dict[str, Any] = {}
    try:
        pe = dnfile.dnPE(data=data)
    except Exception as e:
        logger.info("dnfile failed to parse: %s", e)
        return None

    if pe.net is None:
        pe.close()
        return None

    try:
        # Assembly identity
        if pe.net.mdtables and hasattr(pe.net.mdtables, "Assembly"):
            asm_table = pe.net.mdtables.Assembly
            if asm_table and asm_table.num_rows > 0:
                row = asm_table.rows[0]
                meta["assembly_name"] = str(getattr(row, "Name", ""))
                meta["assembly_version"] = (
                    f"{getattr(row, 'MajorVersion', 0)}."
                    f"{getattr(row, 'MinorVersion', 0)}."
                    f"{getattr(row, 'BuildNumber', 0)}."
                    f"{getattr(row, 'RevisionNumber', 0)}"
                )
                meta["assembly_culture"] = str(getattr(row, "Culture", ""))

        # Referenced assemblies
        if pe.net.mdtables and hasattr(pe.net.mdtables, "AssemblyRef"):
            ref_table = pe.net.mdtables.AssemblyRef
            if ref_table and ref_table.num_rows > 0:
                meta["assembly_refs"] = [
                    str(getattr(r, "Name", "")) for r in ref_table.rows
                ]

        # TypeDef — class/type names
        if pe.net.mdtables and hasattr(pe.net.mdtables, "TypeDef"):
            td_table = pe.net.mdtables.TypeDef
            if td_table and td_table.num_rows > 0:
                types = []
                for row in td_table.rows:
                    ns = str(getattr(row, "TypeNamespace", ""))
                    name = str(getattr(row, "TypeName", ""))
                    full = f"{ns}.{name}" if ns else name
                    if full and full != "<Module>":
                        types.append(full)
                meta["types"] = types[:200]
                meta["type_count"] = td_table.num_rows

        # MethodDef
        if pe.net.mdtables and hasattr(pe.net.mdtables, "MethodDef"):
            md_table = pe.net.mdtables.MethodDef
            if md_table:
                meta["method_count"] = md_table.num_rows

        # ImplMap (P/Invoke declarations)
        if pe.net.mdtables and hasattr(pe.net.mdtables, "ImplMap"):
            impl_table = pe.net.mdtables.ImplMap
            if impl_table and impl_table.num_rows > 0:
                pinvokes = []
                for row in impl_table.rows:
                    name = str(getattr(row, "ImportName", ""))
                    # Resolve ImportScope (MDTableIndex → ModuleRef.Name)
                    scope_idx = getattr(row, "ImportScope", None)
                    scope = ""
                    if scope_idx is not None:
                        try:
                            scope = str(getattr(scope_idx.row, "Name", ""))
                        except Exception:
                            scope = str(scope_idx)
                    if name:
                        pinvokes.append({"function": name, "module": scope})
                meta["pinvoke_imports"] = pinvokes

        # ModuleRef (native DLL references)
        if pe.net.mdtables and hasattr(pe.net.mdtables, "ModuleRef"):
            modref_table = pe.net.mdtables.ModuleRef
            if modref_table and modref_table.num_rows > 0:
                meta["native_modules"] = [
                    str(getattr(r, "Name", "")) for r in modref_table.rows
                ]

        # ManifestResource (embedded resources)
        if pe.net.mdtables and hasattr(pe.net.mdtables, "ManifestResource"):
            res_table = pe.net.mdtables.ManifestResource
            if res_table and res_table.num_rows > 0:
                meta["resources"] = [
                    {
                        "name": str(getattr(r, "Name", "")),
                        "offset": getattr(r, "Offset", 0),
                    }
                    for r in res_table.rows
                ]

    except Exception as e:
        logger.debug("Metadata extraction partial failure: %s", e)

    pe.close()
    return meta if meta else None


# ─── String-Based Analysis ─────────────────────────────────────────────────

def _detect_obfuscators(data: bytes) -> list[dict[str, str]]:
    """Detect known .NET obfuscators/packers."""
    found: list[dict[str, str]] = []
    for name, sigs in DOTNET_OBFUSCATORS.items():
        for sig in sigs:
            if sig in data:
                found.append({"obfuscator": name, "signature": sig.decode("ascii", errors="replace")})
                break
    return found


def _detect_offensive_tools(data: bytes) -> list[dict[str, str]]:
    """Detect known .NET offensive tools."""
    found: list[dict[str, str]] = []
    for name, sigs in DOTNET_OFFENSIVE_TOOLS.items():
        for sig in sigs:
            if sig in data:
                found.append({"tool": name, "signature": sig.decode("ascii", errors="replace")})
                break
    return found


def _detect_suspicious_apis(data: bytes) -> dict[str, list[str]]:
    """Detect suspicious .NET API usage via string matching."""
    suspicious: dict[str, list[str]] = {}
    text = data.decode("ascii", errors="ignore")
    for category, patterns in DOTNET_SUSPICIOUS_APIS.items():
        hits = [p for p in patterns if p in text]
        if hits:
            suspicious[category] = hits
    return suspicious


def _detect_suspicious_pinvoke_strings(data: bytes) -> dict[str, list[str]]:
    """Detect P/Invoke to suspicious native functions via string matching."""
    suspicious: dict[str, list[str]] = {}
    text = data.decode("ascii", errors="ignore")
    for category, funcs in DOTNET_SUSPICIOUS_PINVOKE.items():
        hits = [f for f in funcs if f in text]
        if hits:
            suspicious[category] = hits
    return suspicious


def _classify_pinvoke_metadata(
    pinvokes: list[dict[str, str]],
) -> dict[str, list[str]]:
    """Classify P/Invoke imports from metadata against suspicious categories."""
    suspicious: dict[str, list[str]] = {}
    func_names = {p["function"] for p in pinvokes}
    for category, target_funcs in DOTNET_SUSPICIOUS_PINVOKE.items():
        found = func_names & target_funcs
        if found:
            suspicious[category] = sorted(found)
    return suspicious


# ─── Core Analysis ─────────────────────────────────────────────────────────

def analyze_dotnet_binary(
    filepath: str, data: bytes | None = None,
    yara_rules_dir: str | None = None,
) -> dict[str, Any]:
    """Full .NET analysis of a single binary."""
    if data is None:
        with open(filepath, "rb") as f:
            data = f.read()

    result: dict[str, Any] = {
        "file": filepath,
        "size": len(data),
        "is_dotnet": has_clr_header(data),
    }

    if not result["is_dotnet"]:
        return result

    hashes = compute_hashes(data)
    result["md5"] = hashes["md5"]
    result["sha256"] = hashes["sha256"]

    # CLR flags
    clr_flags = _get_clr_flags(data)
    if clr_flags is not None:
        result["clr_flags"] = f"0x{clr_flags:x}"
        result["il_only"] = bool(clr_flags & 0x1)
        result["native_entry_point"] = bool(clr_flags & 0x10)

    # Try structured metadata extraction
    meta = _extract_metadata_dnfile(data)
    if meta:
        result["metadata"] = meta
        # Classify P/Invoke from metadata
        if "pinvoke_imports" in meta:
            susp_pinvoke = _classify_pinvoke_metadata(meta["pinvoke_imports"])
            if susp_pinvoke:
                result["suspicious_pinvoke"] = susp_pinvoke

    # String-based analysis (always runs as supplement/fallback)
    scan_data = data[:min(len(data), MAX_SCAN_SIZE)]

    result["obfuscators"] = _detect_obfuscators(scan_data)
    result["offensive_tools"] = _detect_offensive_tools(scan_data)
    result["suspicious_apis"] = _detect_suspicious_apis(scan_data)

    # String-based P/Invoke detection (supplements metadata)
    if "suspicious_pinvoke" not in result:
        str_pinvoke = _detect_suspicious_pinvoke_strings(scan_data)
        if str_pinvoke:
            result["suspicious_pinvoke"] = str_pinvoke

    # YARA scan
    if yara_rules_dir:
        yara_hits = scan_with_yara(data, yara_rules_dir)
        if yara_hits:
            result["yara_matches"] = yara_hits

    # Check if this is a known framework assembly (suppress false positives)
    asm_name = (result.get("metadata", {}).get("assembly_name") or "").lower()
    result["is_framework"] = asm_name in _FRAMEWORK_ASSEMBLIES

    # Risk scoring (framework assemblies get score capped)
    result["risk_score"] = _compute_risk_score(result)

    return result


def _compute_risk_score(result: dict[str, Any]) -> int:
    """Compute a risk score (0-100) for a .NET assembly."""
    if result.get("is_framework"):
        return 0

    score = 0

    if result.get("offensive_tools"):
        score += 40
    if result.get("obfuscators"):
        score += 20

    susp_pinvoke = result.get("suspicious_pinvoke", {})
    if "process_injection" in susp_pinvoke:
        score += 25
    if "evasion" in susp_pinvoke:
        score += 15
    if "credential_access" in susp_pinvoke:
        score += 15
    if "memory_manipulation" in susp_pinvoke:
        score += 10

    susp_apis = result.get("suspicious_apis", {})
    if "reflective_loading" in susp_apis:
        score += 20
    if "dynamic_code" in susp_apis:
        score += 15
    if "process_execution" in susp_apis:
        score += 10
    if "network_comms" in susp_apis:
        score += 5

    if result.get("native_entry_point"):
        score += 10

    return min(score, 100)


# ─── Report Printing ──────────────────────────────────────────────────────

def _print_dotnet_report(assemblies: list[dict]) -> None:
    """Print human-readable .NET analysis report."""
    if not assemblies:
        print("\nNo suspicious .NET assemblies found.")
        return

    for i, asm in enumerate(assemblies):
        risk = asm.get("risk_score", 0)
        if risk < 10:
            continue

        print(f"\n{'='*80}")
        label = severity_label(risk)
        print(f".NET ASSEMBLY #{i+1} [{label}] risk={risk}/100")
        print(f"{'='*80}")

        print(f"\n  File:     {asm['file']}")
        print(f"  Size:     {asm['size']:,} bytes")
        if asm.get("md5"):
            print(f"  MD5:      {asm['md5']}")
            print(f"  SHA256:   {asm['sha256']}")

        if asm.get("il_only") is not None:
            print(f"  IL-Only:  {asm['il_only']}")
        if asm.get("native_entry_point"):
            print(f"  Native entry point (mixed-mode assembly)")

        meta = asm.get("metadata", {})
        if meta.get("assembly_name"):
            print(f"\n  Assembly: {meta['assembly_name']} v{meta.get('assembly_version', '?')}")
        if meta.get("type_count"):
            print(f"  Types:    {meta['type_count']}")
        if meta.get("method_count"):
            print(f"  Methods:  {meta['method_count']}")

        if meta.get("assembly_refs"):
            print(f"\n  Referenced Assemblies ({len(meta['assembly_refs'])}):")
            for ref in meta["assembly_refs"][:15]:
                print(f"    {ref}")

        if asm.get("offensive_tools"):
            print(f"\n  *** OFFENSIVE TOOL DETECTED ***")
            for t in asm["offensive_tools"]:
                print(f"    {t['tool']}: matched '{t['signature']}'")

        if asm.get("obfuscators"):
            print(f"\n  Obfuscators/Packers:")
            for o in asm["obfuscators"]:
                print(f"    {o['obfuscator']}: matched '{o['signature']}'")

        if asm.get("suspicious_pinvoke"):
            print(f"\n  Suspicious P/Invoke:")
            for cat, funcs in asm["suspicious_pinvoke"].items():
                print(f"    [{cat}] {', '.join(funcs)}")

        if asm.get("suspicious_apis"):
            print(f"\n  Suspicious .NET APIs:")
            for cat, apis in asm["suspicious_apis"].items():
                print(f"    [{cat}] {', '.join(apis)}")

        if meta.get("pinvoke_imports"):
            print(f"\n  All P/Invoke Imports ({len(meta['pinvoke_imports'])}):")
            for p in meta["pinvoke_imports"][:20]:
                print(f"    {p['module']}!{p['function']}")

        if meta.get("resources"):
            print(f"\n  Embedded Resources ({len(meta['resources'])}):")
            for r in meta["resources"][:10]:
                print(f"    {r['name']}")

        if asm.get("yara_matches"):
            print(f"\n  YARA Matches:")
            for ym in asm["yara_matches"]:
                print(f"    Rule: {ym['rule']}  Tags: {', '.join(ym.get('tags', []))}")


# ─── Pipeline Entry Points ─────────────────────────────────────────────────

def analyze(
    mf: Any, reader: Any, out_dir: str,
    yara_rules_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Core .NET analysis (called by orchestrator with pre-parsed dump).

    Scans all listed modules and hidden PEs for .NET assemblies,
    skipping trusted system paths.
    """
    dotnet_dir = os.path.join(out_dir, "dotnet")
    os.makedirs(dotnet_dir, exist_ok=True)

    modules = mf.modules.modules if mf.modules else []
    known_bases = get_known_bases(mf)

    results: list[dict] = []
    count = 0

    # Scan listed modules (skip trusted paths to focus on suspicious ones)
    logger.info("Scanning listed modules for .NET assemblies...")
    for mod in modules:
        trusted = is_trusted_path(mod.name)

        try:
            data, _ = read_module_memory(reader, mod.baseaddress, mod.size)
        except Exception as e:
            logger.warning("Failed to read .NET module memory: %s", e)
            continue

        if not has_clr_header(data):
            continue

        count += 1

        # Only do full analysis on untrusted modules
        if trusted:
            continue

        result = analyze_dotnet_binary(
            mod.name, data, yara_rules_dir=yara_rules_dir,
        )
        result["source"] = "module_list"
        result["base_address"] = f"0x{mod.baseaddress:016x}"

        if result.get("risk_score", 0) >= 10:
            # Save the binary
            fname = f"dotnet_{safe_filename(mod.name)}"
            with open(os.path.join(dotnet_dir, fname), "wb") as f:
                f.write(data)
            result["extracted_to"] = os.path.join(dotnet_dir, fname)

        results.append(result)

    # Scan hidden PEs
    logger.info("Scanning hidden PEs for .NET assemblies...")
    for seg in reader.memory_segments:
        base = seg.start_virtual_address
        seg_size = seg.end_virtual_address - base
        if seg_size < 0x200 or base in known_bases:
            continue

        hdr_result = check_pe_header(reader, base, seg_size)
        if not hdr_result:
            continue

        _, img_size, hdr = hdr_result

        if not has_clr_header(hdr):
            # Header too small? Try reading more
            if img_size > 0x400:
                try:
                    more = reader.read(base, min(seg_size, 0x1000))
                    if not has_clr_header(more):
                        continue
                except Exception:
                    continue
            else:
                continue

        count += 1
        data = read_pe_data(reader, base, img_size)

        result = analyze_dotnet_binary(
            f"hidden_0x{base:x}", data, yara_rules_dir=yara_rules_dir,
        )
        result["source"] = "hidden"
        result["base_address"] = f"0x{base:016x}"

        if result.get("risk_score", 0) >= 10:
            fname = f"dotnet_hidden_0x{base:x}.dll"
            with open(os.path.join(dotnet_dir, fname), "wb") as f:
                f.write(data)
            result["extracted_to"] = os.path.join(dotnet_dir, fname)

        results.append(result)

    trusted_count = count - len(results)
    hidden_count = sum(1 for r in results if r.get("source") == "hidden")
    listed_count = len(results) - hidden_count
    logger.info(f"\nFound {count} .NET assemblies total:")
    logger.info(f"  {trusted_count} in trusted system paths (skipped)")
    logger.info(f"  {listed_count} listed modules outside trusted paths")
    logger.info(f"  {hidden_count} hidden (not in module list, found in raw memory)")

    # Filter to only suspicious ones for report
    suspicious = [r for r in results if r.get("risk_score", 0) >= 10]

    # Save report
    report_path = os.path.join(out_dir, "dotnet_analysis.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"\nJSON report: {report_path}")

    if suspicious:
        csv_rows = []
        for r in suspicious:
            csv_rows.append({
                "file": r["file"],
                "base": r.get("base_address", ""),
                "source": r.get("source", ""),
                "size": r["size"],
                "risk_score": r.get("risk_score", 0),
                "assembly_name": r.get("metadata", {}).get("assembly_name", ""),
                "offensive_tools": "|".join(t["tool"] for t in r.get("offensive_tools", [])),
                "obfuscators": "|".join(o["obfuscator"] for o in r.get("obfuscators", [])),
                "suspicious_pinvoke": "|".join(r.get("suspicious_pinvoke", {}).keys()),
                "suspicious_apis": "|".join(r.get("suspicious_apis", {}).keys()),
                "md5": r.get("md5", ""),
                "sha256": r.get("sha256", ""),
            })
        csv_path = os.path.join(out_dir, "dotnet_suspicious.csv")
        write_csv(csv_path, csv_rows, csv_rows[0].keys())
        logger.info(f"Suspicious .NET CSV: {csv_path}")
        logger.info(f"Extracted binaries: {dotnet_dir}")

    return results


def run(
    dump_path: str, out_dir: str | None = None,
    verbose: bool = False, yara_rules_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Standalone entry point - parses dump then calls analyze()."""
    setup_logging(verbose)
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(dump_path) or ".", "output")
    os.makedirs(out_dir, exist_ok=True)

    print(f"Parsing: {dump_path}")
    mf = MinidumpFile.parse(dump_path)
    reader = mf.get_reader()
    return analyze(mf, reader, out_dir, yara_rules_dir)
