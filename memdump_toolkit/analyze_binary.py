"""Universal binary analyzer — language-agnostic malicious indicator detection.

Runs on EVERY extracted PE module from a dump, regardless of language:
  1. PE metadata analysis (timestamps, sections, imports)
  2. Packer artifact detection (section names, header strings)
  3. Language identification (Go, .NET, Rust, Delphi, Nim, native)
  4. Known offensive tool signatures (cross-language)
  5. Section anomalies (RWX, unusual names, entropy)
  6. Language-specific deep analysis (dispatches to Go/.NET sub-analyzers)
  7. Config/IOC extraction (dispatches to extract_config for suspicious binaries)
  8. YARA scanning

Three-tier filtering:
  Tier 0: SKIP — resource-only DLLs (zero code sections, zero imports, EP=0)
  Tier 1: LIGHTWEIGHT — trusted path modules (timestamp, packer artifacts, language ID)
  Tier 2: FULL — untrusted + hidden (all checks + language dispatch + config + YARA)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from minidump.minidumpfile import MinidumpFile

from memdump_toolkit.constants import (
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_RWX, IMAGE_SCN_MEM_WRITE,
    LANG_SIGNATURES, MAX_SCAN_SIZE, PACKER_SIGNATURES, TRUSTED_PATH_FRAGMENTS,
    TIMESTAMP_EPOCH_ZERO, TIMESTAMP_EPOCH_MAX,
    TIMESTAMP_YEAR_MIN, TIMESTAMP_YEAR_MAX,
    UNPACK_VSIZE_RATIO_THRESHOLD, UNPACK_MIN_SECTION_SIZE, UNPACK_ENTROPY_THRESHOLD,
)
from memdump_toolkit.pe_utils import (
    compute_hashes, extract_imports, get_pe_info, is_trusted_path,
    logger, scan_with_yara, severity_label, setup_logging, write_csv,
)


# ─── Parallel Analysis ──────────────────────────────────────────────────────

# Worker state — initialized once per process via ProcessPoolExecutor initializer
_worker_yara_dir: str | None = None
_worker_known_good: set[str] | None = None


def _init_worker(yara_dir: str | None, known_good: set[str] | None) -> None:
    """Initialize worker process state (called once per worker by ProcessPoolExecutor)."""
    global _worker_yara_dir, _worker_known_good
    _worker_yara_dir = yara_dir
    _worker_known_good = known_good


def _analyze_file_worker(args: tuple[str, str]) -> dict[str, Any] | None:
    """Analyze a single binary file in a worker process.

    Args:
        args: (filepath, source) tuple — must be a single arg for Pool.map().

    Returns:
        Analysis result dict, or None if file is unreadable/too small.
    """
    filepath, source = args
    try:
        fsize = os.path.getsize(filepath)
        if fsize < 0x200:
            return None
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return None

    result = analyze_single_binary(
        filepath, data, source=source,
        yara_rules_dir=_worker_yara_dir,
        known_good=_worker_known_good,
    )

    if not result.get("is_pe", False):
        return None

    return result


# ─── Classification ──────────────────────────────────────────────────────────

def classify_language(data: bytes, pe_info: dict) -> str | None:
    """Identify the source language of a PE binary.

    Uses structural checks for Go/.NET (cheap, reliable),
    string signatures for Rust/Delphi/Nim.
    Returns: "go", "dotnet", "rust", "delphi", "nim", or None (native/unknown).
    """
    # .NET: CLR header (data directory 14)
    try:
        from memdump_toolkit.analyze_dotnet import has_clr_header
        if has_clr_header(data):
            return "dotnet"
    except ImportError:
        pass

    # Go: magic byte scan first (works even on UPX-packed binaries in memory),
    # then score-based heuristics as fallback.
    if b"\xff Go buildinf:" in data:
        return "go"
    try:
        from memdump_toolkit.identify_go_implants import (
            go_detection_score, is_go_binary_deep,
        )
        sections = pe_info.get("sections_detail", [])
        first_page = data[:0x1000]
        score, _ = go_detection_score(first_page, sections)
        if score >= 3:
            return "go"
        if score >= 1:
            is_go, _ = is_go_binary_deep(data)
            if is_go:
                return "go"
    except ImportError:
        pass

    # String-based detection for other languages.
    # Scan up to 10 MB — Rust/Delphi strings often live in .rdata which can be
    # well past the 2 MB mark in large binaries (e.g. 7 MB Rust DLL has .rdata at ~5 MB).
    scan_data = data[:min(len(data), 10 * 1024 * 1024)]
    for lang, sigs in LANG_SIGNATURES.items():
        matches = sum(1 for s in sigs if s in scan_data)
        if matches >= 2:
            return lang

    return None


def check_timestamp(pe_info: dict) -> str | None:
    """Flag anomalous PE compilation timestamps."""
    ts = pe_info.get("timestamp_raw", 0)
    if ts == TIMESTAMP_EPOCH_ZERO:
        return "epoch_zero"
    if ts == TIMESTAMP_EPOCH_MAX:
        return "max_value"
    if 0 < ts < TIMESTAMP_YEAR_MIN:
        return "pre_2000"
    if ts > TIMESTAMP_YEAR_MAX:
        return "future"
    return None


def detect_packer_artifacts(data: bytes, sections: list[dict]) -> list[dict]:
    """Detect packer/crypter artifacts in section names and header bytes."""
    found: list[dict] = []
    header = data[:min(len(data), 0x1000)]
    sec_names = {s["name"] for s in sections}

    for packer, sigs in PACKER_SIGNATURES.items():
        for sig in sigs:
            sig_str = sig.decode("ascii", errors="replace")
            # Check section names
            if sig_str in sec_names:
                found.append({"packer": packer, "match": sig_str, "location": "section_name"})
                break
            # Check header bytes
            if sig in header:
                found.append({"packer": packer, "match": sig_str, "location": "header"})
                break

    return found


def detect_section_anomalies(sections: list[dict], section_entropies: list[dict] | None = None) -> list[dict]:
    """Detect suspicious section characteristics."""
    anomalies: list[dict] = []

    for sec in sections:
        chars = sec.get("characteristics", 0)
        name = sec["name"]

        # RWX: readable + writable + executable (0x20=exec, 0x40=read, 0x80=write)
        is_rwx = (chars & IMAGE_SCN_MEM_RWX) == IMAGE_SCN_MEM_RWX
        if is_rwx:
            anomalies.append({
                "section": name, "type": "rwx",
                "detail": f"Read+Write+Execute (0x{chars:08x})",
            })

        # Executable + Writable (without explicit read, still suspicious)
        if not is_rwx and (chars & IMAGE_SCN_MEM_EXECUTE) and (chars & IMAGE_SCN_MEM_WRITE):
            anomalies.append({
                "section": name, "type": "wx",
                "detail": f"Write+Execute (0x{chars:08x})",
            })

        # Unusual section names (not standard PE names)
        standard_names = {
            ".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata",
            ".edata", ".idata", ".bss", ".tls", ".CRT", ".gfids",
            ".didat", ".debug", ".xdata", ".00cfg",
            # Go sections
            ".noptrdata", ".symtab",
            # .NET
            ".cormeta",
        }
        if name and name not in standard_names:
            anomalies.append({
                "section": name, "type": "unusual_name",
                "detail": f"Non-standard section name",
            })

        # Zero-size section with executable flag
        vsize = sec.get("virtual_size", 0)
        if vsize == 0 and (chars & IMAGE_SCN_MEM_EXECUTE):
            anomalies.append({
                "section": name, "type": "zero_exec",
                "detail": "Zero-size executable section",
            })

        # Section unpacking: large virtual_size vs tiny raw_size + high entropy
        raw_size = sec.get("raw_size", 0)
        if (raw_size > 0
                and vsize > 0
                and vsize >= UNPACK_MIN_SECTION_SIZE
                and vsize / raw_size >= UNPACK_VSIZE_RATIO_THRESHOLD
                and (chars & IMAGE_SCN_MEM_EXECUTE)):
            # Check entropy if available
            ent = 0.0
            if section_entropies:
                for se in section_entropies:
                    if se["name"] == name:
                        ent = se.get("entropy", 0.0)
                        break
            if ent >= UNPACK_ENTROPY_THRESHOLD:
                anomalies.append({
                    "section": name, "type": "unpacked",
                    "detail": f"Likely runtime-unpacked: vsize/rsize={vsize/raw_size:.0f}x, entropy={ent:.1f}",
                })

    return anomalies



# ─── Tier Classification ─────────────────────────────────────────────────────

def _is_resource_only(pe_info: dict) -> bool:
    """Check if PE is a resource-only DLL (no code, no imports, EP=0)."""
    if pe_info.get("entry_point", 0) != 0:
        return False
    sections = pe_info.get("sections_detail", [])
    has_code = any(
        s.get("characteristics", 0) & IMAGE_SCN_MEM_EXECUTE
        for s in sections
    )
    if has_code:
        return False
    # Only .rsrc and .reloc sections
    names = {s["name"] for s in sections}
    return names <= {".rsrc", ".reloc", ".data", ".rdata", ""}


def _get_analysis_tier(filepath: str, source: str) -> int:
    """Determine analysis tier: 0=skip, 1=lightweight, 2=full."""
    basename = Path(filepath).name.lower()

    # Resource-only check happens in caller after pe_info is available
    # Here we just check path trust

    if source == "hidden":
        return 2  # Hidden PEs always get full analysis

    if is_trusted_path(filepath):
        return 1  # Trusted system paths get lightweight

    return 2  # Everything else gets full


# ─── Core Analysis ───────────────────────────────────────────────────────────

def analyze_single_binary(
    filepath: str, data: bytes, source: str = "unknown",
    yara_rules_dir: str | None = None,
    known_good: set[str] | None = None,
) -> dict[str, Any]:
    """Run universal analysis on a single PE binary.

    Args:
        filepath: Original path or identifier (e.g. "hidden_0x1234")
        data: Raw PE bytes
        source: "listed", "hidden", or file path
        yara_rules_dir: Optional YARA rules directory
    """
    result: dict[str, Any] = {
        "file": filepath,
        "size": len(data),
        "source": source,
    }

    # PE metadata
    pe_info = get_pe_info(data, memory_mapped=True)
    if not pe_info.get("is_pe"):
        result["is_pe"] = False
        result["risk_score"] = 0
        result["risk_factors"] = []
        return result

    result["is_pe"] = True
    result["hashes"] = pe_info.get("hashes", compute_hashes(data))
    result["pe_info"] = {
        "is_dll": pe_info.get("is_dll"),
        "is_64bit": pe_info.get("is_64bit"),
        "entry_point": pe_info.get("entry_point"),
        "image_size": pe_info.get("image_size"),
        "num_sections": pe_info.get("num_sections"),
        "timestamp": pe_info.get("timestamp"),
        "timestamp_str": pe_info.get("timestamp_str"),
        "export_name": pe_info.get("export_name"),
        "sections": pe_info.get("sections", []),
        "section_entropy": pe_info.get("section_entropy", []),
    }
    if pe_info.get("version_info"):
        result["version_info"] = pe_info["version_info"]

    # Tier 0: skip resource-only
    if _is_resource_only(pe_info):
        result["tier"] = 0
        result["language"] = None
        result["risk_score"] = 0
        result["risk_factors"] = []
        return result

    tier = _get_analysis_tier(filepath, source)
    result["tier"] = tier

    # ─── All tiers: timestamp + packer + language ID ─────────────────
    sections = pe_info.get("sections_detail", [])

    result["timestamp_anomaly"] = check_timestamp(pe_info)
    result["packer_artifacts"] = detect_packer_artifacts(data, sections)
    result["language"] = classify_language(data, pe_info)

    if tier == 1:
        # Lightweight: stop here for trusted modules
        result["risk_score"], result["risk_factors"] = compute_risk_score(result, known_good)
        return result

    # ─── Tier 2: Full analysis ───────────────────────────────────────

    # Imports
    imports, suspicious_imports = extract_imports(data, pe_info, memory_mapped=True)
    if suspicious_imports:
        result["suspicious_imports"] = suspicious_imports
    result["import_count"] = sum(len(v) for v in imports.values())
    result["imported_dlls"] = sorted(imports.keys())

    # Section anomalies
    section_anomalies = detect_section_anomalies(sections, pe_info.get("section_entropy"))
    if section_anomalies:
        result["section_anomalies"] = section_anomalies

    # High-entropy sections (potential encrypted/compressed content)
    from memdump_toolkit.constants import HIGH_ENTROPY_THRESHOLD
    high_entropy = [
        s for s in pe_info.get("section_entropy", [])
        if s.get("entropy", 0) > HIGH_ENTROPY_THRESHOLD and s.get("size", 0) > 0x1000
    ]
    if high_entropy:
        result["high_entropy_sections"] = high_entropy

    # ─── Language-specific deep analysis ─────────────────────────────
    lang = result.get("language")

    if lang == "go":
        try:
            from memdump_toolkit.identify_go_implants import analyze_go_binary
            go_result = analyze_go_binary(data, memory_mapped=True)
            result["go_analysis"] = go_result
        except Exception as e:
            logger.info("Go analysis failed for '%s': %s", filepath, e)

    elif lang == "dotnet":
        try:
            from memdump_toolkit.analyze_dotnet import analyze_dotnet_binary
            dotnet_result = analyze_dotnet_binary(filepath, data)
            result["dotnet_analysis"] = dotnet_result
        except Exception as e:
            logger.info(".NET analysis failed for '%s': %s", filepath, e)

    # Rust/Delphi/Nim: no deep analyzer yet, but language tag is set

    # ─── Config/IOC extraction for suspicious binaries ───────────────
    # Run config extraction if there are suspicious signals
    has_signals = (
        result.get("offensive_tools")
        or result.get("yara_matches")
        or result.get("suspicious_imports")
        or result.get("packer_artifacts")
        or lang in ("go", "rust", "nim")
        or any(a["type"] == "rwx" for a in result.get("section_anomalies", []))
    )

    if has_signals:
        try:
            from memdump_toolkit.extract_config import extract_config_from_binary
            config = extract_config_from_binary(filepath, data=data, memory_mapped=True,
                                                yara_rules_dir=None)  # YARA runs separately below
            # Only include if we found something meaningful
            net = config.get("network", {})
            crypto = config.get("crypto", {})
            c2 = config.get("c2", {})
            has_content = (
                net.get("ips") or net.get("urls") or net.get("hostnames")
                or net.get("named_pipes") or crypto.get("possible_hex_keys")
                or c2.get("user_agents")
            )
            if has_content:
                result["config"] = config
        except Exception as e:
            logger.info("Config extraction failed for '%s': %s", filepath, e)

    # ─── YARA ────────────────────────────────────────────────────────
    if yara_rules_dir:
        yara_matches = scan_with_yara(data, yara_rules_dir)
        if yara_matches:
            result["yara_matches"] = yara_matches
            # Extract offensive tool attributions from YARA matches
            # (rules tagged "offensive_tool" are treated as tool detections)
            offensive_tools = []
            for m in yara_matches:
                if "offensive_tool" in m.get("tags", []):
                    offensive_tools.append({
                        "tool": m["rule"],
                        "signature": m["strings"][0]["identifier"] if m.get("strings") else m["rule"],
                    })
            if offensive_tools:
                result["offensive_tools"] = offensive_tools

    # ─── Composite risk score ────────────────────────────────────────
    result["risk_score"], result["risk_factors"] = compute_risk_score(result, known_good)

    return result


# ─── Scoring ─────────────────────────────────────────────────────────────────

def compute_risk_score(
    result: dict,
    known_good: set[str] | None = None,
) -> tuple[int, list[str]]:
    """Compute composite risk score (0-100) with human-readable factors."""
    score = 0
    factors: list[str] = []

    # Offensive tools (universal or language-specific)
    universal_tools = result.get("offensive_tools", [])
    go_tools = result.get("go_analysis", {}).get("known_tools", [])
    dn_tools = result.get("dotnet_analysis", {}).get("offensive_tools", [])

    if universal_tools or go_tools or dn_tools:
        score += 40
        names = [t["tool"] for t in universal_tools]
        names += go_tools
        names += [t.get("tool", "") for t in dn_tools]
        factors.append(f"offensive_tools: {', '.join(names)}")

    # Packer artifacts
    if result.get("packer_artifacts"):
        score += 15
        packers = [p["packer"] for p in result["packer_artifacts"]]
        factors.append(f"packer_artifacts: {', '.join(packers)}")

    # YARA matches (additional signal, but don't double-count offensive tools)
    yara_matches = result.get("yara_matches", [])
    non_tool_yara = [m for m in yara_matches if "offensive_tool" not in m.get("tags", [])]
    if non_tool_yara:
        score += min(len(non_tool_yara) * 10, 30)
        rule_names = [m["rule"] for m in non_tool_yara[:5]]
        factors.append(f"yara_matches: {', '.join(rule_names)}")

    # .NET-specific scoring (obfuscators, risky P/Invoke)
    dn = result.get("dotnet_analysis", {})
    if dn.get("obfuscators"):
        score += 20
        factors.append("dotnet_obfuscators")
    if dn.get("suspicious_pinvoke"):
        pinvoke_cats = list(dn["suspicious_pinvoke"].keys())
        if "process_injection" in pinvoke_cats:
            score += 20
            factors.append("dotnet_process_injection_pinvoke")
        if "evasion" in pinvoke_cats:
            score += 10
            factors.append("dotnet_evasion_pinvoke")

    # Go-specific scoring (capabilities)
    go = result.get("go_analysis", {})
    if go.get("capabilities"):
        cap_count = len(go["capabilities"])
        if cap_count >= 5:
            score += 35
            factors.append(f"go_capabilities({cap_count})")
        elif cap_count >= 3:
            score += 25
            factors.append(f"go_capabilities({cap_count})")
        elif cap_count >= 1:
            score += 15
            factors.append(f"go_capabilities({cap_count})")

    # Suspicious imports (native)
    susp = result.get("suspicious_imports", {})
    if "process_injection" in susp:
        score += 20
        factors.append("imports_process_injection")
    if "credential_access" in susp:
        score += 15
        factors.append("imports_credential_access")
    if "memory_manipulation" in susp and len(susp) > 1:
        score += 5
        factors.append("imports_memory_manipulation")

    # Section anomalies
    anomalies = result.get("section_anomalies", [])
    rwx = [a for a in anomalies if a["type"] == "rwx"]
    if rwx:
        score += 15
        factors.append(f"rwx_sections({len(rwx)})")

    unpacked = [a for a in anomalies if a["type"] == "unpacked"]
    if unpacked:
        score += 15
        factors.append(f"section_unpacking({len(unpacked)})")

    # High entropy sections
    if result.get("high_entropy_sections"):
        score += 10
        factors.append("high_entropy_sections")

    # Timestamp anomaly (minor signal)
    ts_anomaly = result.get("timestamp_anomaly")
    if ts_anomaly and ts_anomaly not in ("epoch_zero", "max_value"):
        score += 5
        factors.append(f"timestamp_{ts_anomaly}")

    # Headerless PE (MZ header zeroed — strong evasion indicator)
    if result.get("source") == "hidden" and "headerless" in str(result.get("file", "")):
        score += 25
        factors.append("headerless_pe")

    # Config extraction found IOCs
    config = result.get("config", {})
    net = config.get("network", {})
    if net.get("urls") or net.get("named_pipes"):
        score += 10
        factors.append("embedded_network_iocs")

    # Known-good hash match — strong de-prioritization
    sha = result.get("hashes", {}).get("sha256", "")
    if sha and known_good and sha.lower() in known_good:
        score = max(score - 50, 0)
        factors.append("KNOWN_GOOD_HASH")
        result["known_good"] = True

    return min(score, 100), factors


# ─── Report Output ───────────────────────────────────────────────────────────

def _print_report(results: list[dict]) -> None:
    """Print human-readable universal analysis report."""
    suspicious = [r for r in results if r.get("risk_score", 0) >= 10]
    if not suspicious:
        print("\nNo suspicious binaries detected.")
        return

    # Sort by risk score descending
    suspicious.sort(key=lambda r: r.get("risk_score", 0), reverse=True)

    for i, r in enumerate(suspicious):
        score = r.get("risk_score", 0)
        label = severity_label(score)
        lang = r.get("language") or "native"

        print(f"\n{'='*80}")
        print(f"BINARY #{i+1} [{label}] risk={score}/100  lang={lang}")
        print(f"{'='*80}")

        print(f"\n  File:     {r['file']}")
        print(f"  Size:     {r['size']:,} bytes")
        print(f"  Source:   {r.get('source', '?')}")

        hashes = r.get("hashes", {})
        if hashes:
            print(f"  MD5:      {hashes.get('md5', '')}")
            print(f"  SHA256:   {hashes.get('sha256', '')}")

        pe = r.get("pe_info", {})
        if pe:
            print(f"  Type:     {'DLL' if pe.get('is_dll') else 'EXE'}  "
                  f"{'64-bit' if pe.get('is_64bit') else '32-bit'}")
            if pe.get("export_name"):
                print(f"  Export:   {pe['export_name']}")
            if pe.get("timestamp_str"):
                print(f"  Compiled: {pe['timestamp_str']}")

        if r.get("timestamp_anomaly"):
            print(f"\n  *** TIMESTAMP ANOMALY: {r['timestamp_anomaly']} ***")

        if r.get("packer_artifacts"):
            print(f"\n  Packer Artifacts:")
            for p in r["packer_artifacts"]:
                print(f"    {p['packer']} ({p['match']} in {p['location']})")

        if r.get("offensive_tools"):
            print(f"\n  *** OFFENSIVE TOOLS DETECTED ***")
            for t in r["offensive_tools"]:
                print(f"    {t['tool']}: matched '{t['signature']}'")

        if r.get("suspicious_imports"):
            print(f"\n  Suspicious Imports:")
            for cat, funcs in r["suspicious_imports"].items():
                print(f"    [{cat}] {', '.join(funcs)}")

        if r.get("section_anomalies"):
            print(f"\n  Section Anomalies:")
            for a in r["section_anomalies"]:
                print(f"    [{a['type']}] {a['section']}: {a['detail']}")

        if r.get("high_entropy_sections"):
            print(f"\n  High-Entropy Sections:")
            for s in r["high_entropy_sections"]:
                print(f"    {s['name']}: entropy={s['entropy']:.2f} size={s['size']:,}")

        # Language-specific details
        go = r.get("go_analysis", {})
        if go:
            if go.get("known_tools"):
                print(f"\n  Go Known Tools: {', '.join(go['known_tools'])}")
            if go.get("capabilities"):
                print(f"  Go Capabilities: {', '.join(go['capabilities'].keys())}")
            if go.get("custom_module_paths"):
                print(f"  Go Module Paths:")
                for mp in go["custom_module_paths"][:5]:
                    print(f"    {mp}")

        dn = r.get("dotnet_analysis", {})
        if dn:
            meta = dn.get("metadata", {})
            if meta.get("assembly_name"):
                print(f"\n  .NET Assembly: {meta['assembly_name']} "
                      f"v{meta.get('assembly_version', '?')}")
            if dn.get("obfuscators"):
                print(f"  .NET Obfuscators: "
                      f"{', '.join(o['obfuscator'] for o in dn['obfuscators'])}")
            if dn.get("offensive_tools"):
                print(f"  .NET Offensive Tools: "
                      f"{', '.join(t['tool'] for t in dn['offensive_tools'])}")

        # Config/IOC highlights
        config = r.get("config", {})
        net = config.get("network", {})
        if net.get("urls"):
            print(f"\n  Embedded URLs:")
            for u in net["urls"][:5]:
                print(f"    {u}")
        if net.get("named_pipes"):
            print(f"  Named Pipes: {', '.join(net['named_pipes'][:5])}")

        if r.get("yara_matches"):
            print(f"\n  YARA Matches:")
            for m in r["yara_matches"]:
                print(f"    {m['rule']}  tags={', '.join(m.get('tags', []))}")

        if r.get("risk_factors"):
            print(f"\n  Risk Factors: {', '.join(r['risk_factors'])}")


# ─── Pipeline Entry Points ───────────────────────────────────────────────────

def analyze(
    mf: Any, reader: Any, out_dir: str,
    yara_rules_dir: str | None = None,
    known_good: set[str] | None = None,
) -> list[dict]:
    """Orchestrator entry point — analyze all extracted binaries from a dump.

    Expects extract_dlls.analyze() to have already run, producing
    out_dir/modules/ and out_dir/hidden/ directories.

    Uses ProcessPoolExecutor for parallel analysis when multiple binaries
    are present. Falls back to sequential on failure.
    """
    # ─── Collect all files to analyze ─────────────────────────────────
    file_tasks: list[tuple[str, str]] = []  # (filepath, source)

    dirs_to_scan = [
        (os.path.join(out_dir, "modules"), "listed"),
        (os.path.join(out_dir, "hidden"), "hidden"),
    ]

    for scan_dir, source in dirs_to_scan:
        if not os.path.isdir(scan_dir):
            continue
        for fname in sorted(os.listdir(scan_dir)):
            fpath = os.path.join(scan_dir, fname)
            if os.path.isfile(fpath):
                file_tasks.append((fpath, source))

    if not file_tasks:
        logger.info("No binaries found to analyze.")
        return []

    logger.info(f"Analyzing {len(file_tasks)} binaries...")

    # ─── Run analysis (parallel or sequential) ───────────────────────
    raw_results: list[dict] = []
    used_parallel = False

    max_workers = min(os.cpu_count() or 1, 4)

    if max_workers > 1 and len(file_tasks) >= 4:
        try:
            from concurrent.futures import ProcessPoolExecutor
            logger.info(f"  Using {max_workers} parallel workers")
            with ProcessPoolExecutor(
                max_workers=max_workers,
                initializer=_init_worker,
                initargs=(yara_rules_dir, known_good),
            ) as pool:
                for result in pool.map(_analyze_file_worker, file_tasks):
                    if result is not None:
                        raw_results.append(result)
            used_parallel = True
        except Exception as e:
            logger.info(f"  Parallel analysis failed ({e}), falling back to sequential")
            raw_results = []

    if not used_parallel:
        # Set worker state in main process for sequential mode
        _init_worker(yara_rules_dir, known_good)
        for filepath, source in file_tasks:
            result = _analyze_file_worker((filepath, source))
            if result is not None:
                raw_results.append(result)

    # ─── Post-process: tier filtering + dedup ─────────────────────────
    results: list[dict] = []
    seen_hashes: set[str] = set()
    skipped_tier0 = 0
    skipped_trusted = 0

    for result in raw_results:
        # Tier 0 skip
        if result.get("tier") == 0:
            skipped_tier0 += 1
            continue

        # Deduplicate by SHA-256
        sha = result.get("hashes", {}).get("sha256", "")
        if sha in seen_hashes:
            continue
        if sha:
            seen_hashes.add(sha)

        # Tier 1: only keep if risk >= 10
        if result.get("tier") == 1:
            if result.get("risk_score", 0) < 10:
                skipped_trusted += 1
                continue

        results.append(result)

    total = len(file_tasks)
    logger.info(f"\nAnalyzed {total} binaries:")
    logger.info(f"  {skipped_tier0} resource-only (skipped)")
    logger.info(f"  {skipped_trusted} trusted (lightweight check)")
    logger.info(f"  {len(results)} with findings (risk >= 10)")

    # Print report
    _print_report(results)

    # Save JSON
    report_path = os.path.join(out_dir, "binary_analysis.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"\nJSON report: {report_path}")

    # Save CSV of suspicious binaries
    suspicious = [r for r in results if r.get("risk_score", 0) >= 10]
    if suspicious:
        csv_rows = []
        for r in suspicious:
            csv_rows.append({
                "file": Path(r["file"]).name,
                "source": r.get("source", ""),
                "size": r["size"],
                "language": r.get("language") or "native",
                "risk_score": r.get("risk_score", 0),
                "severity": severity_label(r.get("risk_score", 0)),
                "risk_factors": "; ".join(r.get("risk_factors", [])),
                "md5": r.get("hashes", {}).get("md5", ""),
                "sha256": r.get("hashes", {}).get("sha256", ""),
            })
        csv_path = os.path.join(out_dir, "suspicious_binaries.csv")
        write_csv(csv_path, csv_rows, fieldnames=[
            "file", "source", "size", "language", "risk_score",
            "severity", "risk_factors", "md5", "sha256",
        ])
        logger.info(f"Suspicious binaries CSV: {csv_path}")

    return results


def run(
    dump_path: str, out_dir: str | None = None,
    verbose: bool = False, yara_rules_dir: str | None = None,
    known_good: set[str] | None = None,
) -> list[dict]:
    """Standalone entry point — extracts DLLs first, then analyzes all."""
    setup_logging(verbose)

    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(dump_path) or ".", "output")
    os.makedirs(out_dir, exist_ok=True)

    # Step 1: Extract all PEs (needed as input)
    print(f"Parsing: {dump_path}")
    mf = MinidumpFile.parse(dump_path)
    reader = mf.get_reader()

    from memdump_toolkit.extract_dlls import analyze as extract_analyze
    print("Extracting PE modules...")
    extract_analyze(mf, reader, out_dir)

    # Step 2: Universal analysis
    print("\nRunning universal binary analysis...")
    return analyze(mf, reader, out_dir, yara_rules_dir, known_good)
