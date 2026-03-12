"""Identify Go-compiled binaries in a process dump using score-based detection."""

from __future__ import annotations

import json
import os
import re
import struct
from typing import Any

from minidump.minidumpfile import MinidumpFile

from memdump_toolkit.constants import (
    CAPABILITY_STRONG, CAPABILITY_WEAK, KNOWN_TOOLS, MAX_SCAN_SIZE, PAGE_SIZE,
)
from memdump_toolkit.pe_utils import (
    check_pe_header, get_known_bases, get_pe_info, logger, parse_pe_sections,
    read_pe_data, safe_filename, scan_with_yara, setup_logging,
)


def go_detection_score(
    first_page: bytes, sections_info: list[dict],
) -> tuple[int, list[str]]:
    """Score-based Go binary detection.

    Score >= 3: confirmed Go binary.
    Score 1-2: possible, needs deeper scan.
    Score 0: not Go.
    """
    score = 0
    reasons: list[str] = []

    # Strong signals (3 points each)
    if b"Go build ID:" in first_page or b"\xff Go buildinf:" in first_page:
        score += 3
        reasons.append("Go build ID in header")
    if b"go.buildid" in first_page:
        score += 3
        reasons.append("go.buildid marker")

    # Medium signals (2 points each)
    if b".symtab" in first_page:
        score += 2
        reasons.append(".symtab section")
    if b"_cgo_" in first_page:
        score += 2
        reasons.append("CGO export")

    # Weak signals from section table (1 point each)
    if sections_info:
        sec_names = {s["name_raw"] for s in sections_info}
        num_sec = len(sections_info)

        has_bss = b".bss" in sec_names
        has_edata = b".edata" in sec_names
        has_crt = b".CRT" in sec_names
        has_tls = b".tls" in sec_names
        has_noptrdata = b".noptrd" in sec_names or any(b"noptrdata" in s for s in sec_names)

        if has_noptrdata:
            score += 2
            reasons.append(".noptrdata section")

        weak_count = sum([has_bss, has_edata, has_crt, has_tls])
        if weak_count >= 3 and num_sec >= 8:
            score += 1
            reasons.append(f"Go-like section pattern ({weak_count}/4 markers, {num_sec} sections)")
        # Note: .bss+.edata alone is NOT scored — Rust/C++ commonly have these too

    return score, reasons


def is_go_binary_deep(data: bytes) -> tuple[bool, list[str]]:
    """Deep check on full binary data."""
    reasons: list[str] = []

    if b"Go build ID:" in data[:0x2000]:
        reasons.append("Go build ID in header")

    go_markers = [b"runtime.goexit", b"runtime.main", b"go.buildid",
                  b"runtime.gopanic", b"runtime.gorecover"]
    marker_hits = [m for m in go_markers if m in data]
    if marker_hits:
        reasons.append(f"Go markers: {', '.join(m.decode() for m in marker_hits)}")

    # golang.org/x/ is Go-specific; github.com/ alone is not (Rust/etc. use it too)
    if b"golang.org/x/" in data:
        reasons.append("Go stdlib extension import (golang.org/x/)")

    # Require 2+ independent reasons to confirm (single marker could be coincidental)
    return len(reasons) >= 2, reasons


def detect_capabilities(
    data: bytes, extracted_strings: list[bytes],
) -> dict[str, bool]:
    """Two-tier capability detection to reduce false positives."""
    capabilities: dict[str, bool] = {}

    # Tier 1: high-confidence (single match in raw bytes)
    for cap_name, keywords in CAPABILITY_STRONG.items():
        for kw in keywords:
            if kw in data:
                capabilities[cap_name] = True
                break

    # Tier 2: generic (require 2+ matches in extracted strings only)
    joined = b"\n".join(extracted_strings)
    for cap_name, keywords in CAPABILITY_WEAK.items():
        if cap_name in capabilities:
            continue
        matches = sum(1 for kw in keywords if kw in joined)
        if matches >= 2:
            capabilities[cap_name] = True

    return capabilities


def analyze_go_binary(data: bytes, memory_mapped: bool = True) -> dict[str, Any]:
    """Full analysis of a Go binary."""
    result: dict[str, Any] = {}
    scan_data = data[:MAX_SCAN_SIZE]
    text = scan_data.decode("ascii", errors="ignore")

    # Build ID
    bid_idx = data.find(b"Go build ID:")
    if bid_idx >= 0:
        end = data.find(b"\x00", bid_idx)
        if end < 0:
            end = bid_idx + 200
        result["build_id"] = data[bid_idx:end].decode("ascii", errors="replace")

    # PE info
    pe_info = get_pe_info(data, memory_mapped)
    result["export_dll_name"] = pe_info.get("export_name", "")
    result["exports"] = pe_info.get("exports", [])
    result["hashes"] = pe_info.get("hashes", {})
    result["section_entropy"] = pe_info.get("section_entropy", [])

    # Known tool identification
    matched_tools: list[str] = []
    for tool, sigs in KNOWN_TOOLS.items():
        for sig in sigs:
            if sig in data:
                matched_tools.append(tool)
                break
    result["known_tools"] = matched_tools

    # Custom module paths (scan capped region)
    module_paths: set[str] = set()
    for m in re.finditer(rb'([a-z][a-z0-9_\-]+/[a-z][a-z0-9_\-]+(?:/[a-z][a-z0-9_\-]+)+)', scan_data):
        path = m.group().decode("ascii", errors="replace")
        if not any(path.startswith(p) for p in ["github.com", "golang.org", "google.", "nhooyr.", "go."]):
            module_paths.add(path)
    result["custom_module_paths"] = sorted(module_paths)[:20]

    # Third-party Go packages
    go_pkgs: set[str] = set()
    for m in re.finditer(r'(github\.com/[\w\-\.]+(?:/[\w\-\.]+)*)', text):
        parts = m.group().split("/")
        if len(parts) >= 3:
            go_pkgs.add("/".join(parts[:3]))
    for m in re.finditer(r'(golang\.org/x/[\w\-]+)', text):
        go_pkgs.add(m.group())
    for m in re.finditer(r'(nhooyr\.io/[\w\-]+)', text):
        go_pkgs.add(m.group())
    result["go_packages"] = sorted(go_pkgs)

    # Two-tier capability detection (scan capped region)
    extracted_strings = [m.group() for m in re.finditer(rb'[\x20-\x7e]{8,500}', scan_data)]
    result["capabilities"] = detect_capabilities(scan_data, extracted_strings)

    # main.* symbols
    result["main_symbols"] = sorted(set(
        m.group().decode("ascii") for m in re.finditer(rb'main\.[A-Za-z][\w]{2,}', scan_data)
    ))

    # protocol / channel symbols
    result["protocol_symbols"] = sorted(set(
        m.group().decode("ascii") for m in re.finditer(rb'packet\.[A-Z][\w]*', scan_data)
    ))
    result["channel_symbols"] = sorted(set(
        m.group().decode("ascii") for m in re.finditer(rb'channel\.[A-Z][\w]*', scan_data)
    ))

    # Network IOCs
    iocs: dict[str, Any] = {}
    ua_match = re.search(rb'Mozilla/5\.0[^\x00]{10,200}', scan_data)
    if ua_match:
        iocs["user_agent"] = ua_match.group().decode("ascii", errors="replace")

    urls: set[str] = set()
    for m in re.finditer(r'(?:https?|wss?)://[\w\.\-:/?&=@#%]+', text):
        u = m.group()
        if len(u) > 12 and "golang.org" not in u:
            urls.add(u)
    iocs["urls"] = sorted(urls)[:20]

    pipes = set(re.findall(r'\\\\.\\pipe\\[^\s\x00"\']{3,100}', text))
    if pipes:
        iocs["named_pipes"] = sorted(pipes)

    result["network_iocs"] = iocs

    # Suspicious strings sample
    suspicious: set[str] = set()
    for s_bytes in extracted_strings:
        sl = s_bytes.lower()
        if any(kw in sl for kw in [b"exec", b"shell", b"payload", b"inject",
                                     b"callback", b"beacon", b"c2"]):
            suspicious.add(s_bytes[:150].decode("ascii", errors="replace"))
    result["suspicious_strings_sample"] = sorted(suspicious)[:30]

    return result


def _print_go_report(go_binaries: list[dict]) -> None:
    """Print human-readable Go analysis report."""
    if not go_binaries:
        print("\nNo Go binaries found.")
        return

    for i, gb in enumerate(go_binaries):
        print(f"\n{'='*80}")
        print(f"GO BINARY #{i+1}: {gb.get('export_dll_name', 'Unknown')}")
        print(f"{'='*80}")

        print(f"\n  Base Address:   {gb['base_address']}")
        print(f"  Image Size:     {gb['image_size']:,} bytes")
        print(f"  Source:         {gb['source']}")
        print(f"  Detection:      score={gb['detection_score']}")
        if "build_id" in gb:
            print(f"  Build ID:       {gb['build_id'][:80]}")
        if gb.get("export_dll_name"):
            print(f"  Export Name:    {gb['export_dll_name']}")
        if gb.get("exports"):
            print(f"  Exports:        {', '.join(gb['exports'])}")
        if gb.get("hashes"):
            print(f"  MD5:            {gb['hashes'].get('md5', '')}")
            print(f"  SHA256:         {gb['hashes'].get('sha256', '')}")

        packed = [s for s in gb.get("section_entropy", []) if s.get("packed")]
        if packed:
            print(f"\n  Packed Sections (entropy > 7.0):")
            for s in packed:
                print(f"    {s['name']:10s}  entropy={s['entropy']}")

        if gb.get("known_tools"):
            print(f"\n  *** KNOWN TOOL MATCH: {', '.join(gb['known_tools']).upper()} ***")
        else:
            print(f"\n  No match to known tools - likely custom/private")

        if gb.get("custom_module_paths"):
            print(f"\n  Custom Module Paths:")
            for p in gb["custom_module_paths"]:
                print(f"    {p}")

        if gb.get("capabilities"):
            print(f"\n  Capabilities ({len(gb['capabilities'])}):")
            for cap in sorted(gb["capabilities"]):
                print(f"    + {cap}")

        if gb.get("go_packages"):
            print(f"\n  Third-party Go Packages ({len(gb['go_packages'])}):")
            for p in gb["go_packages"]:
                print(f"    {p}")

        if gb.get("channel_symbols"):
            print(f"\n  Communication Channels:")
            for s in gb["channel_symbols"]:
                print(f"    {s}")

        if gb.get("protocol_symbols"):
            print(f"\n  Protocol Symbols ({len(gb['protocol_symbols'])}):")
            for s in gb["protocol_symbols"][:30]:
                print(f"    {s}")

        if gb.get("main_symbols"):
            print(f"\n  Main Package Symbols ({len(gb['main_symbols'])}):")
            for s in gb["main_symbols"]:
                print(f"    {s}")

        iocs = gb.get("network_iocs", {})
        if any(iocs.values()):
            print(f"\n  Network IOCs:")
            if iocs.get("user_agent"):
                print(f"    User-Agent: {iocs['user_agent'][:100]}")
            if iocs.get("urls"):
                print(f"    URLs:")
                for u in iocs["urls"]:
                    print(f"      {u}")
            if iocs.get("named_pipes"):
                print(f"    Named Pipes:")
                for p in iocs["named_pipes"]:
                    print(f"      {p}")

        if gb.get("yara_matches"):
            print(f"\n  YARA Matches:")
            for ym in gb["yara_matches"]:
                print(f"    Rule: {ym['rule']}  Tags: {', '.join(ym.get('tags', []))}")


def _scan_candidates(
    reader: Any, candidates: list[dict], go_dir: str,
    yara_rules_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Score and analyze all PE candidates for Go signatures."""
    go_binaries: list[dict] = []

    for cand in candidates:
        base = cand["base"]
        size = cand["size"]

        try:
            first_page = reader.read(base, min(PAGE_SIZE, size))
        except Exception:
            logger.debug("Failed to read first page for candidate at 0x%x", base)
            continue

        sections_info: list[dict] = []
        if len(first_page) >= 0x200:
            try:
                pe_off = struct.unpack_from("<I", first_page, 0x3C)[0]
                sections_info = parse_pe_sections(first_page, pe_off)
            except Exception:
                logger.debug("PE section parse failed for candidate at 0x%x", base)

        score, reasons = go_detection_score(first_page, sections_info)

        # Deeper scan for weak or zero signals
        if 0 < score < 3:
            try:
                sample = read_pe_data(reader, base, min(0x10000, size))
                for marker in [b"Go build", b"runtime.goexit", b"runtime.main",
                               b".symtab", b"_cgo_dummy_export", b"go.buildid"]:
                    if marker in sample:
                        score += 2
                        reasons.append(f"Deep scan: {marker.decode('ascii', errors='replace')}")
                        break
            except Exception:
                logger.debug("Deep scan read failed for candidate at 0x%x (weak signal path)", base)
        elif score == 0 and size > 1_000_000:
            try:
                sample = read_pe_data(reader, base, min(0x10000, size))
                if (b"Go build" in sample or b"runtime.goexit" in sample or
                        b"runtime.main" in sample or b"_cgo_dummy_export" in sample):
                    score = 3
                    reasons.append("Deep scan found Go markers in large binary")
            except Exception:
                logger.debug("Deep scan read failed for candidate at 0x%x (large binary path)", base)

        if score < 3:
            continue

        logger.info(f"  * Go binary found: {cand['name']} (0x{base:x}, {size:,} bytes)")
        logger.info(f"    Detection score: {score}  ({', '.join(reasons)})")

        logger.info(f"    Reading full image...")
        data = read_pe_data(reader, base, size)

        is_go, deep_reasons = is_go_binary_deep(data)
        if not is_go:
            logger.debug("Deep verification failed for 0x%x despite score %d", base, score)
            continue

        all_reasons = list(set(reasons + deep_reasons))
        logger.info(f"    Go evidence: {', '.join(all_reasons)}")
        logger.info(f"    Analyzing...")

        analysis = analyze_go_binary(data)
        analysis["source"] = cand["source"]
        analysis["original_path"] = cand["name"]
        analysis["base_address"] = f"0x{base:016x}"
        analysis["image_size"] = size
        analysis["detection_score"] = score
        analysis["detection_reasons"] = all_reasons

        # YARA scan
        if yara_rules_dir:
            yara_hits = scan_with_yara(data, yara_rules_dir)
            if yara_hits:
                analysis["yara_matches"] = yara_hits

        # Save binary
        raw_dll_name = analysis.get("export_dll_name", "") or f"go_binary_0x{base:x}.dll"
        dll_name = safe_filename(raw_dll_name)
        bin_path = os.path.join(go_dir, dll_name)
        with open(bin_path, "wb") as f:
            f.write(data)
        analysis["extracted_to"] = bin_path
        logger.info(f"    Saved: {bin_path}")

        go_binaries.append(analysis)

    return go_binaries


def analyze(
    mf: Any, reader: Any, out_dir: str,
    yara_rules_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Core Go identification logic (called by orchestrator with pre-parsed dump)."""
    go_dir = os.path.join(out_dir, "go_binaries")
    os.makedirs(go_dir, exist_ok=True)

    known_bases = get_known_bases(mf)

    # Collect all PE candidates
    candidates: list[dict] = []

    if mf.modules:
        for mod in mf.modules.modules:
            candidates.append({
                "source": "module_list",
                "name": mod.name,
                "base": mod.baseaddress,
                "size": mod.size,
            })

    for seg in reader.memory_segments:
        base = seg.start_virtual_address
        seg_size = seg.end_virtual_address - base
        if seg_size < 0x200 or base in known_bases:
            continue

        hdr_result = check_pe_header(reader, base, seg_size)
        if not hdr_result:
            continue

        _, img_size, _ = hdr_result
        candidates.append({
            "source": "hidden",
            "name": f"hidden_0x{base:x}",
            "base": base,
            "size": img_size,
        })

    logger.info(f"Scanning {len(candidates)} PE images for Go signatures...\n")

    go_binaries = _scan_candidates(reader, candidates, go_dir, yara_rules_dir)

    # Save JSON report
    report_path = os.path.join(out_dir, "go_implants.json")
    with open(report_path, "w") as f:
        json.dump(go_binaries, f, indent=2, default=str)
    logger.info(f"\n\nJSON report: {report_path}")
    logger.info(f"Go binaries: {go_dir}")

    return go_binaries


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
