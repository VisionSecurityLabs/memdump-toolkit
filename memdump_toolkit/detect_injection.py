"""Detect DLL injection indicators in a Windows Minidump."""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from minidump.minidumpfile import MinidumpFile

from rapidfuzz.distance import Levenshtein

from memdump_toolkit.constants import (
    HOMOGLYPH_MAP, LARGE_PE_THRESHOLD, MAX_SEGMENT_SCAN_SIZE, NOP_PATTERNS, PAGE_SIZE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    SHELLCODE_CODE_DENSITY_THRESHOLD, SHELLCODE_MIN_REGION_SIZE,
    SHELLCODE_PATTERNS, SHELLCODE_PROLOGUES,
    SYSTEM_DLLS, TRUSTED_PATH_FRAGMENTS,
)
from memdump_toolkit.pe_utils import (
    check_pe_header, detect_pe_bitness, extract_imports, get_known_bases,
    get_pe_identity, get_pe_info, is_heap_address, is_trusted_path,
    logger, read_module_memory, setup_logging, shannon_entropy,
)


# ─── Helper Functions ────────────────────────────────────────────────────────

def levenshtein(s1: str, s2: str) -> int:
    """Edit distance via rapidfuzz (C-optimized)."""
    return Levenshtein.distance(s1, s2)


def is_homoglyph(s1: str, s2: str) -> bool:
    """True if s1 looks like a homoglyph of s2 (visually similar, textually different)."""
    if s1 == s2:
        return False
    return s1.translate(HOMOGLYPH_MAP) == s2.translate(HOMOGLYPH_MAP)


def _build_module_ranges(modules: list) -> list[tuple[int, int, str]]:
    return [(m.baseaddress, m.baseaddress + m.size, m.name) for m in modules]


def compare_modules(reader: Any, base1: int, base2: int, size: int) -> dict:
    """Compare in-memory PE headers against on-disk originals for tampering detection."""
    same = diff = empty1 = empty2 = 0
    total = size // PAGE_SIZE + (1 if size % PAGE_SIZE else 0)
    for off in range(0, size, PAGE_SIZE):
        chunk = min(PAGE_SIZE, size - off)
        try:
            d1 = reader.read(base1 + off, chunk)
        except Exception:
            d1 = b"\x00" * chunk
        try:
            d2 = reader.read(base2 + off, chunk)
        except Exception:
            d2 = b"\x00" * chunk
        if d1 == d2:
            same += 1
        else:
            diff += 1
        if d1 == b"\x00" * len(d1):
            empty1 += 1
        if d2 == b"\x00" * len(d2):
            empty2 += 1
    return {
        "total_pages": total, "identical_pages": same, "different_pages": diff,
        "empty_pages_module1": empty1, "empty_pages_module2": empty2,
        "similarity_pct": round(same / total * 100, 1) if total else 0,
    }


# ─── New Checks ──────────────────────────────────────────────────────────────

def check_threads(mf: Any, modules: list) -> list[dict]:
    """CHECK 6: Threads executing outside any known module."""
    findings: list[dict] = []
    if not hasattr(mf, "threads") or not mf.threads:
        return findings
    ranges = _build_module_ranges(modules)
    try:
        threads = mf.threads.threads
    except AttributeError:
        return findings
    for thread in threads:
        try:
            ctx = thread.ThreadContext
            if ctx is None:
                continue
            ip = getattr(ctx, "Rip", None) or getattr(ctx, "Eip", None)
            if ip is None or ip <= 0x10000:
                continue
            if not any(s <= ip < e for s, e, _ in ranges):
                findings.append({
                    "type": "THREAD_OUTSIDE_MODULE", "severity": "HIGH",
                    "thread_id": thread.ThreadId,
                    "instruction_pointer": f"0x{ip:016x}",
                })
        except Exception:
            logger.debug("Failed to read thread context for TID %s",
                         getattr(thread, "ThreadId", "?"))
    return findings


def analyze_shellcode(data: bytes) -> dict[str, Any]:
    """Scan a memory region for shellcode indicators.

    Returns a dict with matched patterns, heuristic scores, and a verdict.
    """
    matches: list[dict] = []
    flags: list[str] = []

    if len(data) < SHELLCODE_MIN_REGION_SIZE:
        return {"matches": [], "flags": [], "verdict": "too_small", "score": 0}

    # 1. Prologue check (first 16 bytes)
    head = data[:16]
    for name, sig in SHELLCODE_PROLOGUES.items():
        if head[:len(sig)] == sig:
            matches.append({"type": "prologue", "name": name, "offset": 0})
            flags.append(f"PROLOGUE_{name}")

    # 2. Pattern scan (full region, capped at 256 KB for performance)
    scan_limit = min(len(data), 0x40000)
    scan_data = data[:scan_limit]
    for name, (pattern, desc) in SHELLCODE_PATTERNS.items():
        idx = scan_data.find(pattern)
        if idx != -1:
            matches.append({
                "type": "pattern", "name": name,
                "description": desc, "offset": idx,
            })
            flags.append(name)

    # 3. NOP sled detection
    for nop in NOP_PATTERNS:
        idx = scan_data.find(nop)
        if idx != -1:
            matches.append({"type": "nop_sled", "offset": idx, "length": len(nop)})
            flags.append("NOP_SLED")
            break  # one NOP match is enough

    # 4. Code density heuristic
    #    Shellcode has high byte diversity; empty/heap pages are mostly null.
    non_null = sum(1 for b in data[:4096] if b != 0)
    density = non_null / min(len(data), 4096)
    is_code_like = density >= SHELLCODE_CODE_DENSITY_THRESHOLD

    if is_code_like and not matches:
        # High density but no known pattern — flag as suspicious
        flags.append("HIGH_CODE_DENSITY")

    # 5. MZ header inside RWX (embedded PE — reflective loader)
    mz_offset = scan_data.find(b"MZ")
    if mz_offset != -1 and mz_offset + 0x40 < len(scan_data):
        # Verify PE signature pointer
        try:
            e_lfanew = int.from_bytes(scan_data[mz_offset + 0x3C:mz_offset + 0x40], "little")
            if (0 < e_lfanew < 0x1000
                    and mz_offset + e_lfanew + 4 <= len(scan_data)
                    and scan_data[mz_offset + e_lfanew:mz_offset + e_lfanew + 4] == b"PE\x00\x00"):
                matches.append({"type": "embedded_pe", "offset": mz_offset})
                flags.append("EMBEDDED_PE")
        except Exception:
            logger.debug("PE signature validation failed at MZ offset %d", mz_offset)

    # 6. Statistical classification (pe-sieve approach)
    #    Analyzes byte frequency distribution to classify the region as
    #    code, obfuscated (XOR-encoded), or encrypted.
    sample = data[:4096]
    freq = Counter(sample)
    unique_bytes = len(freq)
    most_common_byte, most_common_count = freq.most_common(1)[0]
    null_ratio = freq.get(0, 0) / len(sample)
    call_opcode_ratio = freq.get(0xE8, 0) / len(sample)  # x86 CALL

    ent = shannon_entropy(sample)

    # Frequency spread: stddev of byte frequencies / mean
    mean_freq = len(sample) / 256
    spread = sum((c - mean_freq) ** 2 for c in freq.values()) / 256
    uniform = spread < (mean_freq * 0.01) ** 2  # nearly uniform distribution

    classification = "unknown"

    # CodeMatcher: real executable code
    if (ent > 3.0 and call_opcode_ratio > 0.01
            and null_ratio > 0.10 and unique_bytes > 50):
        classification = "code"
        if "HIGH_CODE_DENSITY" not in flags:
            flags.append("STAT_CODE")

    # ObfuscatedMatcher: XOR-encoded shellcode
    elif (ent > 3.0 and most_common_byte != 0
            and unique_bytes > 85):
        classification = "obfuscated"
        matches.append({
            "type": "statistical", "name": "xor_obfuscated",
            "description": f"Byte diversity={unique_bytes}, most_common=0x{most_common_byte:02x} (not null)",
        })
        flags.append("STAT_OBFUSCATED")

    # EncryptedMatcher: strongly encrypted
    elif ent > 7.0 or (ent > 6.0 and uniform):
        classification = "encrypted"
        matches.append({
            "type": "statistical", "name": "encrypted",
            "description": f"Entropy={ent:.2f}, uniform_distribution={uniform}",
        })
        flags.append("STAT_ENCRYPTED")

    # 7. Disassembly validation (requires capstone, optional)
    disasm_ratio = 0.0
    try:
        import capstone
        # Auto-detect architecture from region content
        # Default to x64; if first bytes suggest 32-bit, use x86
        mode = capstone.CS_MODE_64
        cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        disasm_sample = data[:1024]
        insn_count = 0
        valid_bytes = 0
        for insn in cs.disasm(disasm_sample, 0):
            insn_count += 1
            valid_bytes += insn.size
        disasm_ratio = valid_bytes / len(disasm_sample) if disasm_sample else 0
        if disasm_ratio > 0.6 and insn_count > 10:
            matches.append({
                "type": "disassembly", "name": "valid_code",
                "description": f"{insn_count} instructions, {disasm_ratio:.0%} valid x86-64",
            })
            flags.append("DISASM_CODE")
    except ImportError:
        pass  # capstone not installed
    except Exception:
        logger.debug("Disassembly validation failed")

    # Score: prologues are strongest signal, patterns additive
    score = 0
    for m in matches:
        if m["type"] == "prologue":
            score += 40
        elif m["type"] == "embedded_pe":
            score += 35
        elif m["type"] == "pattern":
            score += 15
        elif m["type"] == "nop_sled":
            score += 10
        elif m["type"] == "statistical":
            score += 20
        elif m["type"] == "disassembly":
            score += 15
    if is_code_like:
        score += 10

    verdict = "clean"
    if score >= 40:
        verdict = "shellcode"
    elif score >= 15:
        verdict = "suspicious"
    elif is_code_like:
        verdict = "code_like"

    return {
        "matches": matches,
        "flags": flags,
        "verdict": verdict,
        "score": score,
        "code_density": round(density, 3),
        "classification": classification,
        "entropy": round(ent, 2),
        "disasm_ratio": round(disasm_ratio, 3),
    }


def check_executable_regions(mf: Any, modules: list,
                             reader: Any = None) -> list[dict]:
    """CHECK 7: Executable memory regions outside known modules.

    Scans both RWX *and* RX regions.  RX regions outside modules are the #1
    indicator of post-VirtualProtect shellcode (attacker allocs RWX, writes
    payload, flips to RX).  Uses the MEM_PRIVATE/MEM_IMAGE type flag when
    available — executable MEM_PRIVATE memory is almost always injected code.
    """
    EXECUTABLE_PROTECTS = (
        PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    )

    findings: list[dict] = []
    if not hasattr(mf, "memory_info") or not mf.memory_info:
        return findings
    module_ranges = [(m.baseaddress, m.baseaddress + m.size) for m in modules]
    try:
        entries = getattr(mf.memory_info, "infos", None) or mf.memory_info.entries
    except AttributeError:
        return findings
    for info in entries:
        try:
            if getattr(info, "State", 0) != 0x1000:  # MEM_COMMIT
                continue
            protect = getattr(info, "Protect", 0)
            if protect not in EXECUTABLE_PROTECTS:
                continue
            addr = info.BaseAddress
            size = info.RegionSize
            # Skip regions that overlap any known module range
            if any(s < addr + size and addr < e for s, e in module_ranges):
                continue

            mem_type = getattr(info, "Type", 0)
            is_rwx = protect in (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
            is_private = mem_type == MEM_PRIVATE
            is_image = mem_type == MEM_IMAGE

            # RX inside MEM_IMAGE but outside module list = unlisted image
            # RX inside MEM_PRIVATE = strong injection signal
            # RWX anywhere outside modules = suspicious (original check)

            if is_image and not is_rwx:
                # MEM_IMAGE + RX outside module list — could be mapped section;
                # lower severity unless shellcode found
                base_severity = "MEDIUM"
                finding_type = "EXEC_IMAGE_UNMAPPED"
            elif is_private:
                # MEM_PRIVATE + executable = strong injection indicator
                base_severity = "HIGH"
                finding_type = "EXEC_PRIVATE" if not is_rwx else "RWX_PRIVATE"
            elif is_rwx:
                base_severity = "HIGH"
                finding_type = "RWX_REGION"
            else:
                # RX + MEM_MAPPED (or unknown type) outside modules
                base_severity = "LOW"
                finding_type = "EXEC_REGION"

            finding: dict = {
                "type": finding_type, "severity": base_severity,
                "base": f"0x{addr:016x}", "size": size,
                "protect": f"0x{protect:x}",
                "mem_type": f"0x{mem_type:x}" if mem_type else "unknown",
            }

            # Scan content for shellcode if reader available
            if reader is not None and size >= SHELLCODE_MIN_REGION_SIZE:
                try:
                    read_size = min(size, 0x40000)  # cap at 256 KB
                    region_data = reader.read(addr, read_size)
                    sc = analyze_shellcode(region_data)
                    if sc["verdict"] != "clean":
                        finding["shellcode"] = sc
                        if sc["verdict"] == "shellcode":
                            finding["severity"] = "CRITICAL"
                        elif sc["verdict"] == "suspicious":
                            # Private + suspicious shellcode = HIGH
                            finding["severity"] = "HIGH"
                except Exception:
                    logger.warning("Failed to read region at 0x%x for shellcode analysis", addr)

            findings.append(finding)
        except Exception:
            logger.debug("Failed to read memory info entry")
    return findings


def check_suspicious_imports(reader: Any, modules: list, is_32bit: bool) -> list[dict]:
    """CHECK 8: Suspicious API imports in untrusted modules."""
    findings: list[dict] = []
    for mod in modules:
        if is_trusted_path(mod.name):
            continue
        try:
            data, _ = read_module_memory(reader, mod.baseaddress, min(mod.size, 0x100000))
            pe_info = get_pe_info(data)
            if not pe_info.get("is_pe"):
                continue
            _, suspicious = extract_imports(data, pe_info, memory_mapped=True)
            if suspicious:
                sev = "HIGH" if "process_injection" in suspicious else "MEDIUM"
                findings.append({
                    "type": "SUSPICIOUS_IMPORTS", "severity": sev,
                    "module": mod.name, "base": f"0x{mod.baseaddress:016x}",
                    "suspicious_categories": suspicious,
                })
        except Exception:
            logger.warning("Failed to check imports for module at 0x%x", mod.baseaddress)
    return findings


def check_thread_stacks(
    mf: Any, modules: list, reader: Any, is_32bit: bool,
) -> list[dict]:
    """CHECK 9: Walk thread stacks to find return addresses outside known modules.

    Catches threads that were called FROM shellcode but are currently executing
    inside a legitimate module (e.g., in kernel32.Sleep after being called from
    injected code).
    """
    from memdump_toolkit.constants import STACK_CRITICAL_THRESHOLD
    from memdump_toolkit.pe_utils import walk_stack_frames

    findings: list[dict] = []
    if not hasattr(mf, "threads") or not mf.threads:
        return findings

    module_ranges = _build_module_ranges(modules)

    # Build executable memory ranges (for stack scan false positive filtering)
    exec_ranges: list[tuple[int, int]] = []
    if hasattr(mf, "memory_info") and mf.memory_info:
        EXECUTABLE_PROTECTS = (
            PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        )
        try:
            entries = getattr(mf.memory_info, "infos", None) or mf.memory_info.entries
            for info in entries:
                if (getattr(info, "State", 0) == 0x1000
                        and getattr(info, "Protect", 0) in EXECUTABLE_PROTECTS):
                    exec_ranges.append((info.BaseAddress, info.BaseAddress + info.RegionSize))
        except AttributeError:
            pass

    # Build .pdata unwind tables for precise x64 stack walking
    pdata_tables: list[list[tuple[int, int, int]]] = []
    if not is_32bit:
        from memdump_toolkit.pe_utils import parse_pdata
        for mod in modules:
            try:
                base = mod.baseaddress
                size = mod.size
                # Read module from memory to parse .pdata
                data = reader.read(base, min(size, 0x100000))  # Cap at 1MB for .pdata parsing
                table = parse_pdata(data, base)
                if table:
                    pdata_tables.append(table)
            except Exception:
                continue

    try:
        threads = mf.threads.threads
    except AttributeError:
        return findings

    for thread in threads:
        try:
            ctx = thread.ThreadContext
            if ctx is None:
                continue

            if is_32bit:
                rsp = getattr(ctx, "Esp", 0) or 0
                rbp = getattr(ctx, "Ebp", 0) or 0
            else:
                rsp = getattr(ctx, "Rsp", 0) or 0
                rbp = getattr(ctx, "Rbp", 0) or 0

            if rsp <= 0x10000:
                continue

            frames = walk_stack_frames(
                reader, rsp, rbp, module_ranges,
                is_32bit=is_32bit, exec_ranges=exec_ranges,
                pdata_tables=pdata_tables,
            )

            # Find return addresses outside any known module
            outside = [f for f in frames if not f["in_module"]]
            if not outside:
                continue

            sev = "CRITICAL" if len(outside) >= STACK_CRITICAL_THRESHOLD else "HIGH"
            findings.append({
                "type": "STACK_RETURN_OUTSIDE_MODULE",
                "severity": sev,
                "thread_id": thread.ThreadId,
                "suspicious_returns": len(outside),
                "total_frames": len(frames),
                "details": [
                    {
                        "address": f"0x{f['address']:016x}",
                        "source": f["source"],
                        "frame_depth": f.get("frame_depth", f.get("stack_offset", -1)),
                    }
                    for f in outside[:10]  # Cap details at 10 entries
                ],
            })
        except Exception:
            logger.debug("Failed to walk stack for TID %s",
                         getattr(thread, "ThreadId", "?"))

    return findings


# ─── Core Analysis ───────────────────────────────────────────────────────────

def analyze(mf: Any, reader: Any, out_dir: str) -> dict[str, Any]:
    """Core injection analysis (called by orchestrator with pre-parsed dump)."""
    if not mf.modules:
        logger.info("No modules found.")
        return {"dump": "", "findings": [], "bitness": 64}

    modules = mf.modules.modules
    report: dict = {"findings": [], "bitness": 64}

    # Detect bitness
    is_32bit = False
    try:
        first_data = reader.read(modules[0].baseaddress, min(0x400, modules[0].size))
        is_32bit = detect_pe_bitness(first_data) == 32
    except Exception:
        logger.warning("Bitness detection failed for module analysis")
    report["bitness"] = 32 if is_32bit else 64

    name_map: dict[str, list] = defaultdict(list)
    for mod in modules:
        name_map[Path(mod.name).name.lower()].append(mod)

    # CHECK 1: Typosquatting (Levenshtein + Homoglyph)
    logger.info("\n%s", "=" * 80)
    logger.info("[1] TYPOSQUATTING DETECTION (Levenshtein + homoglyph)")
    logger.info("%s", "=" * 80)

    for mod in modules:
        mod_name = Path(mod.name).name.lower()
        for legit in SYSTEM_DLLS:
            if mod_name == legit:
                continue
            # Length pre-filter: skip if names differ by > 2 chars
            if abs(len(mod_name) - len(legit)) > 2:
                continue
            dist = levenshtein(mod_name, legit)
            homoglyph = is_homoglyph(mod_name, legit)
            if not (0 < dist <= 2 or homoglyph):
                continue

            detection = "HOMOGLYPH" if homoglyph else f"EDIT_DIST_{dist}"
            finding: dict = {
                "type": "TYPOSQUATTING", "severity": "HIGH",
                "module": mod.name, "base": f"0x{mod.baseaddress:016x}",
                "size": mod.size, "similar_to": legit,
                "edit_distance": dist, "detection_method": detection,
                "heap_address": is_heap_address(mod.baseaddress, is_32bit),
            }
            if legit in name_map:
                real = name_map[legit][0]
                finding["legitimate_base"] = f"0x{real.baseaddress:016x}"
                if mod.size == real.size:
                    logger.info("\n  Comparing '%s' vs '%s'...", Path(mod.name).name, legit)
                    finding["comparison"] = compare_modules(
                        reader, mod.baseaddress, real.baseaddress, mod.size,
                    )
            report["findings"].append(finding)
            logger.info("\n  ⚠ TYPOSQUAT [%s]: %s -> mimics %s", detection, Path(mod.name).name, legit)
            logger.info("    Base: %s  (heap: %s)", finding['base'], finding['heap_address'])
            if "comparison" in finding:
                c = finding["comparison"]
                logger.info("    Similarity: %s%%  (%s/%s pages)", c['similarity_pct'], c['identical_pages'], c['total_pages'])

    # CHECK 2: Heap-loaded modules
    logger.info("\n%s", "=" * 80)
    logger.info("[2] HEAP-REGION MODULES (%s address space)", "x86" if is_32bit else "x64")
    logger.info("%s", "=" * 80)

    flagged_bases = {f["base"] for f in report["findings"]}
    for mod in modules:
        if is_heap_address(mod.baseaddress, is_32bit):
            base_str = f"0x{mod.baseaddress:016x}"
            if base_str not in flagged_bases:
                report["findings"].append({
                    "type": "HEAP_LOADED_MODULE", "severity": "MEDIUM",
                    "module": mod.name, "base": base_str, "size": mod.size,
                })
                logger.info("  ⚠ %-50s  Base: %s  Size: %s", Path(mod.name).name, base_str, f"{mod.size:,}")

    # CHECK 3: Duplicate modules
    logger.info("\n%s", "=" * 80)
    logger.info("[3] DUPLICATE MODULE NAMES")
    logger.info("%s", "=" * 80)

    for name, mods in name_map.items():
        if len(mods) > 1:
            report["findings"].append({
                "type": "DUPLICATE_MODULE", "severity": "HIGH",
                "module_name": name,
                "instances": [{"base": f"0x{m.baseaddress:016x}", "path": m.name} for m in mods],
            })
            logger.info("\n  ⚠ '%s' loaded %d times:", name, len(mods))
            for m in mods:
                logger.info("    0x%016x  %s", m.baseaddress, m.name)

    # CHECK 4: Hidden PE images
    logger.info("\n%s", "=" * 80)
    logger.info("[4] HIDDEN PE IMAGES (not in module list)")
    logger.info("%s", "=" * 80)

    known_bases = get_known_bases(mf)
    hidden_count = hidden_unknown = 0

    for seg in reader.memory_segments:
        base = seg.start_virtual_address
        seg_size = seg.end_virtual_address - base
        hdr_result = check_pe_header(reader, base, seg_size)
        if not hdr_result or base in known_bases:
            continue

        pe_off, img_size, hdr = hdr_result
        hidden_count += 1

        # Use get_pe_info on the header for identity (no full read needed here)
        pe_info = get_pe_info(hdr)
        identity = get_pe_identity(pe_info)

        # If header was too small for version info, try reading more
        if not identity or identity == "UNKNOWN":
            try:
                more = reader.read(base, min(seg_size, 0x10000))
                more_info = get_pe_info(more)
                identity = get_pe_identity(more_info)
            except Exception:
                logger.debug("Failed to extract PE identity for hidden module")
                identity = "UNKNOWN"

        is_dll = pe_info.get("is_dll", False)
        ep = pe_info.get("entry_point", 0)

        is_go = False
        try:
            page = reader.read(base, min(seg_size, PAGE_SIZE))
            if b"Go build" in page or b".symtab" in page or b"go.buildid" in page:
                is_go = True
        except Exception:
            logger.debug("Failed to read page for Go marker check at 0x%x", base)

        severity = "LOW"
        flags: list[str] = []
        if identity == "UNKNOWN":
            hidden_unknown += 1
            severity = "HIGH"
            flags.append("NO_IDENTITY")
        if is_heap_address(base, is_32bit):
            flags.append("HEAP_REGION")
        if ep == 0x200:  # Common shellcode/packed PE entry point
            severity = "HIGH"
            flags.append("SUSPICIOUS_EP_0x200")
        if is_go:
            severity = "CRITICAL"
            flags.append("GO_BINARY")
        if img_size > LARGE_PE_THRESHOLD and identity == "UNKNOWN":
            severity = "CRITICAL"
            flags.append("LARGE_UNKNOWN")

        report["findings"].append({
            "type": "HIDDEN_PE", "severity": severity,
            "base": f"0x{base:016x}", "image_size": img_size,
            "captured_in_segment": seg_size, "is_dll": is_dll,
            "entry_point": f"0x{ep:x}",
            "timestamp": pe_info.get("timestamp", ""),
            "identity": identity, "is_go": is_go, "flags": flags,
        })

        if severity in ("HIGH", "CRITICAL"):
            marker = "!!!" if severity == "CRITICAL" else " ! "
            logger.info("  [%s] 0x%016x  %s  ImgSize=0x%x  EP=0x%x  %s", marker, base, "DLL" if is_dll else "EXE", img_size, ep, identity)
            if flags:
                logger.info("        Flags: %s", ", ".join(flags))

    # Deep scan: search for MZ headers at page-aligned offsets WITHIN segments.
    # Catches manually mapped PEs that don't start at a segment boundary.
    found_bases = known_bases | {
        int(f["base"], 16) for f in report["findings"] if f.get("type") == "HIDDEN_PE"
    }
    deep_count = 0
    for seg in reader.memory_segments:
        seg_base = seg.start_virtual_address
        seg_size = seg.end_virtual_address - seg_base
        # Only scan segments > 1 page that aren't tiny
        if seg_size <= PAGE_SIZE * 2 or seg_size > MAX_SEGMENT_SCAN_SIZE:
            continue
        # Scan segment in 2 MB chunks to cover the full segment
        chunk_size = 2_000_000
        for chunk_offset in range(0, seg_size, chunk_size):
            read_size = min(chunk_size, seg_size - chunk_offset)
            try:
                chunk_data = reader.read(seg_base + chunk_offset, read_size)
            except Exception:
                break
            # Scan at every page boundary; skip offset 0 of the first chunk
            # (already checked in the segment-boundary scan above)
            scan_start = PAGE_SIZE if chunk_offset == 0 else 0
            for off in range(scan_start, len(chunk_data) - 0x200, PAGE_SIZE):
                if chunk_data[off:off + 2] != b"MZ":
                    continue
                candidate_base = seg_base + chunk_offset + off
                if candidate_base in found_bases:
                    continue
                # Validate PE header
                hdr_result = check_pe_header(reader, candidate_base, seg_size - (chunk_offset + off))
                if not hdr_result:
                    continue
                pe_off, img_size, hdr = hdr_result
                pe_info = get_pe_info(hdr)
                identity = get_pe_identity(pe_info)

                found_bases.add(candidate_base)
                hidden_count += 1
                deep_count += 1
                is_dll = pe_info.get("is_dll", False)
                ep = pe_info.get("entry_point", 0)

                severity = "HIGH"
                flags_deep: list[str] = ["DEEP_SCAN", "MID_SEGMENT"]
                if identity == "UNKNOWN":
                    hidden_unknown += 1
                    flags_deep.append("NO_IDENTITY")
                if img_size > LARGE_PE_THRESHOLD and identity == "UNKNOWN":
                    severity = "CRITICAL"
                    flags_deep.append("LARGE_UNKNOWN")

                report["findings"].append({
                    "type": "HIDDEN_PE", "severity": severity,
                    "base": f"0x{candidate_base:016x}", "image_size": img_size,
                    "captured_in_segment": seg_size, "is_dll": is_dll,
                    "entry_point": f"0x{ep:x}",
                    "timestamp": pe_info.get("timestamp", ""),
                    "identity": identity, "flags": flags_deep,
                })
                logger.info("  [ ! ] 0x%016x  %s  ImgSize=0x%x  EP=0x%x  %s  [DEEP_SCAN]", candidate_base, "DLL" if is_dll else "EXE", img_size, ep, identity)

    if deep_count:
        logger.info("  Deep scan found %d additional PE(s) inside segments", deep_count)

    # Headerless PE recovery: find PEs with zeroed MZ headers
    from memdump_toolkit.pe_utils import find_headerless_pe
    headerless_count = 0
    for seg in reader.memory_segments:
        base = seg.start_virtual_address
        seg_size = seg.end_virtual_address - base
        if seg_size < 0x200 or base in found_bases:
            continue
        try:
            hdr_data = reader.read(base, min(seg_size, 0x2000))
        except Exception:
            continue
        if hdr_data[:2] == b"MZ":
            continue
        candidates = find_headerless_pe(hdr_data, base)
        for cand in candidates:
            found_bases.add(base)
            hidden_count += 1
            headerless_count += 1

            machine_str = "x64" if cand.get("machine") == 0x8664 else "x86" if cand.get("machine") == 0x014C else "?"
            sec_names = [s["name"] for s in cand.get("sections", [])]

            severity = "CRITICAL"
            flags_hl: list[str] = ["HEADERLESS_PE", "MZ_ZEROED"]
            if not cand.get("machine_confirmed"):
                flags_hl.append("MACHINE_UNCONFIRMED")
                severity = "HIGH"

            report["findings"].append({
                "type": "HIDDEN_PE", "severity": severity,
                "base": f"0x{base:016x}",
                "image_size": cand.get("image_size_est", 0),
                "captured_in_segment": seg_size,
                "is_dll": False,
                "entry_point": "",
                "timestamp": "",
                "identity": "HEADERLESS_PE",
                "flags": flags_hl,
                "machine": machine_str,
                "num_sections": cand["num_sections"],
                "section_names": sec_names,
            })
            logger.info("  [!!!] 0x%016x  HEADERLESS  %s  %d sections: %s  [MZ_ZEROED]",
                        base, machine_str, cand["num_sections"], ", ".join(sec_names))

    if headerless_count:
        logger.info("  Headerless PE recovery found %d PE(s) with zeroed headers", headerless_count)

    logger.info("\n  Total hidden: %d  (Unknown: %d)", hidden_count, hidden_unknown)

    # CHECK 5: Untrusted paths
    logger.info("\n%s", "=" * 80)
    logger.info("[5] UNTRUSTED MODULE PATHS")
    logger.info("%s", "=" * 80)

    for mod in modules:
        if not is_trusted_path(mod.name):
            report["findings"].append({
                "type": "UNTRUSTED_PATH", "severity": "INFO",
                "module": mod.name, "base": f"0x{mod.baseaddress:016x}",
            })
            logger.info("  %-50s  %s", Path(mod.name).name, mod.name)

    # CHECK 6: Thread injection
    logger.info("\n%s", "=" * 80)
    logger.info("[6] THREADS EXECUTING OUTSIDE MODULES")
    logger.info("%s", "=" * 80)

    thread_findings = check_threads(mf, modules)
    for f in thread_findings:
        report["findings"].append(f)
        logger.info("  ⚠ Thread %s at %s (outside all modules)", f['thread_id'], f['instruction_pointer'])
    if not thread_findings:
        logger.info("  No suspicious thread start addresses detected.")

    # CHECK 7: Executable memory (RWX + RX + MEM_PRIVATE)
    logger.info("\n%s", "=" * 80)
    logger.info("[7] EXECUTABLE MEMORY REGIONS (outside modules)")
    logger.info("%s", "=" * 80)

    exec_findings = check_executable_regions(mf, modules, reader=reader)
    for f in exec_findings:
        report["findings"].append(f)
        sc = f.get("shellcode")
        ftype = f["type"]
        if sc and sc["verdict"] in ("shellcode", "suspicious"):
            label = "SHELLCODE" if sc["verdict"] == "shellcode" else "SUSPICIOUS"
            flags_str = ", ".join(sc["flags"][:5])
            logger.info("  ⚠ %s at %s  Size: %s  [%s] %s", ftype, f['base'], f"{f['size']:,}", label, flags_str)
        elif ftype in ("RWX_REGION", "RWX_PRIVATE", "EXEC_PRIVATE"):
            logger.info("  ⚠ %s at %s  Size: %s  Protect: %s  Type: %s", ftype, f['base'], f"{f['size']:,}", f['protect'], f.get('mem_type', '?'))
        else:
            # Lower-severity exec regions — only print if HIGH+
            if f.get("severity") in ("CRITICAL", "HIGH"):
                logger.info("  ⚠ %s at %s  Size: %s  Protect: %s", ftype, f['base'], f"{f['size']:,}", f['protect'])
    if not exec_findings:
        logger.info("  No suspicious executable regions detected (or MemoryInfoList not in dump).")

    # CHECK 8: Suspicious imports
    logger.info("\n%s", "=" * 80)
    logger.info("[8] SUSPICIOUS PE IMPORTS")
    logger.info("%s", "=" * 80)

    import_findings = check_suspicious_imports(reader, modules, is_32bit)
    for f in import_findings:
        report["findings"].append(f)
        cats = ", ".join(f["suspicious_categories"].keys())
        logger.info("  ⚠ %-50s  Categories: %s", Path(f['module']).name, cats)
    if not import_findings:
        logger.info("  No suspicious import combinations detected in untrusted modules.")

    # CHECK 9: Stack frame walking
    logger.info("\n%s", "=" * 80)
    logger.info("[9] THREAD STACK RETURN ADDRESS ANALYSIS")
    logger.info("%s", "=" * 80)

    stack_findings = check_thread_stacks(mf, modules, reader, is_32bit)
    for f in stack_findings:
        report["findings"].append(f)
        logger.info("  ⚠ Thread %s: %d/%d return addresses outside modules [%s]",
                     f['thread_id'], f['suspicious_returns'], f['total_frames'],
                     f['severity'])
        for d in f.get("details", [])[:5]:
            logger.info("      → %s (%s)", d['address'], d['source'])
    if not stack_findings:
        logger.info("  No suspicious stack return addresses detected.")

    # Summary
    logger.info("\n%s", "=" * 80)
    logger.info("SUMMARY")
    logger.info("%s", "=" * 80)

    by_severity = Counter(f["severity"] for f in report["findings"])
    by_type = Counter(f["type"] for f in report["findings"])
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in by_severity:
            logger.info("  %-10s: %s", sev, by_severity[sev])
    logger.info("")
    for t, c in sorted(by_type.items()):
        logger.info("  %-30s: %s", t, c)

    return report


def run(dump_path: str, out_dir: str | None = None, verbose: bool = False) -> dict[str, Any]:
    """Standalone entry point."""
    setup_logging(verbose)
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(dump_path) or ".", "output")

    print(f"Analyzing: {dump_path}")
    mf = MinidumpFile.parse(dump_path)
    reader = mf.get_reader()
    report = analyze(mf, reader, out_dir)
    report["dump"] = dump_path

    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "injection_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved: {report_path}")
    return report
