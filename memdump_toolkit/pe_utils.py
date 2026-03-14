"""
Shared PE parsing utilities, memory I/O, hashing, and entropy.

Uses the `pefile` library for all PE structure parsing (headers, imports,
exports, sections, data directories).  Manual struct unpacking has been
replaced — pefile handles malformed PEs, edge cases, and both PE32/PE32+
transparently.
"""

from __future__ import annotations

import csv
import hashlib
import logging
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import pefile

# Suppress pefile warnings for corrupt/truncated memory-dumped PEs
logging.getLogger("pefile").setLevel(logging.ERROR)

from memdump_toolkit.constants import (
    HEAP_THRESHOLD_X86, HEAP_THRESHOLD_X64, HIGH_ENTROPY_THRESHOLD,
    PAGE_SIZE, SUSPICIOUS_IMPORTS,
)


def safe_filename(name: str) -> str:
    """Sanitize a filename from dump data for safe filesystem use."""
    import re as _re
    from pathlib import PureWindowsPath
    basename = PureWindowsPath(name).name
    basename = _re.sub(r'[<>:"|?*\x00/]', '_', basename)
    if not basename or basename in (".", ".."):
        basename = "unnamed"
    return basename

# Sanity cap: reject PE headers claiming images larger than this
MAX_IMAGE_SIZE = 512 * 1024 * 1024  # 512 MB

logger = logging.getLogger("memdump_toolkit")

PEInfo = dict[str, Any]
SectionInfo = dict[str, Any]


def setup_logging(verbose: bool = False) -> None:
    """Configure root logging level and format for memdump_toolkit."""
    import sys as _sys
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=_sys.stdout,
        force=True,
    )


# ─── Hashing & Entropy ──────────────────────────────────────────────────────

def compute_hashes(data: bytes) -> dict[str, str]:
    """Compute MD5 and SHA-256 hashes of binary data."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of bytes, 0.0–8.0 scale."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


# ─── PE Timestamps ──────────────────────────────────────────────────────────

def timestamp_to_str(ts: int) -> str:
    """PE timestamp (epoch seconds) → human-readable UTC string."""
    if ts == 0 or ts == 0xFFFFFFFF:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError, OverflowError):
        return ""


# ─── Address Classification ─────────────────────────────────────────────────

def is_heap_address(addr: int, is_32bit: bool = False) -> bool:
    """Bitness-aware check: is this address in a heap/private region?"""
    if is_32bit:
        return 0x00100000 < addr < HEAP_THRESHOLD_X86
    return 0x0000010000000000 < addr < HEAP_THRESHOLD_X64


def detect_pe_bitness(data: bytes) -> int:
    """Return 32 or 64 from PE optional header magic."""
    try:
        pe = pefile.PE(data=data, fast_load=True)
        try:
            result = 32 if pe.OPTIONAL_HEADER.Magic == 0x10B else 64
        finally:
            pe.close()
        return result
    except Exception:
        logger.warning("PE bitness detection failed, assuming 64-bit")
        return 64


# ─── Memory I/O ─────────────────────────────────────────────────────────────

def read_pe_data(reader: Any, base: int, size: int) -> bytes:
    """Read PE image page-by-page from minidump reader."""
    data = bytearray(size)
    for off in range(0, size, PAGE_SIZE):
        try:
            chunk = reader.read(base + off, min(PAGE_SIZE, size - off))
            data[off:off + len(chunk)] = chunk
        except Exception:
            logger.debug("Failed to read page at 0x%x", base + off)
    return bytes(data)


def read_module_memory(reader: Any, base: int, size: int) -> tuple[bytes, int]:
    """Full-read first, page-by-page fallback. Returns (data, bytes_read)."""
    try:
        return reader.read(base, size), size
    except Exception:
        logger.debug("Full read failed at 0x%x, falling back to page-by-page", base)

    result = bytearray(size)
    bytes_read = 0
    for offset in range(0, size, PAGE_SIZE):
        chunk_size = min(PAGE_SIZE, size - offset)
        try:
            data = reader.read(base + offset, chunk_size)
            result[offset:offset + len(data)] = data
            bytes_read += len(data)
        except Exception:
            logger.debug("Page read failed at 0x%x+0x%x", base, offset)
    return bytes(result), bytes_read


def read_pe_full_image(reader: Any, base: int, img_size: int, seg_size: int) -> bytes:
    """Read a hidden PE image, handling segment boundary extension."""
    read_size = min(img_size, seg_size)

    try:
        data = reader.read(base, read_size)
    except Exception:
        logger.debug("Full image read failed at 0x%x, falling back to page-by-page", base)
        data = bytes(read_pe_data(reader, base, read_size))

    if read_size < img_size:
        full_data = bytearray(img_size)
        full_data[:len(data)] = data
        for off in range(read_size, img_size, PAGE_SIZE):
            try:
                chunk = reader.read(base + off, min(PAGE_SIZE, img_size - off))
                full_data[off:off + len(chunk)] = chunk
            except Exception:
                logger.debug("Extension page read failed at 0x%x+0x%x", base, off)
        data = bytes(full_data)

    return data


# ─── PE Section Parsing ─────────────────────────────────────────────────────

def parse_pe_sections(data: bytes, pe_off: int = 0) -> list[SectionInfo]:
    """Parse PE section table into list of dicts using pefile.

    The pe_off parameter is accepted for backward compatibility but ignored —
    pefile locates the section table automatically.
    """
    sections: list[SectionInfo] = []
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception:
        return sections

    sections = _sections_from_pe(pe)
    pe.close()
    return sections


def _sections_from_pe(pe: pefile.PE) -> list[SectionInfo]:
    """Extract section info dicts from a parsed pefile.PE object."""
    sections: list[SectionInfo] = []
    for sec in pe.sections:
        name_raw = sec.Name.rstrip(b"\x00")
        sections.append({
            "name": name_raw.decode("ascii", errors="replace"),
            "name_raw": name_raw,
            "virtual_size": sec.Misc_VirtualSize,
            "virtual_address": sec.VirtualAddress,
            "raw_size": sec.SizeOfRawData,
            "raw_ptr": sec.PointerToRawData,
            "characteristics": sec.Characteristics,
        })
    return sections


# ─── RVA Resolution ──────────────────────────────────────────────────────────

def rva_to_raw(sections: list[SectionInfo], rva: int) -> int:
    """Convert RVA to raw file offset via section table (for on-disk PEs)."""
    for sec in sections:
        va = sec["virtual_address"]
        vs = max(sec["virtual_size"], sec["raw_size"])
        if va <= rva < va + vs:
            return sec["raw_ptr"] + (rva - va)
    return rva


def resolve_rva(
    data: bytes, rva: int,
    sections: list[SectionInfo] | None = None,
    memory_mapped: bool = True,
) -> int:
    """Resolve RVA to buffer offset. memory_mapped=True → RVA is the offset."""
    if memory_mapped or not sections:
        return rva
    return rva_to_raw(sections, rva)


# ─── Version Info Extraction ─────────────────────────────────────────────────

def _extract_version_info_pefile(pe: pefile.PE) -> dict[str, str]:
    """Extract version info strings using pefile's VS_VERSIONINFO parser."""
    info: dict[str, str] = {}
    try:
        if not hasattr(pe, "FileInfo") or not pe.FileInfo:
            return info
        for fi_list in pe.FileInfo:
            for fi in fi_list:
                if hasattr(fi, "StringTable"):
                    for st in fi.StringTable:
                        for key, val in st.entries.items():
                            k = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else str(key)
                            v = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
                            if k in ("OriginalFilename", "InternalName", "FileDescription",
                                     "CompanyName", "ProductName") and v:
                                info[k] = v
    except Exception:
        logger.debug("Failed to extract version info via pefile")
    return info


def extract_version_info(data: bytes, sections: list[SectionInfo] | None = None) -> dict[str, str]:
    """Extract version info strings from PE data.

    Uses pefile for structured parsing, falls back to UTF-16 string scanning.
    """
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        info = _extract_version_info_pefile(pe)
        pe.close()
        if info:
            return info
    except Exception:
        logger.debug("Structured version info extraction failed, trying UTF-16 fallback")

    # Fallback: scan .rsrc section as UTF-16-LE
    info = {}
    search_data = data
    if sections:
        for sec in sections:
            if sec["name"].startswith(".rsrc"):
                start = sec["virtual_address"]
                end = min(start + sec["virtual_size"], len(data))
                if start < len(data):
                    search_data = data[start:end]
                    break

    search_data = search_data[:min(len(search_data), 2 * 1024 * 1024)]
    try:
        text = search_data.decode("utf-16-le", errors="ignore")
        for marker in ["OriginalFilename", "InternalName", "FileDescription",
                        "CompanyName", "ProductName"]:
            idx = text.find(marker)
            if idx >= 0:
                val_start = idx + len(marker) + 1
                val_end = text.find("\x00", val_start)
                if val_end > val_start:
                    val = text[val_start:val_end].strip()
                    if val:
                        info[marker] = val
    except Exception:
        logger.debug("Failed to extract version info")
    return info


# ─── Full PE Info ────────────────────────────────────────────────────────────

def get_pe_info(data: bytes, memory_mapped: bool = True) -> PEInfo:
    """Extract comprehensive PE metadata using pefile.

    Args:
        data: Raw PE bytes (memory-mapped from dump, or read from disk).
        memory_mapped: True → RVA equals buffer offset. False → use section table.
    """
    info: PEInfo = {"is_pe": False}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return info

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return info

    info["is_pe"] = True
    info["pe_offset"] = pe.DOS_HEADER.e_lfanew

    # Timestamp
    ts = pe.FILE_HEADER.TimeDateStamp
    info["timestamp_raw"] = ts
    info["timestamp"] = f"0x{ts:x}"
    info["timestamp_str"] = timestamp_to_str(ts)

    info["num_sections"] = pe.FILE_HEADER.NumberOfSections
    info["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    info["entry_point"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    info["image_size"] = pe.OPTIONAL_HEADER.SizeOfImage

    magic = pe.OPTIONAL_HEADER.Magic
    info["is_64bit"] = magic == 0x20B
    info["is_32bit"] = magic == 0x10B

    # Sections
    sections = _sections_from_pe(pe)
    info["sections"] = [s["name"] for s in sections]
    info["sections_detail"] = sections

    # Section entropy
    section_entropies = []
    for sec_info in sections:
        start = sec_info["virtual_address"] if memory_mapped else sec_info["raw_ptr"]
        size = sec_info["virtual_size"] if memory_mapped else sec_info["raw_size"]
        if start < len(data) and size > 0:
            end = min(start + size, len(data))
            ent = shannon_entropy(data[start:end])
            section_entropies.append({
                "name": sec_info["name"], "entropy": ent,
                "size": size, "packed": ent > HIGH_ENTROPY_THRESHOLD,
            })
    info["section_entropy"] = section_entropies

    # Exports
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exp = pe.DIRECTORY_ENTRY_EXPORT
            if exp.name:
                name = exp.name
                info["export_name"] = name.decode("ascii", errors="replace") if isinstance(name, bytes) else str(name)
            exports = []
            for sym in exp.symbols[:100]:
                if sym.name:
                    n = sym.name
                    exports.append(n.decode("ascii", errors="replace") if isinstance(n, bytes) else str(n))
            info["exports"] = exports
    except Exception:
        logger.debug("Failed to parse export directory")

    # Version info
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        vi = _extract_version_info_pefile(pe)
        if vi:
            info["version_info"] = vi
    except Exception:
        logger.debug("Failed to parse version info resource directory")

    if "version_info" not in info:
        vi = extract_version_info(data, sections)
        if vi:
            info["version_info"] = vi

    info["hashes"] = compute_hashes(data)
    pe.close()
    return info


# ─── Import Table ────────────────────────────────────────────────────────────

def extract_imports(
    data: bytes,
    pe_info: PEInfo | None = None,
    memory_mapped: bool = True,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Extract imports using pefile. Returns (imports_dict, suspicious_categories)."""
    imports: dict[str, list[str]] = {}
    suspicious: dict[str, list[str]] = {}

    if pe_info and not pe_info.get("is_pe"):
        return imports, suspicious

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    except Exception:
        return imports, suspicious

    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("ascii", errors="replace") if entry.dll else "unknown"
                func_names: list[str] = []
                for imp in entry.imports:
                    if imp.name:
                        func_names.append(
                            imp.name.decode("ascii", errors="replace") if isinstance(imp.name, bytes) else str(imp.name)
                        )
                    elif imp.ordinal:
                        func_names.append(f"ordinal_{imp.ordinal}")
                imports[dll_name] = func_names

        all_funcs: set[str] = set()
        for funcs in imports.values():
            all_funcs.update(funcs)
        for category, susp_funcs in SUSPICIOUS_IMPORTS.items():
            found = susp_funcs & all_funcs
            if found:
                suspicious[category] = sorted(found)
    except Exception:
        logger.debug("Failed to parse import directory")

    pe.close()
    return imports, suspicious


# ─── PE Header Validation ────────────────────────────────────────────────────

def check_pe_header(
    reader: Any, base: int, seg_size: int,
) -> tuple[int, int, bytes] | None:
    """Validate MZ/PE at address. Returns (pe_off, img_size, hdr_bytes) or None."""
    if seg_size < 0x200:
        return None
    try:
        hdr = reader.read(base, min(0x400, seg_size))
    except Exception:
        logger.debug("Failed to read PE header at 0x%x", base)
        return None
    if hdr[:2] != b"MZ":
        return None

    try:
        pe = pefile.PE(data=hdr, fast_load=True)
    except pefile.PEFormatError:
        return None

    pe_off = pe.DOS_HEADER.e_lfanew
    img_size = pe.OPTIONAL_HEADER.SizeOfImage

    pe.close()

    if img_size < 0x200 or img_size > MAX_IMAGE_SIZE:
        return None
    return pe_off, img_size, hdr


def find_headerless_pe(data: bytes, base_addr: int = 0) -> list[dict[str, Any]]:
    """Find PE artifacts in memory where the MZ header has been zeroed out.

    Searches for section table patterns (characteristics, section names)
    and validates by finding the IMAGE_FILE_HEADER.Machine field nearby.

    Returns list of candidate PEs:
        [{"offset": int, "machine": int, "num_sections": int, "image_size_est": int}]
    """
    from memdump_toolkit.constants import (
        PE_VALID_MACHINES, PE_SECTION_CODE_EXEC_READ, PE_KNOWN_SECTION_NAMES,
        PE_SECTION_HEADER_SIZE, PE_MIN_SECTIONS_HEADERLESS, PE_MAX_SECTIONS_HEADERLESS,
    )
    import struct

    results: list[dict[str, Any]] = []
    if len(data) < 0x200:
        return results

    # Strategy: scan for section characteristic patterns at 40-byte intervals.
    # In a PE section table, the Characteristics field is at offset +36 within
    # each 40-byte section header. If we find CODE|EXECUTE|READ (0x60000020)
    # at some offset, the next section's characteristics would be at offset+40.

    # Scan for the characteristic pattern
    target_chars = struct.pack("<I", PE_SECTION_CODE_EXEC_READ)
    scan_limit = min(len(data), 0x2000)  # Section table is always in first ~8 KB

    pos = 0
    while pos < scan_limit - 4:
        idx = data.find(target_chars, pos, scan_limit)
        if idx == -1:
            break
        pos = idx + 1

        # Characteristics is at offset +36 within a 40-byte section header.
        # So the start of this section header is at idx - 36.
        sec_start = idx - 36
        if sec_start < 0:
            continue

        # Validate: the first 8 bytes of the section header should be the name.
        # Check if it looks like a known section name.
        sec_name = data[sec_start:sec_start + 8]
        name_match = sec_name in PE_KNOWN_SECTION_NAMES
        # Also accept names that are printable ASCII (custom section names)
        name_printable = all(
            (0x20 <= b <= 0x7E or b == 0) for b in sec_name
        ) and sec_name[0] != 0

        if not (name_match or name_printable):
            continue

        # Walk forward and backward to find all consecutive section headers
        sections_found: list[dict] = []

        # Walk backward from sec_start to find earlier sections
        check = sec_start
        while check >= 0:
            s_name = data[check:check + 8]
            s_printable = all(
                (0x20 <= b <= 0x7E or b == 0) for b in s_name
            ) and len(s_name) == 8 and s_name[0] != 0

            if not (s_name in PE_KNOWN_SECTION_NAMES or s_printable):
                break

            if check + 40 <= len(data):
                vsize = struct.unpack_from("<I", data, check + 8)[0]
                va = struct.unpack_from("<I", data, check + 12)[0]
                rsize = struct.unpack_from("<I", data, check + 16)[0]
                chars = struct.unpack_from("<I", data, check + 36)[0]
                sections_found.insert(0, {
                    "name": s_name.rstrip(b"\x00").decode("ascii", errors="replace"),
                    "virtual_size": vsize,
                    "virtual_address": va,
                    "raw_size": rsize,
                    "characteristics": chars,
                })
            check -= PE_SECTION_HEADER_SIZE

        # Walk forward from the section after sec_start
        check = sec_start + PE_SECTION_HEADER_SIZE
        while check + PE_SECTION_HEADER_SIZE <= len(data) and check < scan_limit:
            s_name = data[check:check + 8]
            s_printable = all(
                (0x20 <= b <= 0x7E or b == 0) for b in s_name
            ) and len(s_name) == 8 and s_name[0] != 0

            if not (s_name in PE_KNOWN_SECTION_NAMES or s_printable):
                break

            vsize = struct.unpack_from("<I", data, check + 8)[0]
            va = struct.unpack_from("<I", data, check + 12)[0]
            rsize = struct.unpack_from("<I", data, check + 16)[0]
            chars = struct.unpack_from("<I", data, check + 36)[0]
            sections_found.append({
                "name": s_name.rstrip(b"\x00").decode("ascii", errors="replace"),
                "virtual_size": vsize,
                "virtual_address": va,
                "raw_size": rsize,
                "characteristics": chars,
            })
            check += PE_SECTION_HEADER_SIZE

        # Validate: need at least PE_MIN_SECTIONS_HEADERLESS sections
        if len(sections_found) < PE_MIN_SECTIONS_HEADERLESS:
            continue
        if len(sections_found) > PE_MAX_SECTIONS_HEADERLESS:
            continue

        # Validate: virtual addresses should be ascending
        vas = [s["virtual_address"] for s in sections_found]
        if vas != sorted(vas) or len(set(vas)) != len(vas):
            continue

        # Validate: all virtual addresses should be positive and reasonable
        if any(va == 0 or va > 0x80000000 for va in vas):
            continue

        # Find the offset of the first section header in the table.
        # sec_start is the header that matched CODE|EXEC|READ; find its
        # index within sections_found so we can compute the table start.
        trigger_va = struct.unpack_from("<I", data, sec_start + 12)[0]
        trigger_idx = next(
            (i for i, s in enumerate(sections_found)
             if s["virtual_address"] == trigger_va),
            0,
        )
        first_sec_offset = sec_start - trigger_idx * PE_SECTION_HEADER_SIZE

        # Search for Machine field in the ~300 bytes before the section table
        machine = 0
        search_start = max(0, first_sec_offset - 300)
        for moff in range(search_start, first_sec_offset):
            if moff + 2 > len(data):
                break
            candidate = struct.unpack_from("<H", data, moff)[0]
            if candidate in PE_VALID_MACHINES:
                # Sanity: NumberOfSections should be at moff + 2
                if moff + 4 <= len(data):
                    num_sec = struct.unpack_from("<H", data, moff + 2)[0]
                    if num_sec == len(sections_found):
                        machine = candidate
                        break

        if machine == 0:
            # Couldn't confirm Machine field — still report but lower confidence
            pass

        # Estimate image size from last section
        last = sections_found[-1]
        image_size_est = last["virtual_address"] + max(last["virtual_size"], last["raw_size"])

        # Compute the actual PE start offset within the data buffer.
        # The PE header (or where it would be) precedes the section table.
        pe_data_offset = max(first_sec_offset - 300, 0)  # conservative estimate

        # Avoid duplicates: skip if we already found a PE at a nearby offset
        actual_addr = base_addr + pe_data_offset
        if any(abs(r["offset"] - actual_addr) < 0x1000 for r in results):
            continue

        results.append({
            "offset": actual_addr,
            "machine": machine,
            "num_sections": len(sections_found),
            "sections": sections_found,
            "image_size_est": image_size_est,
            "machine_confirmed": machine != 0,
        })

        # Skip past this table to avoid re-detecting
        pos = sec_start + len(sections_found) * PE_SECTION_HEADER_SIZE

    return results


# ─── x64 Unwind Information ────────────────────────────────────────────────

# UNWIND_CODE operations
UWOP_PUSH_NONVOL = 0
UWOP_ALLOC_LARGE = 1
UWOP_ALLOC_SMALL = 2
UWOP_SET_FPREG = 3
UWOP_SAVE_NONVOL = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_SAVE_XMM128 = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRAME = 10

UNW_FLAG_CHAININFO = 0x04


def parse_pdata(pe_data: bytes, base_addr: int) -> list[tuple[int, int, int]]:
    """Parse .pdata section from a PE to extract function unwind information.

    Reads RUNTIME_FUNCTION entries and their UNWIND_INFO to compute
    the total RSP adjustment (stack frame size) for each function.

    Args:
        pe_data: Raw PE file bytes
        base_addr: Virtual address where this module is loaded

    Returns:
        Sorted list of (func_start_va, func_end_va, rsp_delta) where
        rsp_delta is the number of bytes to add to RSP to reach the
        return address (includes the return address push itself, so
        read_ptr(RSP + rsp_delta) gives the caller's return address).
        Empty list if no .pdata section found.
    """
    import struct

    # Find PE header
    if len(pe_data) < 0x40 or pe_data[:2] != b"MZ":
        return []
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    if pe_off + 4 > len(pe_data) or pe_data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return []

    # Read COFF header
    coff_off = pe_off + 4
    machine = struct.unpack_from("<H", pe_data, coff_off)[0]
    if machine != 0x8664:  # x64 only
        return []
    num_sections = struct.unpack_from("<H", pe_data, coff_off + 2)[0]
    optional_size = struct.unpack_from("<H", pe_data, coff_off + 16)[0]
    sections_off = coff_off + 20 + optional_size

    # Find .pdata section
    pdata_rva = 0
    pdata_size = 0
    pdata_raw = 0
    for i in range(num_sections):
        sec_off = sections_off + i * 40
        if sec_off + 40 > len(pe_data):
            break
        name = pe_data[sec_off:sec_off + 8].rstrip(b"\x00")
        if name == b".pdata":
            pdata_rva = struct.unpack_from("<I", pe_data, sec_off + 12)[0]
            pdata_size = struct.unpack_from("<I", pe_data, sec_off + 16)[0]
            pdata_raw = struct.unpack_from("<I", pe_data, sec_off + 20)[0]
            break

    if not pdata_raw or not pdata_size:
        return []

    # Build section map for RVA resolution
    sec_map: list[tuple[int, int, int]] = []  # (rva, raw_offset, size)
    for i in range(num_sections):
        sec_off = sections_off + i * 40
        if sec_off + 40 > len(pe_data):
            break
        s_rva = struct.unpack_from("<I", pe_data, sec_off + 12)[0]
        s_raw_size = struct.unpack_from("<I", pe_data, sec_off + 16)[0]
        s_raw_off = struct.unpack_from("<I", pe_data, sec_off + 20)[0]
        s_virt_size = struct.unpack_from("<I", pe_data, sec_off + 8)[0]
        sec_map.append((s_rva, s_raw_off, max(s_raw_size, s_virt_size)))

    def rva_to_offset(rva: int) -> int | None:
        for s_rva, s_raw, s_size in sec_map:
            if s_rva <= rva < s_rva + s_size:
                return s_raw + (rva - s_rva)
        return None

    def _compute_rsp_delta(unwind_rva: int) -> int:
        """Compute total RSP delta from UNWIND_INFO at given RVA."""
        off = rva_to_offset(unwind_rva)
        if off is None or off + 4 > len(pe_data):
            return 0

        flags = pe_data[off] >> 3
        count_of_codes = pe_data[off + 2]
        codes_off = off + 4

        delta = 0
        i = 0
        while i < count_of_codes:
            code_off = codes_off + i * 2
            if code_off + 2 > len(pe_data):
                break
            op = pe_data[code_off + 1] & 0x0F
            op_info = (pe_data[code_off + 1] >> 4) & 0x0F

            if op == UWOP_PUSH_NONVOL:
                delta += 8
                i += 1
            elif op == UWOP_ALLOC_LARGE:
                if op_info == 0:
                    if code_off + 4 > len(pe_data):
                        break
                    alloc = struct.unpack_from("<H", pe_data, code_off + 2)[0] * 8
                    delta += alloc
                    i += 2
                else:
                    if code_off + 6 > len(pe_data):
                        break
                    alloc = struct.unpack_from("<I", pe_data, code_off + 2)[0]
                    delta += alloc
                    i += 3
            elif op == UWOP_ALLOC_SMALL:
                delta += (op_info + 1) * 8
                i += 1
            elif op == UWOP_SET_FPREG:
                i += 1  # Frame pointer based -- delta already accounts for pushes
            elif op == UWOP_SAVE_NONVOL:
                i += 2
            elif op == UWOP_SAVE_NONVOL_FAR:
                i += 3
            elif op == UWOP_SAVE_XMM128:
                i += 2
            elif op == UWOP_SAVE_XMM128_FAR:
                i += 3
            elif op == UWOP_PUSH_MACHFRAME:
                delta += 48 if op_info else 40
                i += 1
            else:
                i += 1  # Unknown op, skip

        # Handle chained unwind info
        if flags & UNW_FLAG_CHAININFO:
            # After the unwind codes (aligned to even count), there's a RUNTIME_FUNCTION
            aligned_count = count_of_codes + (count_of_codes % 2)
            chain_off = codes_off + aligned_count * 2
            if chain_off + 12 <= len(pe_data):
                chain_unwind_rva = struct.unpack_from("<I", pe_data, chain_off + 8)[0]
                delta += _compute_rsp_delta(chain_unwind_rva)

        return delta

    # Parse RUNTIME_FUNCTION entries (12 bytes each)
    results: list[tuple[int, int, int]] = []
    num_entries = pdata_size // 12

    for i in range(num_entries):
        entry_off = pdata_raw + i * 12
        if entry_off + 12 > len(pe_data):
            break
        begin_rva, end_rva, unwind_rva = struct.unpack_from("<III", pe_data, entry_off)
        if begin_rva == 0 and end_rva == 0:
            continue

        rsp_delta = _compute_rsp_delta(unwind_rva)

        results.append((
            base_addr + begin_rva,
            base_addr + end_rva,
            rsp_delta,
        ))

    results.sort()
    return results


def unwind_frame(
    reader: Any,
    rip: int,
    rsp: int,
    pdata_tables: list[list[tuple[int, int, int]]],
) -> tuple[int, int] | None:
    """Unwind one stack frame using .pdata information.

    Finds the RUNTIME_FUNCTION containing rip, applies the RSP delta
    to locate the return address, and returns the new (rip, rsp).

    Args:
        reader: Minidump memory reader
        rip: Current instruction pointer
        rsp: Current stack pointer
        pdata_tables: List of parsed .pdata tables (from parse_pdata)

    Returns:
        (new_rip, new_rsp) tuple, or None if unwinding failed.
    """
    import struct

    # Binary search across all pdata tables for the function containing RIP
    for table in pdata_tables:
        lo, hi = 0, len(table) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            func_start, func_end, rsp_delta = table[mid]
            if rip < func_start:
                hi = mid - 1
            elif rip >= func_end:
                lo = mid + 1
            else:
                # Found the function
                # Return address is at RSP + rsp_delta
                ret_addr_loc = rsp + rsp_delta
                try:
                    data = reader.read(ret_addr_loc, 8)
                    if len(data) < 8:
                        return None
                    new_rip = struct.unpack("<Q", data)[0]
                    new_rsp = ret_addr_loc + 8  # Past the return address
                    if new_rip <= 0x10000 or new_rip > 0x00007FFFFFFFFFFF:
                        return None
                    return (new_rip, new_rsp)
                except Exception:
                    return None

    return None


def walk_stack_frames(
    reader: Any,
    rsp: int,
    rbp: int,
    module_ranges: list[tuple[int, int, str]],
    is_32bit: bool = False,
    exec_ranges: list[tuple[int, int]] | None = None,
    pdata_tables: list[list[tuple[int, int, int]]] | None = None,
) -> list[dict[str, Any]]:
    """Walk a thread's stack to extract return addresses and check module membership.

    Uses a hybrid approach:
      0. Unwind-based walk (x64 only) — uses .pdata/.xdata for precise unwinding
      1. Frame pointer chain (RBP/EBP) — precise but breaks with -fomit-frame-pointer
      2. Stack scan fallback — scans stack as pointer array, checks executable ranges

    Args:
        reader: Minidump memory reader
        rsp: Stack pointer (RSP or ESP)
        rbp: Frame pointer (RBP or EBP)
        module_ranges: List of (start, end, name) for known modules
        is_32bit: True for x86, False for x64
        exec_ranges: Optional list of (start, end) for executable memory regions.
                     Used in scan mode to filter false positives.
        pdata_tables: Optional list of parsed .pdata tables (from parse_pdata).
                      Enables precise x64 unwind-based stack walking.

    Returns:
        List of return address entries:
            [{"address": int, "in_module": bool, "module_name": str|None, "source": str}]
    """
    from memdump_toolkit.constants import (
        MAX_STACK_FRAMES, STACK_PTR_SIZE_32, STACK_PTR_SIZE_64,
        MAX_STACK_SCAN_SIZE,
    )
    import struct

    ptr_size = STACK_PTR_SIZE_32 if is_32bit else STACK_PTR_SIZE_64
    ptr_fmt = "<I" if is_32bit else "<Q"
    results: list[dict[str, Any]] = []
    seen_addrs: set[int] = set()

    def _addr_in_module(addr: int) -> tuple[bool, str | None]:
        for start, end, name in module_ranges:
            if start <= addr < end:
                return True, name
        return False, None

    def _addr_in_exec(addr: int) -> bool:
        if exec_ranges is None:
            return True  # If no exec info, accept all
        for start, end in exec_ranges:
            if start <= addr < end:
                return True
        return False

    def _read_ptr(addr: int) -> int | None:
        try:
            data = reader.read(addr, ptr_size)
            if len(data) < ptr_size:
                return None
            return struct.unpack(ptr_fmt, data)[0]
        except Exception:
            return None

    # ── Phase 0: Unwind-based walk (x64 only, requires .pdata) ──────────
    if not is_32bit and pdata_tables:
        try:
            first_ret_data = reader.read(rsp, 8)
            if len(first_ret_data) >= 8:
                current_rip = struct.unpack("<Q", first_ret_data)[0]
                current_rsp = rsp + 8

                for _ in range(MAX_STACK_FRAMES):
                    if current_rip <= 0x10000:
                        break

                    if current_rip not in seen_addrs:
                        seen_addrs.add(current_rip)
                        in_mod, mod_name = _addr_in_module(current_rip)
                        results.append({
                            "address": current_rip,
                            "in_module": in_mod,
                            "module_name": mod_name,
                            "source": "unwind",
                            "frame_depth": len(results),
                        })

                    frame_result = unwind_frame(reader, current_rip, current_rsp, pdata_tables)
                    if frame_result is None:
                        break
                    current_rip, current_rsp = frame_result

                if len(results) >= 3:
                    # Unwind succeeded -- skip frame pointer and scan phases
                    return results
        except Exception:
            pass  # Fall through to frame pointer walk

    # ── Phase 1: Frame pointer chain walk ────────────────────────────────
    frame_count = 0
    fp = rbp
    chain_broken = False

    if fp and fp > 0x10000:
        for _ in range(MAX_STACK_FRAMES):
            # Return address is at FP + ptr_size (EBP+4 or RBP+8)
            ret_addr = _read_ptr(fp + ptr_size)
            if ret_addr is None or ret_addr <= 0x10000:
                chain_broken = True
                break

            if ret_addr not in seen_addrs:
                seen_addrs.add(ret_addr)
                in_mod, mod_name = _addr_in_module(ret_addr)
                results.append({
                    "address": ret_addr,
                    "in_module": in_mod,
                    "module_name": mod_name,
                    "source": "frame_walk",
                    "frame_depth": frame_count,
                })
            frame_count += 1

            # Follow the chain: next FP is at [current FP]
            next_fp = _read_ptr(fp)
            if next_fp is None or next_fp <= fp or next_fp <= 0x10000:
                chain_broken = True
                break
            fp = next_fp
    else:
        chain_broken = True

    # ── Phase 2: Stack scan fallback ─────────────────────────────────────
    # Only if frame chain broke within first 3 frames (likely optimized code)
    if chain_broken and frame_count < 3 and rsp and rsp > 0x10000:
        scan_size = min(MAX_STACK_SCAN_SIZE, 0x10000)
        try:
            stack_data = reader.read(rsp, scan_size)
        except Exception:
            stack_data = b""

        for off in range(0, len(stack_data) - ptr_size + 1, ptr_size):
            candidate = struct.unpack_from(ptr_fmt, stack_data, off)[0]

            # Filter: must be a plausible code address
            if candidate <= 0x10000:
                continue
            if is_32bit and candidate > 0x80000000:
                continue
            if not is_32bit and candidate > 0x00007FFFFFFFFFFF:
                continue

            # Filter: must be in an executable region (reduces false positives)
            if not _addr_in_exec(candidate):
                continue

            if candidate in seen_addrs:
                continue
            seen_addrs.add(candidate)

            in_mod, mod_name = _addr_in_module(candidate)
            results.append({
                "address": candidate,
                "in_module": in_mod,
                "module_name": mod_name,
                "source": "stack_scan",
                "stack_offset": off,
            })

            if len(results) >= MAX_STACK_FRAMES:
                break

    return results


# ─── YARA Integration ────────────────────────────────────────────────────────

# YARA compilation cache — avoids recompiling rules for every binary.
# Key: resolved rules_dir path. Value: list of (compiled_rule, source_path).
_yara_rule_cache: dict[str, list[tuple[Any, str]]] = {}


def scan_with_yara(data: bytes, rules_dir: str | None = None) -> list[dict[str, Any]]:
    """Scan binary data with YARA rules from a directory.

    Returns list of matches: [{"rule": name, "tags": [...], "strings": [...]}]
    Silently returns [] if yara-python is not installed or no rules found.
    """
    if rules_dir is None:
        return []

    try:
        import yara
    except ImportError:
        logger.debug("yara-python not installed, skipping YARA scan")
        return []

    import os

    # Validate and resolve rules directory
    rules_dir = os.path.realpath(rules_dir)
    if not os.path.isdir(rules_dir):
        return []

    matches_out: list[dict[str, Any]] = []

    # Check compilation cache (avoids recompiling per-binary)
    if rules_dir in _yara_rule_cache:
        compiled_rules = _yara_rule_cache[rules_dir]
    else:
        rule_files = {}
        for root, _dirs, files in os.walk(rules_dir):
            for fname in files:
                if fname.endswith((".yar", ".yara")):
                    rule_files[os.path.join(root, fname)] = os.path.join(root, fname)

        if not rule_files:
            return []

        # Many community rulesets (signature-base, etc.) use external variables.
        # Provide sensible defaults so rules compile without errors.
        externals = {
            "filepath": "",
            "filename": "",
            "filetype": "",
            "extension": "",
            "owner": "",
        }

        # Compile rules individually so one broken file doesn't kill the scan.
        # Track (compiled_rule, source_path) to attribute matches to rulesets.
        compiled_rules: list[tuple[Any, str]] = []
        skipped = 0
        for fpath in rule_files.values():
            try:
                compiled_rules.append(
                    (yara.compile(filepath=fpath, externals=externals), fpath)
                )
            except yara.SyntaxError as e:
                logger.debug("YARA skip %s: %s", fpath, e)
                skipped += 1
            except yara.Error as e:
                logger.debug("YARA skip %s: %s", fpath, e)
                skipped += 1

        if skipped:
            logger.info("YARA: compiled %d rules, skipped %d broken files",
                         len(compiled_rules), skipped)
        else:
            logger.debug("YARA: compiled all %d rule files", len(compiled_rules))

        _yara_rule_cache[rules_dir] = compiled_rules

    import warnings

    def _extract_source(fpath: str, base: str) -> str:
        """Extract ruleset name and rule file from the full path.

        For ~/.memdump-toolkit/rules/signature-base/yara/foo.yar
        returns 'signature-base/yara/foo.yar'.
        For other paths, returns the filename.
        """
        rel = os.path.relpath(fpath, base)
        # rel will be e.g. "signature-base/yara/foo.yar" or just "foo.yar"
        return rel

    for rules, source_path in compiled_rules:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                matches = rules.match(data=data)
        except Exception as e:
            logger.debug("YARA match error: %s", e)
            continue

        source = _extract_source(source_path, rules_dir)
        # Ruleset name is the first path component (e.g. "signature-base")
        ruleset = source.split(os.sep)[0] if os.sep in source else ""

        for m in matches:
            # Handle both yara-python v3 (tuple) and v4 (object) string APIs
            str_entries: list[dict] = []
            if hasattr(m, "strings"):
                for s in m.strings[:10]:
                    if hasattr(s, "identifier"):
                        # v4+: StringMatch objects with .instances
                        for inst in (s.instances[:3] if hasattr(s, "instances") else []):
                            str_entries.append({
                                "offset": inst.offset,
                                "identifier": s.identifier,
                                "data": bytes(inst.matched_data[:100]).hex(),
                            })
                    else:
                        # v3: plain tuples (offset, identifier, data)
                        str_entries.append({
                            "offset": s[0], "identifier": s[1],
                            "data": s[2][:100].hex(),
                        })

            matches_out.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "meta": dict(m.meta) if hasattr(m, "meta") else {},
                "strings": str_entries,
                "source": source,
                "ruleset": ruleset,
            })

    return matches_out


# ─── Shared Helpers ────────────────────────────────────────────────────────

def severity_label(score: int) -> str:
    """Map a numeric risk score to a severity label.

    Thresholds: >=60 CRITICAL, >=30 HIGH, >=10 MEDIUM, else LOW.
    """
    from memdump_toolkit.constants import SCORE_CRITICAL, SCORE_HIGH, SCORE_MEDIUM
    if score >= SCORE_CRITICAL:
        return "CRITICAL"
    if score >= SCORE_HIGH:
        return "HIGH"
    if score >= SCORE_MEDIUM:
        return "MEDIUM"
    return "LOW"


def get_pe_identity(pe_info: dict[str, Any]) -> str:
    """Extract the best available identity string from PE info.

    Tries export_name first, then OriginalFilename, InternalName, falls back
    to 'UNKNOWN'.
    """
    identity = pe_info.get("export_name", "")
    if not identity:
        vi = pe_info.get("version_info", {})
        identity = vi.get("OriginalFilename", vi.get("InternalName", "UNKNOWN"))
    return identity


def is_trusted_path(path: str) -> bool:
    """Check whether a module path belongs to a known-trusted location."""
    from memdump_toolkit.constants import TRUSTED_PATH_FRAGMENTS
    path_lower = path.lower()
    return any(t in path_lower for t in TRUSTED_PATH_FRAGMENTS)


def get_known_bases(mf: Any) -> set[int]:
    """Extract the set of base addresses from listed modules in a minidump."""
    if mf.modules:
        return {mod.baseaddress for mod in mf.modules.modules}
    return set()


# ─── CSV Writer ──────────────────────────────────────────────────────────────

def _sanitize_csv_value(v: str) -> str:
    """Prevent CSV formula injection by escaping leading control characters."""
    if v and v[0] in ("=", "+", "-", "@"):
        return "'" + v
    return v


def write_csv(path: str, rows: list[dict], fieldnames: Any) -> None:
    """Write a list of dicts to a CSV file with the given fieldnames."""
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            sanitized = {k: _sanitize_csv_value(str(v)) for k, v in row.items()}
            writer.writerow(sanitized)
