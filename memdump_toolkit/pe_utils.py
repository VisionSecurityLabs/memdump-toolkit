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


# ─── YARA Integration ────────────────────────────────────────────────────────

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
