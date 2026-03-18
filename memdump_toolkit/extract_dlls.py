"""Extract all PE modules (listed + hidden) from a Windows Minidump."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from minidump.minidumpfile import MinidumpFile

from memdump_toolkit.constants import PAGE_SIZE
from memdump_toolkit.pe_utils import (
    check_pe_header, get_pe_identity, get_pe_info, logger, read_module_memory,
    read_pe_full_image, safe_filename, setup_logging, write_csv,
)


def extract_listed_modules(
    mf: Any, reader: Any, out_dir: str,
) -> tuple[list[dict], set[int]]:
    """Extract modules from the minidump module list."""
    mod_dir = os.path.join(out_dir, "modules")
    os.makedirs(mod_dir, exist_ok=True)

    if not mf.modules:
        logger.info("  No modules found in dump.")
        return [], set()

    results: list[dict] = []
    known_bases: set[int] = set()
    seen_names: dict[str, int] = {}

    for mod in mf.modules.modules:
        name = safe_filename(mod.name)
        base = mod.baseaddress
        size = mod.size
        known_bases.add(base)

        if name in seen_names:
            seen_names[name] += 1
            outname = f"{Path(name).stem}_0x{base:x}{Path(name).suffix}"
        else:
            seen_names[name] = 1
            outname = name

        outpath = os.path.join(mod_dir, outname)

        try:
            data, bytes_read = read_module_memory(reader, base, size)
            coverage = (bytes_read / size) * 100 if size > 0 else 0
            pe_info = get_pe_info(data)

            if pe_info["is_pe"]:
                with open(outpath, "wb") as f:
                    f.write(data)
                tag = "OK" if coverage > 90 else "PARTIAL"
                logger.info(f"  [{tag:7s}] {outname:55s} {size:>12,} bytes  {coverage:5.1f}%")
            else:
                with open(outpath + ".bin", "wb") as f:
                    f.write(data)
                outname += ".bin"
                logger.info(f"  [NO-PE ] {outname:55s} {size:>12,} bytes  {coverage:5.1f}%")

            hashes = pe_info.get("hashes", {})
            packed = [s["name"] for s in pe_info.get("section_entropy", []) if s.get("packed")]

            results.append({
                "name": outname, "path": mod.name,
                "base": f"0x{base:016x}", "size": size,
                "coverage": f"{coverage:.1f}%",
                "is_pe": pe_info["is_pe"],
                "is_dll": pe_info.get("is_dll", ""),
                "entry_point": f"0x{pe_info.get('entry_point', 0):x}",
                "timestamp": pe_info.get("timestamp", ""),
                "timestamp_str": pe_info.get("timestamp_str", ""),
                "num_sections": pe_info.get("num_sections", 0),
                "md5": hashes.get("md5", ""),
                "sha256": hashes.get("sha256", ""),
                "packed_sections": "|".join(packed),
            })
        except Exception as e:
            logger.info(f"  [FAIL  ] {outname:55s} {e}")
            logger.debug("Module extraction failed for %s", outname, exc_info=True)
            results.append({
                "name": outname, "path": mod.name,
                "base": f"0x{base:016x}", "size": size,
                "coverage": "0%", "is_pe": False,
                "is_dll": "", "entry_point": "", "timestamp": "",
                "timestamp_str": "", "num_sections": 0,
                "md5": "", "sha256": "", "packed_sections": "",
            })

    return results, known_bases


def extract_hidden_pes(
    mf: Any, reader: Any, known_bases: set[int], out_dir: str,
) -> list[dict]:
    """Scan memory for PE images not in the module list."""
    hidden_dir = os.path.join(out_dir, "hidden")
    os.makedirs(hidden_dir, exist_ok=True)

    results: list[dict] = []
    count = 0

    for seg in reader.memory_segments:
        base = seg.start_virtual_address
        seg_size = seg.end_virtual_address - base
        if seg_size < 0x200 or base in known_bases:
            continue

        hdr_result = check_pe_header(reader, base, seg_size)
        if not hdr_result:
            continue

        pe_off, img_size, hdr = hdr_result
        count += 1

        data = read_pe_full_image(reader, base, img_size, seg_size)
        pe_info = get_pe_info(data)
        is_dll = pe_info.get("is_dll", False)

        identity = get_pe_identity(pe_info)

        hashes = pe_info.get("hashes", {})
        packed = [s["name"] for s in pe_info.get("section_entropy", []) if s.get("packed")]

        fname = f"hidden_{count:03d}_0x{base:x}.{'dll' if is_dll else 'exe'}"
        with open(os.path.join(hidden_dir, fname), "wb") as f:
            f.write(data)

        logger.info(f"  [{count:3d}] 0x{base:016x}  {'DLL' if is_dll else 'EXE'}  {len(data):>10,} bytes  {identity}")

        results.append({
            "file": fname, "base": f"0x{base:016x}",
            "image_size": img_size, "captured_size": len(data),
            "is_dll": is_dll,
            "entry_point": f"0x{pe_info.get('entry_point', 0):x}",
            "timestamp": pe_info.get("timestamp", ""),
            "timestamp_str": pe_info.get("timestamp_str", ""),
            "num_sections": pe_info.get("num_sections", 0),
            "sections": "|".join(pe_info.get("sections", [])),
            "identity": identity,
            "export_name": pe_info.get("export_name", ""),
            "md5": hashes.get("md5", ""),
            "sha256": hashes.get("sha256", ""),
            "packed_sections": "|".join(packed),
            "headerless": False,
            "machine": "",
            "machine_confirmed": "",
        })

    # Second pass: headerless PE recovery (MZ header zeroed out)
    from memdump_toolkit.pe_utils import find_headerless_pe
    headerless_count = 0
    for seg in reader.memory_segments:
        base = seg.start_virtual_address
        seg_size = seg.end_virtual_address - base
        if seg_size < 0x200 or base in known_bases:
            continue
        # Skip segments where we already found a normal PE
        if any(r.get("base") == f"0x{base:016x}" for r in results):
            continue
        try:
            hdr_data = reader.read(base, min(seg_size, 0x2000))
        except Exception:
            continue
        # Only scan segments that DON'T start with MZ (those were already handled)
        if hdr_data[:2] == b"MZ":
            continue
        candidates = find_headerless_pe(hdr_data, base)
        for cand in candidates:
            headerless_count += 1
            count += 1
            # Read the full estimated image
            est_size = cand.get("image_size_est", seg_size)
            read_size = min(est_size, seg_size)
            try:
                data = reader.read(base, read_size)
            except Exception:
                logger.warning("Failed to read headerless PE at 0x%x, skipping", base)
                continue

            fname = f"headerless_{headerless_count:03d}_0x{base:x}.bin"
            with open(os.path.join(hidden_dir, fname), "wb") as f:
                f.write(data)

            machine_str = "x64" if cand.get("machine") == 0x8664 else "x86" if cand.get("machine") == 0x014C else "unknown"
            sec_names = [s["name"] for s in cand.get("sections", [])]
            logger.info(f"  [{count:3d}] 0x{base:016x}  HEADERLESS  {len(data):>10,} bytes  {machine_str}  sections: {', '.join(sec_names)}")

            results.append({
                "file": fname, "base": f"0x{base:016x}",
                "image_size": est_size, "captured_size": len(data),
                "is_dll": False,  # Can't determine without full PE header
                "entry_point": "",
                "timestamp": "",
                "timestamp_str": "",
                "num_sections": cand["num_sections"],
                "sections": "|".join(sec_names),
                "identity": "HEADERLESS_PE",
                "export_name": "",
                "md5": "", "sha256": "",
                "packed_sections": "",
                "headerless": True,
                "machine": machine_str,
                "machine_confirmed": cand.get("machine_confirmed", False),
            })

    if headerless_count:
        logger.info(f"\n  Headerless PE recovery found {headerless_count} additional PE(s)")

    return results


def analyze(mf: Any, reader: Any, out_dir: str) -> tuple[list[dict], list[dict]]:
    """Core extraction logic (called by orchestrator with pre-parsed dump)."""
    logger.info(f"\n{'='*80}")
    logger.info("PHASE 1: Extracting listed modules")
    logger.info(f"{'='*80}")
    mod_results, known_bases = extract_listed_modules(mf, reader, out_dir)
    logger.info(f"\nExtracted: {len(mod_results)} modules -> {out_dir}/modules/")

    if mod_results:
        csv_path = os.path.join(out_dir, "module_list.csv")
        write_csv(csv_path, mod_results, mod_results[0].keys())
        logger.info(f"Inventory: {csv_path}")

    logger.info(f"\n{'='*80}")
    logger.info("PHASE 2: Scanning for hidden PE images")
    logger.info(f"{'='*80}")
    hidden_results = extract_hidden_pes(mf, reader, known_bases, out_dir)
    logger.info(f"\nFound: {len(hidden_results)} hidden PE images -> {out_dir}/hidden/")

    if hidden_results:
        csv_path = os.path.join(out_dir, "hidden_list.csv")
        write_csv(csv_path, hidden_results, hidden_results[0].keys())
        logger.info(f"Inventory: {csv_path}")

    total = len(mod_results) + len(hidden_results)
    logger.info(f"\nTotal: {len(mod_results)} listed + {len(hidden_results)} hidden = {total} PE images")
    return mod_results, hidden_results


def run(dump_path: str, out_dir: str | None = None, verbose: bool = False) -> tuple[list[dict], list[dict]]:
    """Standalone entry point — parses dump then calls analyze()."""
    setup_logging(verbose)
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(dump_path) or ".", "output")
    os.makedirs(out_dir, exist_ok=True)

    print(f"Parsing: {dump_path}")
    mf = MinidumpFile.parse(dump_path)
    reader = mf.get_reader()
    return analyze(mf, reader, out_dir)
