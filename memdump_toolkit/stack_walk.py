"""SEH/unwind and heuristic stack walking for x64 and x86 binaries.

Provides three stack-walking strategies:
  - Unwind-based (.pdata/.xdata) for x64 with precise RSP recovery
  - Frame-pointer chain walk (RBP/EBP)
  - Stack-scan fallback for optimized/frameless code

Also includes .pdata parsing to extract per-function unwind metadata.
"""

from __future__ import annotations

import struct
from typing import Any

import logging

logger = logging.getLogger("memdump_toolkit")

# ─── UNWIND_CODE operations ─────────────────────────────────────────────────

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


# ─── .pdata helpers ──────────────────────────────────────────────────────────

def _rva_to_offset(rva: int, sec_map: list[tuple[int, int, int]]) -> int | None:
    """Translate an RVA to a raw file offset using the section map.

    Args:
        rva: Relative virtual address to resolve.
        sec_map: List of (section_rva, raw_offset, size) tuples.

    Returns:
        Raw file offset, or None if the RVA falls outside all sections.
    """
    for s_rva, s_raw, s_size in sec_map:
        if s_rva <= rva < s_rva + s_size:
            return s_raw + (rva - s_rva)
    return None


def _compute_rsp_delta(
    pe_data: bytes,
    unwind_rva: int,
    sec_map: list[tuple[int, int, int]],
) -> int:
    """Compute total RSP delta from UNWIND_INFO at the given RVA.

    Walks the UNWIND_CODE array, summing stack adjustments (pushes,
    allocations, machine frames).  Follows chained unwind info when
    UNW_FLAG_CHAININFO is set.

    Args:
        pe_data: Raw PE file bytes.
        unwind_rva: RVA pointing to the UNWIND_INFO structure.
        sec_map: Section map for RVA-to-offset translation.

    Returns:
        Total bytes to add to RSP to reach the return address slot.
    """
    off = _rva_to_offset(unwind_rva, sec_map)
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
            i += 1
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
        aligned_count = count_of_codes + (count_of_codes % 2)
        chain_off = codes_off + aligned_count * 2
        if chain_off + 12 <= len(pe_data):
            chain_unwind_rva = struct.unpack_from("<I", pe_data, chain_off + 8)[0]
            delta += _compute_rsp_delta(pe_data, chain_unwind_rva, sec_map)

    return delta


# ─── .pdata parsing ──────────────────────────────────────────────────────────

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
    sec_map: list[tuple[int, int, int]] = []
    for i in range(num_sections):
        sec_off = sections_off + i * 40
        if sec_off + 40 > len(pe_data):
            break
        s_rva = struct.unpack_from("<I", pe_data, sec_off + 12)[0]
        s_raw_size = struct.unpack_from("<I", pe_data, sec_off + 16)[0]
        s_raw_off = struct.unpack_from("<I", pe_data, sec_off + 20)[0]
        s_virt_size = struct.unpack_from("<I", pe_data, sec_off + 8)[0]
        sec_map.append((s_rva, s_raw_off, max(s_raw_size, s_virt_size)))

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

        rsp_delta = _compute_rsp_delta(pe_data, unwind_rva, sec_map)

        results.append((
            base_addr + begin_rva,
            base_addr + end_rva,
            rsp_delta,
        ))

    results.sort()
    return results


# ─── Frame unwinding ─────────────────────────────────────────────────────────

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


# ─── Stack walk helpers (promoted from closures) ─────────────────────────────

def _addr_in_module(
    addr: int,
    module_ranges: list[tuple[int, int, str]],
) -> tuple[bool, str | None]:
    """Check whether *addr* falls inside any known module range."""
    for start, end, name in module_ranges:
        if start <= addr < end:
            return True, name
    return False, None


def _addr_in_exec(
    addr: int,
    exec_ranges: list[tuple[int, int]] | None,
) -> bool:
    """Check whether *addr* falls inside an executable memory region."""
    if exec_ranges is None:
        return True  # If no exec info, accept all
    for start, end in exec_ranges:
        if start <= addr < end:
            return True
    return False


def _read_ptr(reader: Any, addr: int, ptr_size: int, ptr_fmt: str) -> int | None:
    """Read a single pointer-sized value from *addr*."""
    try:
        data = reader.read(addr, ptr_size)
        if len(data) < ptr_size:
            return None
        return struct.unpack(ptr_fmt, data)[0]
    except Exception:
        return None


# ─── Phase functions ─────────────────────────────────────────────────────────

def _walk_unwind(
    reader: Any,
    rsp: int,
    pdata_tables: list[list[tuple[int, int, int]]],
    module_ranges: list[tuple[int, int, str]],
    seen_addrs: set[int],
    ptr_fmt: str,
) -> list[dict[str, Any]]:
    """Phase 0: Unwind-based walk using .pdata (x64 only).

    Reads the initial return address from the top of the stack, then
    iteratively unwinds using .pdata tables until the chain breaks or
    the frame limit is reached.

    Returns:
        List of frame entries found via unwinding.
    """
    from memdump_toolkit.constants import MAX_STACK_FRAMES

    results: list[dict[str, Any]] = []
    try:
        first_ret_data = reader.read(rsp, 8)
        if len(first_ret_data) < 8:
            return results
        current_rip = struct.unpack("<Q", first_ret_data)[0]
        current_rsp = rsp + 8
    except Exception:
        return results

    for _ in range(MAX_STACK_FRAMES):
        if current_rip <= 0x10000:
            break

        if current_rip not in seen_addrs:
            seen_addrs.add(current_rip)
            in_mod, mod_name = _addr_in_module(current_rip, module_ranges)
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

    return results


def _walk_frame_pointer(
    reader: Any,
    fp: int,
    ptr_size: int,
    ptr_fmt: str,
    module_ranges: list[tuple[int, int, str]],
    seen_addrs: set[int],
) -> tuple[list[dict[str, Any]], int, bool]:
    """Phase 1: Frame pointer chain walk.

    Follows the classic EBP/RBP chain where each frame pointer points
    to the previous frame pointer, and the return address sits at
    FP + ptr_size.

    Returns:
        Tuple of (frame_entries, frame_count, chain_broken).
    """
    from memdump_toolkit.constants import MAX_STACK_FRAMES

    results: list[dict[str, Any]] = []
    frame_count = 0
    chain_broken = False

    if not fp or fp <= 0x10000:
        return results, 0, True

    for _ in range(MAX_STACK_FRAMES):
        ret_addr = _read_ptr(reader, fp + ptr_size, ptr_size, ptr_fmt)
        if ret_addr is None or ret_addr <= 0x10000:
            chain_broken = True
            break

        if ret_addr not in seen_addrs:
            seen_addrs.add(ret_addr)
            in_mod, mod_name = _addr_in_module(ret_addr, module_ranges)
            results.append({
                "address": ret_addr,
                "in_module": in_mod,
                "module_name": mod_name,
                "source": "frame_walk",
                "frame_depth": frame_count,
            })
        frame_count += 1

        next_fp = _read_ptr(reader, fp, ptr_size, ptr_fmt)
        if next_fp is None or next_fp <= fp or next_fp <= 0x10000:
            chain_broken = True
            break
        fp = next_fp

    return results, frame_count, chain_broken


def _walk_stack_scan(
    reader: Any,
    rsp: int,
    ptr_size: int,
    ptr_fmt: str,
    module_ranges: list[tuple[int, int, str]],
    exec_ranges: list[tuple[int, int]] | None,
    seen_addrs: set[int],
    max_frames: int,
) -> list[dict[str, Any]]:
    """Phase 2: Stack scan fallback.

    Reads raw stack memory and treats every pointer-aligned value as
    a candidate return address, filtering by executable-region membership.

    Args:
        max_frames: Stop after collecting this many total frames.

    Returns:
        List of candidate return-address entries.
    """
    from memdump_toolkit.constants import MAX_STACK_SCAN_SIZE

    is_32bit = (ptr_size == 4)
    results: list[dict[str, Any]] = []

    scan_size = min(MAX_STACK_SCAN_SIZE, 0x10000)
    try:
        stack_data = reader.read(rsp, scan_size)
    except Exception:
        stack_data = b""

    for off in range(0, len(stack_data) - ptr_size + 1, ptr_size):
        candidate = struct.unpack_from(ptr_fmt, stack_data, off)[0]

        if candidate <= 0x10000:
            continue
        if is_32bit and candidate > 0x80000000:
            continue
        if not is_32bit and candidate > 0x00007FFFFFFFFFFF:
            continue

        if not _addr_in_exec(candidate, exec_ranges):
            continue

        if candidate in seen_addrs:
            continue
        seen_addrs.add(candidate)

        in_mod, mod_name = _addr_in_module(candidate, module_ranges)
        results.append({
            "address": candidate,
            "in_module": in_mod,
            "module_name": mod_name,
            "source": "stack_scan",
            "stack_offset": off,
        })

        if len(results) >= max_frames:
            break

    return results


# ─── Public orchestrator ─────────────────────────────────────────────────────

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
      0. Unwind-based walk (x64 only) -- uses .pdata/.xdata for precise unwinding
      1. Frame pointer chain (RBP/EBP) -- precise but breaks with -fomit-frame-pointer
      2. Stack scan fallback -- scans stack as pointer array, checks executable ranges

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
    )

    ptr_size = STACK_PTR_SIZE_32 if is_32bit else STACK_PTR_SIZE_64
    ptr_fmt = "<I" if is_32bit else "<Q"
    seen_addrs: set[int] = set()

    # Phase 0: Unwind-based walk (x64 only, requires .pdata)
    if not is_32bit and pdata_tables:
        results = _walk_unwind(reader, rsp, pdata_tables, module_ranges, seen_addrs, ptr_fmt)
        if len(results) >= 3:
            return results
    else:
        results = []

    # Phase 1: Frame pointer chain walk
    fp_results, frame_count, chain_broken = _walk_frame_pointer(
        reader, rbp, ptr_size, ptr_fmt, module_ranges, seen_addrs,
    )
    results.extend(fp_results)

    # Phase 2: Stack scan fallback (only if chain broke early)
    if chain_broken and frame_count < 3 and rsp and rsp > 0x10000:
        scan_results = _walk_stack_scan(
            reader, rsp, ptr_size, ptr_fmt,
            module_ranges, exec_ranges, seen_addrs, MAX_STACK_FRAMES,
        )
        results.extend(scan_results)

    return results
