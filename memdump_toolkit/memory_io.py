"""Memory I/O helpers for reading PE images from minidump files.

Provides page-by-page and full-read strategies for extracting PE data
from memory dumps, handling partial reads and segment boundaries gracefully.
"""

from __future__ import annotations

from typing import Any

from memdump_toolkit.constants import PAGE_SIZE
import logging

logger = logging.getLogger("memdump_toolkit")


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
