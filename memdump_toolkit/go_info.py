"""Extract structured Go metadata from a binary file.

Replaces noisy regex-based string extraction with clean structural parsing:
  - Go build info via the ``\\xff Go buildinf:`` magic marker
  - Function names extracted from pclntab by module prefix
  - Capability detection from function/file name patterns
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from typing import Any

from memdump_toolkit.pe_utils import logger, setup_logging


# ─── Capability Detection Patterns ───────────────────────────────────────────

CAPABILITY_PATTERNS: dict[str, list[str]] = {
    "websocket_c2": ["websocket_client", "websocket_server", "WebSocket"],
    "tcp_c2": ["tcp_client", "tcp_server", "TcpClient", "TcpServer"],
    "named_pipe_c2": ["namedpipe_client", "namedpipe_server", "NamedPipe"],
    "port_forwarding": ["forward.go", "TcpOpenReq", "Forward"],
    "reverse_port_forwarding": ["rforward.go", "ReverseForward"],
    "pivoting": ["pivot.go", "PivotStart", "PivotStop"],
    "socks_proxy": [".Socks", "socks"],
    "icmp_tunneling": ["icmp.go", "IcmpReq"],
    "ntlm_auth": ["ntlmssp", "ntlmAuth"],
    "kerberos_auth": ["kerberos", "kerberosAuth"],
    "ldap": ["ldap_", "LDAP"],
    "smb": ["smb_", "SMB"],
    "user_impersonation": ["Impersonate", "LogonUser", "RevertToSelf"],
    "xor_encryption": ["XorStream", "XorSecret", "xor_stream"],
    "sleep_beacon": ["SleepReq", "Sleep"],
    "proxy_traversal": ["proxy_auth", "ProxyDial", "ProxyConfig"],
    "udp_tunneling": ["UdpData", "udp.go", "ForwardUdp"],
    "resilient_connection": ["resilientConn", "resilient_conn", "Reconnect"],
}

# Human-readable labels for the report
_CAPABILITY_LABELS: dict[str, str] = {
    "websocket_c2": "WebSocket C2",
    "tcp_c2": "TCP C2",
    "named_pipe_c2": "Named Pipe C2",
    "port_forwarding": "Port Forwarding",
    "reverse_port_forwarding": "Reverse Forwarding",
    "pivoting": "Pivoting",
    "socks_proxy": "SOCKS Proxy",
    "icmp_tunneling": "ICMP Tunneling",
    "ntlm_auth": "NTLM Auth",
    "kerberos_auth": "Kerberos Auth",
    "ldap": "LDAP",
    "smb": "SMB",
    "user_impersonation": "User Impersonation",
    "xor_encryption": "XOR Encryption",
    "sleep_beacon": "Sleep/Beacon",
    "proxy_traversal": "Proxy Traversal",
    "udp_tunneling": "UDP Tunneling",
    "resilient_connection": "Resilient Connection",
}


# ─── Build Info Extraction ────────────────────────────────────────────────────

def extract_go_buildinfo(data: bytes) -> dict[str, Any]:
    """Extract module path, version, and dependencies from Go buildinfo.

    Finds the ``\\xff Go buildinf:`` magic marker and parses the tab-delimited
    key/value pairs that follow (path, mod, dep lines).
    """
    info: dict[str, Any] = {
        "module_path": None,
        "go_version": None,
        "dependencies": [],
    }

    magic = b"\xff Go buildinf:"
    idx = data.find(magic)
    if idx < 0:
        logger.debug("No Go buildinfo magic found")
        return info

    # Go version appears in the first 64 bytes after the magic
    for m in re.finditer(rb"(go1\.\d+(?:\.\d+)?)", data[idx : idx + 64]):
        info["go_version"] = m.group(1).decode()
        break

    # Scan within 20 MB of the buildinfo magic for structured data
    scan_end = min(len(data), idx + 20 * 1024 * 1024)
    buildinfo_region = data[idx:scan_end]

    # Module path — first path\t line near buildinfo
    for m in re.finditer(rb"path\t([^\n]+)", buildinfo_region):
        info["module_path"] = m.group(1).decode("utf-8", errors="replace").strip()
        break

    # Dependencies — dep\t<module>\t<version>[\t<hash>]
    seen: set[str] = set()
    for m in re.finditer(rb"dep\t([^\n]+)", buildinfo_region):
        dep_line = m.group(1).decode("utf-8", errors="replace").strip()
        parts = dep_line.split("\t")
        mod = parts[0].strip()
        if mod and mod not in seen:
            seen.add(mod)
            info["dependencies"].append(mod)

    return info


# ─── Function / Symbol Extraction ────────────────────────────────────────────

def extract_go_functions(data: bytes, module_prefix: str) -> dict[str, Any]:
    """Extract function names from the binary matching the module prefix.

    Searches for the top-level package prefix (e.g. ``gamos/`` from
    ``gamos/client``) and returns source files and function names found in the
    binary, which effectively scans pclntab and rodata symbol strings.
    """
    top_pkg = module_prefix.split("/")[0].encode() + b"/"

    funcs: set[str] = set()
    # Allow word chars, slashes, dots, parens, asterisks, hyphens — covers
    # both fully-qualified function names and .go source file paths.
    pattern = re.compile(re.escape(top_pkg) + rb"[\w/.()*\-]+")
    for m in pattern.finditer(data):
        try:
            funcs.add(m.group().decode("ascii", errors="replace"))
        except Exception:
            pass

    source_files = sorted(f for f in funcs if f.endswith(".go"))
    functions = sorted(f for f in funcs if not f.endswith(".go"))

    return {"source_files": source_files, "functions": functions}


# ─── Capability Detection ─────────────────────────────────────────────────────

def detect_capabilities(source_files: list[str], functions: list[str]) -> list[str]:
    """Detect capabilities by matching patterns against source files and functions."""
    haystack = source_files + functions
    detected: list[str] = []

    for cap_key, patterns in CAPABILITY_PATTERNS.items():
        for pat in patterns:
            if any(pat in item for item in haystack):
                detected.append(cap_key)
                break

    return detected


# ─── Package Grouping ─────────────────────────────────────────────────────────

def group_functions_by_package(functions: list[str]) -> dict[str, list[str]]:
    """Group function names by their package path (everything before the last dot)."""
    groups: dict[str, list[str]] = defaultdict(list)
    for fn in functions:
        # Function format: pkg/path.FuncName or pkg/path.(*Type).Method
        dot = fn.rfind(".")
        if dot > 0:
            pkg = fn[:dot]
            # Strip method receiver suffix, e.g. "pkg.(*T)" -> "pkg"
            paren = pkg.find(".(")
            if paren > 0:
                pkg = pkg[:paren]
        else:
            pkg = fn
        groups[pkg].append(fn)
    return dict(groups)


# ─── Binary Type Detection ────────────────────────────────────────────────────

def _detect_binary_type(source_files: list[str]) -> str:
    """Infer EXE vs DLL and a hint about entry point from source files."""
    file_names = [os.path.basename(f) for f in source_files]
    if "main_dll.go" in file_names:
        return "DLL (main_dll.go)"
    if "main.go" in file_names:
        return "EXE (main.go)"
    return "Unknown"


# ─── Full Analysis ────────────────────────────────────────────────────────────

def analyze(data: bytes, filename: str = "") -> dict[str, Any]:
    """Run full Go metadata extraction on raw binary bytes.

    Returns a structured dict suitable for JSON serialisation and report
    printing.
    """
    result: dict[str, Any] = {"filename": filename}

    # 1. Build info
    buildinfo = extract_go_buildinfo(data)
    result.update(buildinfo)

    module_path: str = buildinfo.get("module_path") or ""

    # 2. Functions (only meaningful when we have a module path)
    if module_path:
        sym_info = extract_go_functions(data, module_path)
    else:
        # Fall back to scanning for any plausible Go-style path
        fallback_prefix = _infer_module_prefix(data)
        if fallback_prefix:
            logger.debug("Inferred module prefix: %s", fallback_prefix)
            sym_info = extract_go_functions(data, fallback_prefix)
            result["module_path"] = fallback_prefix
            module_path = fallback_prefix
        else:
            sym_info = {"source_files": [], "functions": []}

    result["source_files"] = sym_info["source_files"]
    result["functions"] = sym_info["functions"]

    # 3. Capabilities
    result["capabilities"] = detect_capabilities(
        sym_info["source_files"], sym_info["functions"]
    )

    # 4. Package grouping
    result["functions_by_package"] = group_functions_by_package(sym_info["functions"])

    # 5. Binary type hint
    result["binary_type"] = _detect_binary_type(sym_info["source_files"])

    return result


def _infer_module_prefix(data: bytes) -> str:
    """Best-effort inference of the custom module prefix when buildinfo is absent."""
    from memdump_toolkit.constants import MAX_SCAN_SIZE
    scan_data = data[:MAX_SCAN_SIZE]
    # Look for repeated short path-like tokens that are not stdlib/well-known
    known_prefixes = (
        b"github.com/", b"golang.org/", b"google.golang.org/",
        b"nhooyr.io/", b"go.",
    )
    candidates: dict[str, int] = defaultdict(int)
    for m in re.finditer(rb"([a-z][a-z0-9_\-]+/[a-z][a-z0-9_\-]+)", scan_data):
        token = m.group()
        if not any(token.startswith(p) for p in known_prefixes):
            try:
                candidates[token.decode("ascii")] += 1
            except Exception:
                pass
    if not candidates:
        return ""
    # Return the most-frequent short custom path
    return max(candidates, key=lambda k: candidates[k])


# ─── Report Printing ──────────────────────────────────────────────────────────

def _print_report(result: dict[str, Any]) -> None:
    """Print a clean human-readable report to stdout."""
    filename = result.get("filename", "")
    bar = "\u2550" * 70

    print(f"\n{bar}")
    print(f"GO BINARY ANALYSIS: {filename}")
    print(f"{bar}")

    module_path = result.get("module_path") or "(not found)"
    go_version = result.get("go_version") or "(not found)"
    binary_type = result.get("binary_type", "")

    print(f"  Module:       {module_path}")
    print(f"  Go Version:   {go_version}")
    if binary_type:
        print(f"  Type:         {binary_type}")

    deps = result.get("dependencies", [])
    print(f"\n  Dependencies ({len(deps)}):")
    for dep in deps:
        print(f"    {dep}")

    caps = result.get("capabilities", [])
    if caps:
        print(f"\n  Capabilities:")
        labels = [_CAPABILITY_LABELS.get(c, c) for c in caps]
        # Print in rows of 3
        row_size = 3
        for i in range(0, len(labels), row_size):
            row = labels[i : i + row_size]
            print("    " + "".join(f"\u25cf {lbl:<22}" for lbl in row))
    else:
        print("\n  Capabilities: (none detected)")

    src_files = result.get("source_files", [])
    print(f"\n  Source Files ({len(src_files)}):")
    for sf in src_files:
        print(f"    {sf}")

    by_pkg = result.get("functions_by_package", {})
    if by_pkg:
        print(f"\n  Functions by Package:")
        for pkg, fns in sorted(by_pkg.items()):
            print(f"    {pkg} ({len(fns)} function{'s' if len(fns) != 1 else ''})")

    print()


# ─── Entry Point ─────────────────────────────────────────────────────────────

def run(
    filepath: str,
    out_dir: str | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """Standalone entry point for go-info analysis.

    Args:
        filepath: Path to a Go binary file (EXE or DLL).
        out_dir:  If provided, write ``go_info.json`` to this directory.
        verbose:  Enable debug logging.

    Returns:
        The analysis result dict.
    """
    setup_logging(verbose)

    if not os.path.isfile(filepath):
        logger.error("File not found: %s", filepath)
        return {}

    filename = os.path.basename(filepath)
    logger.debug("Reading %s", filepath)

    with open(filepath, "rb") as fh:
        data = fh.read()

    result = analyze(data, filename=filename)
    _print_report(result)

    if out_dir is not None:
        os.makedirs(out_dir, exist_ok=True)
        report_path = os.path.join(out_dir, "go_info.json")
        # functions_by_package has list values — fine for JSON
        with open(report_path, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        print(f"JSON report: {report_path}")

    return result
