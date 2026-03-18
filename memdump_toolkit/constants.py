"""
Centralized domain constants, threat signatures, and detection rules.

Update these to extend detection coverage without touching analysis logic.
"""

from __future__ import annotations

from memdump_toolkit.signatures import (  # noqa: F401 — re-exported for backward compat
    KNOWN_TOOLS, CAPABILITY_STRONG, CAPABILITY_WEAK,
    PACKER_SIGNATURES, LANG_SIGNATURES,
    DOTNET_OBFUSCATORS, DOTNET_OFFENSIVE_TOOLS,
    SHELLCODE_PROLOGUES, SHELLCODE_PATTERNS, NOP_PATTERNS,
    SUSPICIOUS_IMPORTS, DOTNET_SUSPICIOUS_PINVOKE, DOTNET_SUSPICIOUS_APIS,
)

PAGE_SIZE = 0x1000

# ─── Typosquatting Detection ─────────────────────────────────────────────────

SYSTEM_DLLS: set[str] = {
    # Core
    "ntdll.dll", "kernel32.dll", "kernelbase.dll",
    # Security
    "advapi32.dll", "sechost.dll", "crypt32.dll", "bcrypt.dll",
    "bcryptprimitives.dll", "cryptbase.dll", "sspicli.dll",
    "ncrypt.dll", "cryptsp.dll",
    # CRT
    "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll", "msvcp_win.dll",
    # User / GDI
    "user32.dll", "gdi32.dll", "gdi32full.dll", "win32u.dll",
    "imm32.dll", "uxtheme.dll",
    # COM / RPC
    "rpcrt4.dll", "ole32.dll", "oleaut32.dll", "combase.dll",
    "comctl32.dll", "clbcatq.dll",
    # Shell
    "shell32.dll", "shlwapi.dll", "shcore.dll",
    # Network
    "ws2_32.dll", "winhttp.dll", "wininet.dll",
    "dnsapi.dll", "mswsock.dll", "iphlpapi.dll",
    "nsi.dll", "dhcpcsvc.dll",
    # System
    "powrprof.dll", "profapi.dll", "cfgmgr32.dll",
    "setupapi.dll", "devobj.dll", "wintrust.dll",
    "msasn1.dll", "dpapi.dll",
    "userenv.dll", "version.dll",
    # Diagnostics
    "dbghelp.dll", "dbgcore.dll",
    # Misc
    "mpr.dll", "netapi32.dll", "samcli.dll",
    "wldap32.dll", "cldapi.dll",
}

TRUSTED_PATH_FRAGMENTS: list[str] = [
    "\\windows\\system32", "\\windows\\syswow64", "\\windows\\winsxs",
    "\\windows\\microsoft.net", "\\windows\\assembly",
    "\\program files\\", "\\programdata\\microsoft\\",
]

# Normalize l/1/I and O/0 for homoglyph detection
HOMOGLYPH_MAP = str.maketrans({"1": "l", "I": "l", "0": "o"})


# Timestamp anomaly thresholds
TIMESTAMP_EPOCH_ZERO = 0
TIMESTAMP_EPOCH_MAX = 0xFFFFFFFF
TIMESTAMP_YEAR_MIN = 946684800    # 2000-01-01 UTC
TIMESTAMP_YEAR_MAX = 1893456000   # 2030-01-01 UTC (future)

# ─── Shellcode Detection ────────────────────────────────────────────────────

# Minimum region size worth scanning (skip tiny allocations)
SHELLCODE_MIN_REGION_SIZE = 64

# Code density: shellcode tends to have high byte diversity (not null-heavy)
# Regions where > this fraction of bytes are non-null are "code-like"
SHELLCODE_CODE_DENSITY_THRESHOLD = 0.65

# ─── Shared Thresholds & Limits ───────────────────────────────────────────

# Maximum scan size for string/pattern scanning (50 MB)
MAX_SCAN_SIZE = 50 * 1024 * 1024

# Risk-score severity thresholds (used by severity_label everywhere)
SCORE_CRITICAL = 60
SCORE_HIGH = 30
SCORE_MEDIUM = 10

# High-entropy section threshold (Shannon entropy, 0.0–8.0 scale)
HIGH_ENTROPY_THRESHOLD = 7.2

# Address-space heap boundaries
HEAP_THRESHOLD_X86 = 0x70000000
HEAP_THRESHOLD_X64 = 0x00007FF000000000

# Windows memory type flags
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

# Windows memory protection flags
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

# PE section characteristics flags
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_RWX = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE

# Section unpacking detection thresholds
UNPACK_VSIZE_RATIO_THRESHOLD = 10    # virtual_size / raw_size ratio that suggests unpacking
UNPACK_MIN_SECTION_SIZE = 0x2000     # ignore tiny sections (8 KB)
UNPACK_ENTROPY_THRESHOLD = 6.5       # unpacked-at-runtime code: high but not maximum entropy

# Minimum PE image size
MIN_PE_SIZE = 0x200

# Large unknown PE threshold (1 MB)
LARGE_PE_THRESHOLD = 1_000_000

# Maximum segment size for C2/shellcode scanning (50 MB)
MAX_SEGMENT_SCAN_SIZE = 50_000_000

# Suspicious entry point value
SUSPICIOUS_EP_VALUE = 0x200

# ─── Headerless PE Recovery ──────────────────────────────────────────────────

# Valid PE Machine field values
PE_MACHINE_I386 = 0x014C
PE_MACHINE_AMD64 = 0x8664
PE_VALID_MACHINES = {PE_MACHINE_I386, PE_MACHINE_AMD64}

# Section characteristics that indicate code
PE_SECTION_CODE_EXEC_READ = 0x60000020  # CODE | EXECUTE | READ

# Common PE section names (as bytes, null-padded to 8 bytes)
PE_KNOWN_SECTION_NAMES = {
    b".text\x00\x00\x00", b".rdata\x00\x00", b".data\x00\x00\x00",
    b".rsrc\x00\x00\x00", b".reloc\x00\x00", b".pdata\x00\x00",
    b".edata\x00\x00", b".idata\x00\x00", b".bss\x00\x00\x00\x00",
    b".tls\x00\x00\x00\x00", b".CRT\x00\x00\x00\x00",
}

# Section header size in PE format
PE_SECTION_HEADER_SIZE = 40

# Minimum/maximum section count for validation
PE_MIN_SECTIONS_HEADERLESS = 2
PE_MAX_SECTIONS_HEADERLESS = 96  # PE spec maximum

# ─── Stack Frame Walking ─────────────────────────────────────────────────────

# Maximum frames to walk before giving up (prevent infinite loops)
MAX_STACK_FRAMES = 64

# Pointer sizes per architecture
STACK_PTR_SIZE_32 = 4
STACK_PTR_SIZE_64 = 8

# Stack scan: maximum bytes to scan from RSP/ESP
MAX_STACK_SCAN_SIZE = 0x10000  # 64 KB

# Minimum frames outside modules to trigger escalation to CRITICAL
STACK_CRITICAL_THRESHOLD = 3
