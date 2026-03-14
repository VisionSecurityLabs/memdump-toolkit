"""
Centralized domain constants, threat signatures, and detection rules.

Update these to extend detection coverage without touching analysis logic.
"""

from __future__ import annotations

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


# ─── Suspicious PE Imports ───────────────────────────────────────────────────

SUSPICIOUS_IMPORTS: dict[str, set[str]] = {
    "process_injection": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtQueueApcThread", "NtWriteVirtualMemory", "RtlCreateUserThread",
        "NtCreateThreadEx", "NtMapViewOfSection", "NtUnmapViewOfSection",
    },
    "code_loading": {
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "LdrLoadDll", "GetProcAddress",
    },
    "memory_manipulation": {
        "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    },
    "credential_access": {
        "OpenProcess", "MiniDumpWriteDump", "LsaLogonUser",
        "CredEnumerateA", "CredEnumerateW",
    },
}


# ─── Known Go Offensive Tools ────────────────────────────────────────────────

KNOWN_TOOLS: dict[str, list[bytes]] = {
    "chisel": [b"github.com/jpillora/chisel", b"chisel/client", b"chisel/server"],
    "ligolo-ng": [b"github.com/nicocha30/ligolo", b"ligolo-ng"],
    "ligolo": [b"github.com/sysdream/ligolo"],
    "sliver": [
        b"github.com/BishopFox/sliver", b"sliverpb",
        # Protobuf field names survive garble obfuscation
        b"BeaconJitter", b"GetBeaconJitter", b"ReconfigureReq",
    ],
    "merlin": [b"github.com/Ne0nd0g/merlin"],
    "gsocket": [b"github.com/nicknisi/gsocket"],
    "frp": [b"github.com/fatedier/frp"],
    "gost": [b"github.com/ginuerzh/gost"],
    "rsockstun": [b"github.com/llkat/rsockstun"],
    "revsocks": [b"github.com/kost/revsocks"],
    "venom": [b"github.com/Dliv3/Venom"],
    "stowaway": [b"github.com/ph4ntonn/Stowaway"],
    "iox": [b"github.com/EddieIvan01/iox"],
    "rakshasa": [b"github.com/Mob2003/rakshasa"],
    "pspy": [b"github.com/DominicBreuker/pspy"],
    "garble": [b"mvdan.cc/garble"],
    "gobuster": [b"github.com/OJ/gobuster"],
    "ffuf": [b"github.com/ffuf/ffuf"],
    "nuclei": [b"github.com/projectdiscovery/nuclei"],
    "naabu": [b"github.com/projectdiscovery/naabu"],
    "subfinder": [b"github.com/projectdiscovery/subfinder"],
    "httpx": [b"github.com/projectdiscovery/httpx"],
}


# ─── Capability Detection (Two-Tier) ────────────────────────────────────────

# Tier 1: High-confidence — single match in raw bytes is sufficient
CAPABILITY_STRONG: dict[str, list[bytes]] = {
    "socks_proxy": [b"socks5h://", b"socks4://", b"socksAuth", b"SOCKS5Connect"],
    "credential_theft": [b"mimikatz", b"sekurlsa", b"logonPasswords"],
    "encryption": [b"chacha20", b"poly1305", b"hkdf"],
    "c2_websocket": [b"nhooyr.io/websocket", b"gorilla/websocket"],
    "multiplexing": [b"yamux", b"hashicorp/yamux"],
    "kerberos": [b"sspi/kerberos", b"KerberosSSP"],
    "ntlm": [b"sspi/ntlm", b"NTLMSSP"],
    "smb": [b"SMBSession", b"buildSMB", b"parseSMB"],
    "ldap": [b"parseLDAP", b"ldap.Conn"],
    "icmp": [b"IcmpReq", b"icmp.Message"],
    "pivot": [b"PivotStart", b"PivotStop"],
}

# Tier 2: Generic — require 2+ matches within extracted strings
CAPABILITY_WEAK: dict[str, list[bytes]] = {
    "reverse_shell": [b"reverse_shell", b"cmd.exe", b"/bin/sh", b"/bin/bash"],
    "port_forwarding": [b"portfwd", b"portforward", b"tunnel"],
    "persistence": [b"RegCreateKeyEx", b"schtasks", b"CreateService"],
    "c2_http": [b"beacon", b"callback", b"checkin"],
    "c2_dns": [b"dnscat", b"dns.Msg", b"dnsTunnel"],
    "named_pipes": [b"\\\\.\\pipe\\"],
    "lateral_movement": [b"psexec", b"winrm", b"WMIExec"],
}


# ─── .NET Suspicious Patterns ──────────────────────────────────────────────

# P/Invoke targets that indicate offensive capability
DOTNET_SUSPICIOUS_PINVOKE: dict[str, set[str]] = {
    "process_injection": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtWriteVirtualMemory", "RtlCreateUserThread", "NtCreateThreadEx",
        "QueueUserAPC", "NtQueueApcThread",
    },
    "memory_manipulation": {
        "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    },
    "code_loading": {
        "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
        "GetProcAddress", "LdrLoadDll",
    },
    "credential_access": {
        "OpenProcess", "MiniDumpWriteDump", "LsaLogonUser",
        "CredEnumerate", "OpenProcessToken", "DuplicateTokenEx",
    },
    "evasion": {
        "NtSetInformationThread", "CheckRemoteDebuggerPresent",
        "IsDebuggerPresent", "AmsiScanBuffer", "EtwEventWrite",
    },
}

# Suspicious .NET API usage patterns (type/method names in metadata or strings)
DOTNET_SUSPICIOUS_APIS: dict[str, list[str]] = {
    "reflective_loading": [
        "Assembly.Load", "Assembly.LoadFrom", "Assembly.LoadFile",
        "Assembly.ReflectionOnlyLoad", "AppDomain.Load",
    ],
    "dynamic_code": [
        "Reflection.Emit", "DynamicMethod", "TypeBuilder",
        "MethodBuilder", "ILGenerator", "CompileAssemblyFromSource",
    ],
    "process_execution": [
        "Process.Start", "ProcessStartInfo", "WmiObject",
        "ManagementClass", "Win32_Process",
    ],
    "network_comms": [
        "WebClient", "HttpClient", "WebRequest", "HttpWebRequest",
        "TcpClient", "TcpListener", "Socket", "UdpClient",
    ],
    "memory_access": [
        "Marshal.Copy", "Marshal.AllocHGlobal", "Marshal.PtrToStructure",
        "Marshal.ReadByte", "Marshal.WriteByte", "GCHandle",
        "Marshal.GetDelegateForFunctionPointer",
    ],
    "crypto": [
        "AesManaged", "AesCryptoServiceProvider", "RijndaelManaged",
        "RSACryptoServiceProvider", "DESCryptoServiceProvider",
        "TripleDES", "RC2CryptoServiceProvider",
    ],
    "persistence": [
        "RegistryKey", "Registry.SetValue", "Registry.CurrentUser",
        "TaskScheduler", "ServiceInstaller", "ServiceBase",
    ],
    "anti_analysis": [
        "Debugger.IsAttached", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "Environment.StackTrace",
    ],
}

# Known .NET obfuscator/packer signatures
DOTNET_OBFUSCATORS: dict[str, list[bytes]] = {
    "ConfuserEx": [b"ConfuserEx", b"Confuser.Core", b"Confuser.Runtime"],
    "NET_Reactor": [b".NET Reactor", b"ReactorHelper", b"NETReactor"],
    "SmartAssembly": [b"SmartAssembly", b"{SmartAssembly}", b"PoweredByAttribute"],
    "Dotfuscator": [b"Dotfuscator", b"PreEmptive"],
    "Babel_NET": [b"Babel.Net", b"babelfor.net"],
    "Eazfuscator": [b"Eazfuscator.NET", b"\xEF\xBB\xBFEaz"],
    "Crypto_Obfuscator": [b"CryptoObfuscator", b"Crypto Obfuscator"],
    "Agile_NET": [b"Agile.NET", b"CliSecure"],
    "ILProtector": [b"ILProtector", b"ILProt"],
    "De4dot_marker": [b"de4dot", b"Deobfuscated"],
}

# Known .NET offensive tools / frameworks
DOTNET_OFFENSIVE_TOOLS: dict[str, list[bytes]] = {
    "Cobalt_Strike_BOF_NET": [b"BOF.NET", b"BeaconObject"],
    "SharpHound": [b"SharpHound", b"BloodHound", b"Sharphound.Client"],
    "Rubeus": [b"Rubeus", b"Roast", b"asktgt", b"asktgs"],
    "Seatbelt": [b"Seatbelt", b"GhostPack"],
    "SharpUp": [b"SharpUp", b"PrivescCheck"],
    "Certify": [b"Certify", b"ForgeCert"],
    "SharpDPAPI": [b"SharpDPAPI", b"SharpChrome"],
    "SharpView": [b"SharpView", b"PowerView"],
    "SharpWMI": [b"SharpWMI"],
    "SafetyKatz": [b"SafetyKatz", b"sekurlsa"],
    "SharpSecDump": [b"SharpSecDump"],
    "Covenant": [b"Covenant", b"GruntStager", b"GruntHTTP"],
    "SharpSploit": [b"SharpSploit"],
    "SharpC2": [b"SharpC2", b"DroneModule"],
    "SilverC2": [b"SilverC2"],
    "PoshC2": [b"PoshC2", b"poshc2"],
    "Invoke_Assembly": [b"InvokeAssembly", b"ExecuteAssembly"],
}


# ─── Universal Binary Analysis (Language-Agnostic) ──────────────────────────

# Packer/crypter artifact signatures (section names and header strings)
# In memory dumps, binaries are UNPACKED — we detect leftover artifacts.
PACKER_SIGNATURES: dict[str, list[bytes]] = {
    "UPX": [b"UPX0", b"UPX1", b"UPX!", b"UPX2"],
    "Themida": [b"Themida", b".themida", b"Oreans"],
    "VMProtect": [b".vmp0", b".vmp1", b"VMProtect"],
    "ASPack": [b".aspack", b".adata", b"ASPack"],
    "MPRESS": [b".MPRESS1", b".MPRESS2"],
    "Enigma": [b".enigma1", b".enigma2", b"Enigma protector"],
    "PECompact": [b"PECompact2", b"PEC2"],
    "Armadillo": [b"Armadillo", b".text1\x00"],
    "Obsidium": [b"Obsidium", b".obsidium"],
    "NSPack": [b".nsp0", b".nsp1", b"nsPack"],
}

# Language identification signatures
LANG_SIGNATURES: dict[str, list[bytes]] = {
    "rust": [
        b"panicked at", b"rust_begin_unwind", b"/rustc/",
        b".cargo/registry", b"core::panicking", b"core::fmt::write",
        b"alloc::raw_vec", b"std::rt::lang_start",
    ],
    "delphi": [
        b"TObject\x00", b"Borland C++ -", b"Embarcadero",
        b"TForm\x00", b"System.SysUtils", b"Classes.TComponent",
    ],
    "nim": [
        b"@nimMain", b"stdlib_system", b"Nim/lib/",
        b"nimbase.h", b"NimMainModule", b"NimMainInner",
    ],
}
# Go and .NET are detected via structural checks (score-based / CLR header),
# not string signatures. These cover languages without structural markers.

# Timestamp anomaly thresholds
TIMESTAMP_EPOCH_ZERO = 0
TIMESTAMP_EPOCH_MAX = 0xFFFFFFFF
TIMESTAMP_YEAR_MIN = 946684800    # 2000-01-01 UTC
TIMESTAMP_YEAR_MAX = 1893456000   # 2030-01-01 UTC (future)

# ─── Shellcode Detection ────────────────────────────────────────────────────

# Known shellcode prologues (first bytes of common payloads)
SHELLCODE_PROLOGUES: dict[str, bytes] = {
    # Cobalt Strike beacon (x64): cld; and rsp, -10h; call $+5
    "CobaltStrike_x64":      b"\xfc\x48\x83\xe4\xf0",
    # Cobalt Strike beacon (x86): cld; call $+5
    "CobaltStrike_x86":      b"\xfc\xe8",
    # Metasploit reverse_tcp (x64): cld; and rsp, -10h; mov r14, ...
    "Metasploit_x64":        b"\xfc\x48\x83\xe4\xf0\xe8",
    # Metasploit reverse_tcp (x86): cld; call dword [ebp+...]
    "Metasploit_x86":        b"\xfc\xe8\x82\x00\x00\x00",
    # Generic x64 sub rsp, N prologue (common in custom shellcode)
    "Generic_x64_sub_rsp":   b"\x48\x83\xec",
    # msfvenom shikata_ga_nai decoder stub
    "Shikata_ga_nai":        b"\xd9\x74\x24\xf4",
}

# Byte patterns to search within RWX regions (not just at offset 0)
SHELLCODE_PATTERNS: dict[str, tuple[bytes, str]] = {
    # (pattern, description)
    # PEB access (x64): mov rax, gs:[0x60]
    "PEB_access_x64":   (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "GS:[0x60] PEB access (x64)"),
    # PEB access (x86): mov eax, fs:[0x30]
    "PEB_access_x86":   (b"\x64\xa1\x30\x00\x00\x00", "FS:[0x30] PEB access (x86)"),
    # PEB_LDR_DATA access (x64): mov rax, [rax+0x18]
    "PEB_LDR_x64":      (b"\x48\x8b\x40\x18", "PEB->Ldr (x64)"),
    # Hash-based API resolution: ror edi, 0xD (common in shellcode)
    "API_hash_ror13":   (b"\xc1\xcf\x0d", "ROR EDI,0xD API hashing"),
    # NtAllocateVirtualMemory syscall stub pattern
    "Syscall_stub":     (b"\x0f\x05\xc3", "syscall; ret (direct syscall)"),
    # VirtualAlloc / VirtualProtect call setup (common in loaders)
    "WinExec_hash":     (b"\x68\x72\xfe\xb3\x16", "WinExec hash push (CRC32)"),
}

# NOP sled variants (sliding window detection)
NOP_PATTERNS: list[bytes] = [
    b"\x90" * 16,               # classic NOP sled
    b"\x0f\x1f\x00" * 5,       # multi-byte NOP (3-byte)
    b"\x0f\x1f\x40\x00" * 4,   # multi-byte NOP (4-byte)
    b"\x66\x90" * 8,            # 2-byte NOP (xchg ax,ax)
]

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
