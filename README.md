# memdump-toolkit

Forensic analysis toolkit for Windows process memory dumps. Extracts every DLL, scores them for malicious indicators regardless of language (Go, .NET, Rust, Delphi, Nim, native), and produces SIEM-ready IOCs.

## Quick Start

```bash
# Install
git clone <repo> && cd MemDump
uv sync
```

**Step 1 — Run the full pipeline on the dump:**

```bash
uv run memdump-toolkit full dumps/process.dmp -o results/
```

This produces `results/report.html` — an interactive report with injection findings,
binary risk scores, C2 indicators, MITRE ATT&CK mapping, and recommended actions.

**Step 2 — Deep-dive the most suspicious binary with YARA:**

Open `report.html`, find the highest-risk binary in the Executive Summary, then:

```bash
uv run memdump-toolkit inspect results/hidden/hidden_001_0x....dll --yara
```

This generates a focused per-binary report (`results/hidden/output/report_hidden_001_....html`)
with full Go/dotnet/config analysis, capabilities, dependencies, and YARA matches.

## What It Does

The `full` command runs a 5-step pipeline on any Windows minidump:

```
Step 1: Extract    → Recovers all DLLs (listed + hidden PEs from raw memory)
Step 2: Injection  → Flags 9 injection tactics (typosquatting, RWX, stack walking, ...)
Step 3: Analyze    → Scores EVERY binary for malicious indicators (language-agnostic)
Step 4: C2 Hunt    → Scans ALL process memory for live C2 URLs, keys, certs, pipes
Step 5: Report     → Triage summary + IOC export (cross-references all findings)
```

**Step 3 is the core** — it runs universal checks on all extracted binaries:

| Check | What It Catches |
|-------|----------------|
| Language detection | Go, .NET, Rust, Delphi, Nim (auto-dispatches to deep analyzers) |
| Packer artifacts | UPX, Themida, VMProtect, ASPack, MPRESS, Enigma, ... |
| Suspicious imports | Process injection, credential access, memory manipulation APIs |
| Section anomalies | RWX sections, unusual names, zero-size executable, runtime unpacking |
| YARA rule matching | Cobalt Strike, Metasploit, custom signatures (via --yara or --yara-rules) |
| Timestamp anomalies | Epoch zero, future dates, pre-2000 |
| Config extraction | Embedded IPs, URLs, named pipes, crypto keys, C2 parameters |

Binaries are scored 0-100 and categorized: **CRITICAL** (60+), **HIGH** (30+), **MEDIUM** (10+).

### Three-Tier Filtering (Fast on Large Dumps)

| Tier | Applied To | Checks | Why |
|------|-----------|--------|-----|
| Skip | Resource-only DLLs (.mui, .rll) | None | No code, no threat |
| Lightweight | Trusted system DLLs (system32, etc.) | Timestamp + packer + language ID only | Fast, low noise |
| Full | Hidden + untrusted binaries | All checks + language dispatch + config | Where threats live |

On a 217-module SQL Server dump: 58 skipped, 142 lightweight, 17 full → **completes in ~25 seconds**.

Step 3 (binary analysis) runs in parallel across up to 4 CPU cores. YARA rules compile once per worker process and are cached for all subsequent binaries. Falls back to sequential automatically on single-core systems.

## Installation

```bash
# Clone and install
git clone <repo> && cd MemDump
uv sync

# With YARA scanning
uv sync --extra yara

# With .NET metadata parsing
uv sync --extra dotnet

# With capstone disassembly (shellcode validation)
uv sync --extra capstone

# Everything
uv sync --all-extras
```

Requires [uv](https://docs.astral.sh/uv/). Python 3.10 is auto-installed. Core dependency: `minidump`. Optional: `yara-python`, `dnfile`, `capstone`.

## CLI Commands

### Full Pipeline (recommended)

```bash
memdump-toolkit full dump.dmp -o ./results
memdump-toolkit full dump.dmp -o ./results --yara              # use community rules
memdump-toolkit full dump.dmp -o ./results --yara-rules ./rules/ # explicit path
memdump-toolkit full dump.dmp -o ./results --update-yara --yara  # update then scan
memdump-toolkit full dump.dmp -o ./results -v                    # verbose/debug
```

### Individual Commands

```bash
# Universal binary analysis (extract + score all DLLs)
memdump-toolkit binary-scan dump.dmp -o ./results

# Extract PE modules only
memdump-toolkit extract dump.dmp -o ./modules

# Injection detection only
memdump-toolkit detect dump.dmp -o ./injection

# Go implant scan only
memdump-toolkit go-scan dump.dmp -o ./go

# Structural Go binary analysis (buildinfo + pclntab)
memdump-toolkit go-info suspicious.dll -o ./go

# .NET assembly scan only
memdump-toolkit dotnet-scan dump.dmp -o ./dotnet

# Inspect any binary (auto-detects language, dispatches to right analyzer)
memdump-toolkit inspect suspicious.dll -o ./inspect
memdump-toolkit inspect suspicious.dll --yara-rules ./rules/

# Hunt for C2 indicators in raw process memory
memdump-toolkit c2-hunt dump.dmp -o ./c2

# Config extraction (single binary or dump)
memdump-toolkit config malware.dll -o ./config
memdump-toolkit config dump.dmp --dump -o ./config

# Regenerate HTML report from existing results
memdump-toolkit report ./results

# Fetch community YARA rulesets
memdump-toolkit fetch-rules                     # download or update all 6 rulesets
memdump-toolkit fetch-rules -r signature-base   # just one
memdump-toolkit fetch-rules --list              # show installed
```

## Output Files

| File | What's In It |
|------|-------------|
| **`triage_summary.json`** | Prioritized CRITICAL/HIGH findings with statistics |
| **`suspicious_binaries.csv`** | Every scored binary: file, language, risk, factors, hashes |
| **`binary_analysis.json`** | Full analysis per binary (universal + language-specific) |
| **`iocs.csv`** | Flat IOC table (IP, URL, hash, pipe, tool) for SIEM ingestion |
| **`executive_summary.json`** | Plain-English verdicts, MITRE ATT&CK mapping, recommended actions |
| **`report.html`** | Interactive HTML report — dark theme, sortable tables, ATT&CK mapping (open in browser) |
| `full_report.txt` | Human-readable report with executive summary and execution timeline |
| `injection_report.json` | 9-check injection analysis |
| `module_list.csv` | Listed module inventory (address, size, hashes, entropy) |
| `hidden_list.csv` | Hidden PE inventory |
| `modules/` | Extracted listed PE modules |
| `hidden/` | Extracted hidden PE images (includes headerless recoveries) |
| `go_implants.json` | Go binary analysis (capabilities, packages, known tools) |
| `go_info.json` | Structural Go metadata (buildinfo, pclntab functions, dependencies) |
| `go_binaries/` | Extracted Go binaries |
| `dotnet_analysis.json` | .NET assembly analysis (metadata, P/Invoke, risk scores) |
| `dotnet/` | Extracted suspicious .NET binaries |
| `inspect_report.json` | Unified binary inspection (any language) |
| `c2_hunt.json` | C2 indicators from raw process memory (URLs, keys, certs, UAs) |

## Python API

```python
from minidump.minidumpfile import MinidumpFile
from memdump_toolkit import extract_dlls, detect_injection, analyze_binary

# Parse dump once, pass to all modules
mf = MinidumpFile.parse("process.dmp")
reader = mf.get_reader()

# Run the full universal analysis
extract_dlls.analyze(mf, reader, "output")           # Step 1: extract all PEs
injection = detect_injection.analyze(mf, reader, "output")  # Step 2: injection checks
results = analyze_binary.analyze(mf, reader, "output")      # Step 3: score everything

# Or run language-specific analyzers directly
from memdump_toolkit import identify_go_implants, analyze_dotnet
go = identify_go_implants.analyze(mf, reader, "output")
dotnet = analyze_dotnet.analyze(mf, reader, "output")
```

Every module exports `analyze(mf, reader, out_dir)` (orchestrated) and `run(dump_path, out_dir)` (standalone).

## How Scoring Works

### Universal Risk Score (0-100)

| Signal | Points | Example |
|--------|--------|---------|
| YARA rule match (offensive_tool tag) | +40 | Cobalt Strike beacon, Mimikatz |
| YARA rule match (other) | up to +30 | Custom signature hits |
| Process injection imports | +20 | VirtualAllocEx, CreateRemoteThread |
| Packer artifacts | +15 | UPX section names, VMProtect strings |
| RWX sections | +15 | Read+Write+Execute memory |
| Credential access imports | +15 | MiniDumpWriteDump, LsaLogonUser |
| Go capabilities (3+) | +25 | socks_proxy, yamux, kerberos |
| .NET obfuscators | +20 | ConfuserEx, .NET Reactor |
| .NET evasion P/Invoke | +10 | AmsiScanBuffer, EtwEventWrite |
| High-entropy sections | +10 | Encrypted/compressed content |
| Embedded network IOCs | +10 | URLs, named pipes in strings |
| Timestamp anomaly | +5 | Future date, pre-2000 |
| Headerless PE (MZ zeroed) | +25 | PE found via section table patterns, header erased |
| Section unpacking | +15 | Large virtual/raw ratio + high entropy on executable section |

### Language-Specific Deep Analysis

When language is detected, the binary gets additional specialized analysis:

**Go** — score-based detection (quick first-page + deep verification), two-tier capability detection (socks, yamux, kerberos, NTLM, SMB, ...), known tool matching (Chisel, Sliver, Merlin, Ligolo, ...), package/module path extraction, network IOC discovery.

**.NET** — CLR header + dnfile metadata extraction, P/Invoke classification (5 categories), suspicious API patterns (8 categories), offensive tool matching (SharpHound, Rubeus, Seatbelt, Covenant, ...), obfuscator detection (10 families), framework assembly whitelist.

**Rust/Delphi/Nim** — language identification via string signatures (panic handlers, compiler paths, runtime markers). Tagged in output for analyst awareness.

## Injection Detection (9 Checks)

| Check | What It Finds |
|-------|--------------|
| Typosquatting | DLL names mimicking system DLLs (Levenshtein + homoglyph) |
| Heap-loaded modules | DLLs at heap addresses (bitness-aware) |
| Hidden PE images | PE binaries not in the module list (including headerless PE recovery) |
| Untrusted paths | Modules loaded from non-system locations |
| Duplicate names | Multiple DLLs with the same name |
| Rogue threads | Threads executing outside known modules |
| Executable memory | RWX and RX regions with 7-heuristic shellcode analysis (prologues, patterns, NOP sleds, code density, embedded PEs, statistical classification, capstone disassembly) |
| Suspicious imports | API combinations used for injection/evasion |
| Stack frame walking | Return addresses outside known modules (catches shellcode callers) |

## Binary Inspection (`inspect`)

Analyze any standalone binary file — auto-detects the language and dispatches to the right analyzer:

```bash
memdump-toolkit inspect malware.dll -o ./results
```

Detection order: Go (structural `\xff Go buildinf:` magic) → .NET (CLR header) → Rust/Delphi/Nim (byte signatures) → Native fallback. Always runs YARA if `--yara` or `--yara-rules` is provided.

## C2 Hunt (`c2-hunt`)

Scans ALL memory segments in a minidump for live runtime C2 artifacts — things that exist in heap/stack at capture time but are not in the static binary:

```bash
memdump-toolkit c2-hunt dump.dmp -o ./results
```

| Indicator | What It Finds |
|-----------|--------------|
| URLs | WebSocket/HTTP C2 endpoints (whitelist-first filtering, drops cert store noise) |
| Hostnames | Cloud C2 infrastructure (AWS ELB, CloudFront, ngrok, Cloudflare) |
| IP:Port | Bare IP connections (filtered for reserved/loopback) |
| Private keys | PEM-encoded RSA/EC/DSA keys in heap memory |
| Certificates | PEM certificates with memory addresses |
| Named pipes | IPC channels used by implants |
| User-Agents | Split into heap (likely implant) vs system DLL (benign) by memory address |

## Go Structural Analysis (`go-info`)

Deep structural analysis of Go binaries using build metadata rather than string regex:

```bash
memdump-toolkit go-info implant.dll -o ./results
```

Extracts module path, Go version, dependencies from `\xff Go buildinf:` marker. Recovers function names and source files from pclntab by module prefix. Detects 18 capabilities (WebSocket C2, TCP C2, Named Pipe C2, SOCKS proxy, Kerberos, NTLM, SMB, pivoting, port forwarding, etc.).

## YARA Integration

```bash
# Use community rules (auto-downloaded)
memdump-toolkit full dump.dmp -o ./results --yara

# Update community rules, then scan
memdump-toolkit full dump.dmp -o ./results --update-yara --yara

# Use a custom rules directory
memdump-toolkit full dump.dmp --yara-rules ./my-custom-rules/
```

**The toolkit uses a two-tier detection approach.** Built-in Python signatures (`SHELLCODE_PROLOGUES`, `KNOWN_TOOLS`, `PACKER_SIGNATURES`, etc.) provide fast first-pass detection for common patterns. YARA scanning (via `--yara` or `--yara-rules`) adds deeper offensive tool attribution — matching Cobalt Strike, Metasploit, custom implants, and other advanced signatures for maximum coverage.

`fetch-rules` downloads these rulesets (all by default, or pick with `-r`):

| Ruleset | Focus |
|---------|-------|
| **signature-base** (Neo23x0) | Best for Go implants, Cobalt Strike, webshells |
| **yara-rules** (community) | Broad malware families, packers, exploits |
| **gcti** (Google) | APT-focused, high quality |
| **reversinglabs** | Large malware family signature set |
| **eset** | ESET research publications |
| **elastic** | Elastic threat research |

Rulesets are configured in `~/.memdump-toolkit/rulesets.yml` — edit this file to add custom repositories or remove defaults without code changes.

## Known Limitations

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for a detailed breakdown of what the toolkit cannot do, where detection has gaps, and what constraints are inherent to offline minidump analysis.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "uv not found" | Install uv: see [docs.astral.sh/uv](https://docs.astral.sh/uv/) |
| "No modules found" | Dump may lack module list — hidden PE scan still runs |
| "YARA scan failed" | `uv sync --extra yara` + check rule syntax |
| "Failed to read module memory" | Dump truncated — toolkit falls back to page-by-page reading |
| Slow on large dumps | Normal for >1 GB; dump is parsed once, binary analysis runs in parallel, modules are filtered by tier |
| Too many false positives | System DLLs should score 0 — check if paths are in trusted list |
| Hashes don't match VirusTotal | **Expected.** Memory-dumped DLLs differ from on-disk originals due to relocation, IAT patching, and page zeroing — hashes will never match VirusTotal or any on-disk database. |

## Acknowledgements

This toolkit builds on and integrates with the following open-source projects:

| Project | Role | License |
|---------|------|---------|
| [minidump](https://github.com/skelsec/minidump) | Windows minidump parsing | MIT |
| [capstone](https://github.com/capstone-engine/capstone) | Disassembly for shellcode validation | BSD 3-Clause |
| [signature-base](https://github.com/Neo23x0/signature-base) | YARA rules — Go implants, Cobalt Strike, webshells | CC BY-NC 4.0 |
| [YARA-Rules](https://github.com/Yara-Rules/rules) | YARA rules — broad malware families, packers, exploits | GPL 2.0 |
| [GCTI](https://github.com/chronicle/GCTI) | YARA rules — APT-focused (Google Threat Intelligence) | Apache 2.0 |
| [ReversingLabs YARA](https://github.com/reversinglabs/reversinglabs-yara-rules) | YARA rules — large malware family signature set | MIT |
| [ESET malware-ioc](https://github.com/eset/malware-ioc) | YARA rules — ESET research publications | BSD 2-Clause |
| [Elastic detection-rules](https://github.com/elastic/detection-rules) | YARA rules — Elastic threat research | Elastic License 2.0 |


## Related Tools

| Tool | What It Does |
|------|-------------|
| [PE-sieve](https://github.com/hasherezade/pe-sieve) | Live process scanner — detects hollowing, hooking, and injected code in running processes |
| [HollowsHunter](https://github.com/hasherezade/hollows_hunter) | Wraps PE-sieve to scan all running processes at once |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Full memory forensics framework for raw memory images |

**How they differ:** PE-sieve/HollowsHunter scan *live processes*. Volatility works on *full RAM captures*. This toolkit works on *Windows minidumps* (`.dmp` from Task Manager, ProcDump, etc.) — a lighter-weight artifact that's easier to collect in IR.

## Disclaimer

This toolkit is provided **for defensive security, incident response, and educational purposes only**. It is designed to help analysts examine memory dumps from systems they are authorized to investigate.

- Do **not** use this tool to analyze systems or data you do not own or have explicit authorization to examine.
- The authors assume **no liability** for misuse or for any damage resulting from the use of this software.
- Detection of offensive tools (e.g., Cobalt Strike, Sliver) is intended to aid defenders — not to facilitate attacks.

This project was developed through AI-assisted coding to rapidly orchestrate multiple analysis engines. While functional and tested, it has not undergone formal security audit — use your own judgement before integrating into production workflows.

By using this toolkit you agree to comply with all applicable laws and regulations in your jurisdiction.

## License

Consult LICENSE file in repository root.
