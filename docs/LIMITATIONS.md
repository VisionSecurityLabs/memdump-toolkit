# MemDump Toolkit — Known Limitations

This document describes the current boundaries of memdump-toolkit: what it cannot do, where detection has gaps, and what constraints are inherent to offline minidump analysis.

---

## 1. Input Format Constraints

### Windows minidumps only

The toolkit parses `.dmp` files via the `minidump` library. It cannot process:

- Full crash dumps (complete memory images with kernel data)
- Linux/macOS core dumps (`core.*` files)
- VMware memory snapshots (`.vmem`, `.vmss`)
- Hyper-V saved state files (`.vsv`, `.bin`)
- Volatility-compatible raw memory images
- Hibernation files (`hiberfil.sys`)

### Single-process scope

Each dump represents one process. There is no cross-process correlation — you cannot trace an injection chain (process A injected into process B) from a single dump. Analyzing multiple dumps requires running the tool separately on each and manually correlating the IOC exports.

### No disk baseline

The toolkit only has the memory-resident state of the process. It cannot access the original on-disk files for comparison. This is the single largest architectural constraint and blocks several detection techniques (see §3).

---

## 2. Detection Gaps

### Hook detection — not possible

Inline hooks (JMP patches at function entry points) and IAT hooks (import table modifications) are invisible without the on-disk originals to diff against. pe-sieve detects these by comparing in-memory module bytes against the on-disk PE, page by page. Since minidumps do not include the on-disk files, this comparison is not possible.

### ROP chain detection — not implemented

The stack frame walker (CHECK 9) identifies return addresses outside known modules, which catches classic shellcode-on-stack scenarios. It does not detect return-oriented programming (ROP) within legitimate modules — where every return address points into a valid DLL but the sequence of gadgets forms a malicious payload. ROP detection would require control flow analysis of the return address chain against known gadget databases.

### Memory-mapped file ambiguity

Executable `MEM_MAPPED` regions outside modules receive LOW severity. These could be legitimate memory-mapped sections (fonts, locale data) or injected code. Without the backing file path (which minidumps do not always include), there is no way to distinguish between the two.

### SEH/unwind-based stack walking — not implemented

The stack frame walker uses frame pointer chains (RBP/EBP) with a heuristic stack scan fallback. Most optimized Windows binaries (including system DLLs) omit frame pointers and rely on SEH or `.pdata`/`.xdata` unwind information instead. Parsing these unwind structures would give more accurate stack traces on optimized code but requires implementing the Windows x64 unwind spec.

### Headerless PE recovery limits

The headerless PE scanner finds binaries with zeroed MZ headers by locating section table patterns. It has these limits:

- Requires at least 2 intact section headers with valid names or printable ASCII
- If the attacker zeroes the entire PE header AND the section table, recovery is not possible
- Scan window is capped at 8 KB (0x2000) from segment start — PEs with unusually large optional headers pushing the section table beyond this offset will be missed (rare in practice)

### Hash mismatch with on-disk databases

Memory-dumped DLL hashes do not match their on-disk originals due to relocation, IAT patching, and page zeroing applied by the Windows loader. This means:

- On-disk hash databases (VirusTotal, etc.) will not match memory-dumped files
- The `--known-good` feature requires hashes computed from memory dumps of clean systems, not from on-disk files

---

## 3. Analysis Scope

### No network/disk artifact correlation

The C2 hunt scans raw process memory for indicators (URLs, IPs, hostnames, private keys) but cannot validate findings against external data sources:

- No PCAP/network capture correlation
- No DNS log cross-referencing
- No firewall rule validation
- No file system artifact inspection

### No threat intelligence enrichment

Extracted IOCs (hashes, IPs, URLs) are not checked against external threat intelligence feeds. Integration with VirusTotal, AbuseIPDB, OTX, or similar services would transform output from "suspicious indicators" to "confirmed known-bad indicators" but requires network access and API keys.

### No timeline reconstruction

The toolkit identifies what is suspicious (injection indicators, malicious modules, C2 artifacts) but does not reconstruct the order of events. PE timestamps and module load order provide hints, but a true attack timeline would require correlating with ETW traces, event logs, or Sysmon data — none of which are present in a minidump.

---

## 4. Performance Constraints

### Single-threaded analysis

Module analysis (Step 3) processes binaries sequentially. On dumps with 200+ modules, this is the bottleneck. Parallelizing binary analysis across CPU cores would improve throughput but requires careful handling of shared state (seen hashes, output files).

### YARA compilation overhead

Community rulesets (6 repositories, thousands of rule files) are compiled individually per scan. There is no rule caching between binaries or between runs. Pre-compiling rules into a binary cache on first use would significantly reduce per-binary scan time.

### Memory usage with large known-good sets

Large known-good hash sets (millions of entries) loaded as a Python `set[str]` consume significant RAM. For very large hash sets, a bloom filter or SQLite-backed lookup would be more appropriate than in-memory storage.

---

## 5. Inherent to Offline Minidump Analysis

These limitations are fundamental to the approach and cannot be solved within the minidump format:

| Limitation | Why | What would fix it |
|-----------|-----|-------------------|
| No disk baseline comparison | Minidumps contain only in-memory state | Live-process scanning (pe-sieve) or full memory image + disk access |
| No handle/object information | MiniDumpNormal does not include handle data | MiniDumpWithHandleData flag at capture time |
| No kernel memory | Minidumps are user-mode only | Full memory forensics (Volatility) |
| Incomplete stack memory | Not all minidump types include full thread stacks | MiniDumpWithFullMemory at capture time |
| No network connection state | TCP/UDP table is not in the minidump | Capture with ProcDump `/ma` + netstat, or use Volatility |
| Relocated module hashes | Windows loader applies fixups before capture | Hash against the in-memory image, not the on-disk file |

---

## 6. Future Work

These are concrete improvements that would close the most impactful gaps:

| Priority | Feature | Impact | Effort |
|----------|---------|--------|--------|
| High | Threat intel enrichment (VT, OTX, AbuseIPDB) | Confirms whether IOCs are known-bad | Medium |
| High | Multi-dump correlation | Traces injection chains across processes | High |
| Medium | Parallel binary analysis | Speeds up Step 3 on large dumps | Low |
| Medium | YARA rule caching | Speeds up repeated scans | Low |
| Medium | SEH/unwind stack walking | Better stack traces on optimized binaries | High |
| Low | Volatility integration | Supports full memory images | High |
| Low | Interactive HTML report | Rich visualization for analysts | Medium |
| Low | SIGMA/YARA rule generation | Auto-generate detection rules from findings | Medium |
