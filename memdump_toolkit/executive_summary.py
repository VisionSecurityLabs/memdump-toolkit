"""Generate an executive summary and MITRE ATT&CK mapping for CERT analysts.

Translates raw forensic findings into plain-English prose and maps every
detected capability to ATT&CK technique IDs.  Designed for analysts who
need to understand *what happened* and *what to do* — not how PE headers work.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.table import Table

from memdump_toolkit.colors import bold, console, critical, dim, high, info, success
from memdump_toolkit.constants import HEAP_THRESHOLD_X64, SCORE_CRITICAL, SCORE_HIGH


# ─── Module Address Resolver ────────────────────────────────────────────────

def _build_module_map(
    binary_results: list[dict],
    injection_report: dict | None,
) -> list[tuple[int, int, str]]:
    """Build sorted (base, end, name) ranges from binary results + injection report.

    Covers both listed modules (by parsing base address from file paths in
    binary_results) and hidden PEs (from injection report).
    """
    ranges: list[tuple[int, int, str]] = []

    # Collect filenames from binary_results keyed by base address.
    # Hidden files encode the address in their name: hidden_NNN_0xADDR.dll
    # Listed modules store their base address in pe_info.
    addr_to_filename: dict[int, str] = {}
    for r in binary_results:
        fpath = r.get("file", "")
        fname = Path(fpath).name
        size = r.get("pe_info", {}).get("image_size") or r.get("size", 0)

        # Hidden files: hidden_NNN_0xADDR.dll
        if "0x" in fname:
            try:
                hex_part = fname.split("0x")[1].split(".")[0]
                base = int(hex_part, 16)
                addr_to_filename[base] = fname
                ranges.append((base, base + size, fname))
            except (ValueError, IndexError):
                pass
        else:
            # Listed modules: try to get base address from the extraction path
            # Filenames like "modules/ntdll.dll" — look for base in pe_info
            # or parse from the parent directory context.
            # binary_results from analyze_binary don't store base address directly,
            # so we skip listed modules here (they're added from injection_report below).
            pass

    # Listed + hidden modules from injection report findings.
    # Many finding types (HEAP_LOADED_MODULE, UNTRUSTED_PATH, TYPOSQUATTING,
    # SUSPICIOUS_IMPORTS, HIDDEN_PE) carry a "base" address and "module" name.
    if injection_report:
        covered_bases = {r[0] for r in ranges}
        for f in injection_report.get("findings", []):
            try:
                base_str = f.get("base")
                if not base_str:
                    continue
                base = int(base_str, 16)
                if base in covered_bases:
                    continue

                if f.get("type") == "HIDDEN_PE":
                    size = f.get("image_size", 0)
                    identity = f.get("identity", "UNKNOWN")
                    if identity == "UNKNOWN":
                        identity = f"hidden_PE_0x{base:x}"
                    ranges.append((base, base + size, identity))
                else:
                    # Listed module finding — use module name + size
                    module_name = f.get("module", "")
                    if module_name:
                        name = Path(module_name).name
                        size = f.get("size", 0)
                        ranges.append((base, base + size, name))

                covered_bases.add(base)
            except (ValueError, KeyError):
                pass

    # Sort by base address for binary search
    ranges.sort()
    return ranges


def _resolve_address(addr: int, module_map: list[tuple[int, int, str]]) -> str | None:
    """Find which module an address falls inside, or None if heap/stack."""
    # Linear scan (module lists are small, typically < 200 entries)
    for base, end, name in module_map:
        if base <= addr < end:
            return name
    return None


def _attribute_c2_to_modules(
    c2_results: dict,
    module_map: list[tuple[int, int, str]],
) -> dict[str, list[dict]]:
    """Attribute C2 findings to specific modules by address.

    Returns: {"module_name": [{"type": "url", "value": "..."}, ...],
              "(process memory)": [...]}
    """
    attribution: dict[str, list[dict]] = {}

    def _attr(finding_type: str, value: str, addresses: list[int]) -> None:
        # Try to resolve to a module; use first match
        owner = None
        for addr in addresses:
            owner = _resolve_address(addr, module_map)
            if owner:
                break
        bucket = owner or "(process memory)"
        attribution.setdefault(bucket, [])
        attribution[bucket].append({"type": finding_type, "value": value})

    for entry in c2_results.get("urls", []):
        _attr("url", entry["value"], entry.get("addresses", []))

    for entry in c2_results.get("hostnames", []):
        _attr("hostname", entry["value"], entry.get("addresses", []))

    for entry in c2_results.get("ip_ports", []):
        _attr("ip_port", entry["value"], entry.get("addresses", []))

    for entry in c2_results.get("named_pipes", []):
        _attr("named_pipe", entry["value"], entry.get("addresses", []))

    for entry in c2_results.get("private_keys", []):
        addr = entry.get("address", 0)
        _attr("private_key", "(PEM key material)", [addr])

    for entry in c2_results.get("certificates", []):
        addr = entry.get("address", 0)
        _attr("certificate", "(X.509 certificate)", [addr])

    # Heap user agents (addresses in low range = likely implant)
    for entry in c2_results.get("user_agents", []):
        addrs = entry.get("addresses", [])
        heap_addrs = [a for a in addrs if a < c2_results.get("heap_threshold", HEAP_THRESHOLD_X64)]
        if heap_addrs:
            _attr("user_agent", entry["value"][:200], heap_addrs)

    return attribution


# ─── MITRE ATT&CK Mapping ──────────────────────────────────────────────────

# Maps internal signal names → (ATT&CK ID, Technique Name, Tactic)
ATTACK_MAP: dict[str, tuple[str, str, str]] = {
    # ── Go capability keys (go_info.py CAPABILITY_PATTERNS) ───────────────
    "websocket_c2":        ("T1071.001", "Web Protocols",            "Command and Control"),
    "tcp_c2":              ("T1095",     "Non-Application Layer Protocol", "Command and Control"),
    "named_pipe_c2":       ("T1570",     "Lateral Tool Transfer",    "Lateral Movement"),
    "port_forwarding":     ("T1572",     "Protocol Tunneling",       "Command and Control"),
    "reverse_port_forwarding": ("T1572", "Protocol Tunneling",       "Command and Control"),
    "pivoting":            ("T1090.001", "Internal Proxy",           "Command and Control"),
    "socks_proxy":         ("T1090.001", "Internal Proxy",           "Command and Control"),
    "icmp_tunneling":      ("T1095",     "Non-Application Layer Protocol", "Command and Control"),
    "ntlm_auth":           ("T1550.002", "Pass the Hash",            "Lateral Movement"),
    "kerberos_auth":       ("T1558",     "Steal or Forge Kerberos Tickets", "Credential Access"),
    "ldap":                ("T1018",     "Remote System Discovery",  "Discovery"),
    "smb":                 ("T1021.002", "Remote Services: SMB",     "Lateral Movement"),
    "user_impersonation":  ("T1134",     "Access Token Manipulation","Privilege Escalation"),
    "xor_encryption":      ("T1027",     "Obfuscated Files or Information", "Defense Evasion"),
    "sleep_beacon":        ("T1029",     "Scheduled Transfer",       "Exfiltration"),
    "proxy_traversal":     ("T1090.002", "External Proxy",           "Command and Control"),
    "udp_tunneling":       ("T1095",     "Non-Application Layer Protocol", "Command and Control"),
    "resilient_connection": ("T1008",    "Fallback Channels",        "Command and Control"),

    # ── Go capability keys (identify_go_implants CAPABILITY_STRONG) ───────
    "socks_proxy_strong":  ("T1090.001", "Internal Proxy",           "Command and Control"),
    "credential_theft":    ("T1003",     "OS Credential Dumping",    "Credential Access"),
    "encryption":          ("T1573.002", "Encrypted Channel: Asymmetric", "Command and Control"),
    "c2_websocket":        ("T1071.001", "Web Protocols",            "Command and Control"),
    "multiplexing":        ("T1572",     "Protocol Tunneling",       "Command and Control"),
    "kerberos":            ("T1558",     "Steal or Forge Kerberos Tickets", "Credential Access"),
    "ntlm":                ("T1550.002", "Pass the Hash",            "Lateral Movement"),
    "smb_strong":          ("T1021.002", "Remote Services: SMB",     "Lateral Movement"),
    "ldap_strong":         ("T1018",     "Remote System Discovery",  "Discovery"),
    "icmp":                ("T1095",     "Non-Application Layer Protocol", "Command and Control"),
    "pivot":               ("T1090.001", "Internal Proxy",           "Command and Control"),

    # ── Go capability keys (identify_go_implants CAPABILITY_WEAK) ─────────
    "reverse_shell":       ("T1059",     "Command and Scripting Interpreter", "Execution"),
    "persistence":         ("T1547",     "Boot or Logon Autostart Execution", "Persistence"),
    "c2_http":             ("T1071.001", "Web Protocols",            "Command and Control"),
    "c2_dns":              ("T1071.004", "DNS",                      "Command and Control"),
    "named_pipes":         ("T1570",     "Lateral Tool Transfer",    "Lateral Movement"),
    "lateral_movement":    ("T1021",     "Remote Services",          "Lateral Movement"),

    # ── .NET suspicious categories ────────────────────────────────────────
    "process_injection":   ("T1055",     "Process Injection",        "Defense Evasion"),
    "reflective_loading":  ("T1620",     "Reflective Code Loading",  "Defense Evasion"),
    "dynamic_code":        ("T1027.010", "Command Obfuscation",      "Defense Evasion"),
    "process_execution":   ("T1059",     "Command and Scripting Interpreter", "Execution"),
    "network_comms":       ("T1071",     "Application Layer Protocol","Command and Control"),
    "memory_access":       ("T1055",     "Process Injection",        "Defense Evasion"),
    "anti_analysis":       ("T1622",     "Debugger Evasion",         "Defense Evasion"),
    "evasion":             ("T1562",     "Impair Defenses",          "Defense Evasion"),
    "credential_access":   ("T1003",     "OS Credential Dumping",    "Credential Access"),
    "code_loading":        ("T1129",     "Shared Modules",           "Execution"),
    "memory_manipulation": ("T1055",     "Process Injection",        "Defense Evasion"),

    # ── Universal signals ─────────────────────────────────────────────────
    "packer_artifacts":    ("T1027.002", "Software Packing",         "Defense Evasion"),
    "dotnet_obfuscators":  ("T1027",     "Obfuscated Files or Information", "Defense Evasion"),
    "rwx_sections":        ("T1055.012", "Process Hollowing",        "Defense Evasion"),
    "high_entropy":        ("T1027.002", "Software Packing",         "Defense Evasion"),
    "timestamp_anomaly":   ("T1070.006", "Timestomp",                "Defense Evasion"),
    "hidden_pe":           ("T1055",     "Process Injection",        "Defense Evasion"),

    # ── C2 hunt signals ──────────────────────────────────────────────────
    "c2_url":              ("T1071.001", "Web Protocols",            "Command and Control"),
    "c2_private_key":      ("T1588.004", "Digital Certificates",     "Resource Development"),
    "c2_named_pipe":       ("T1570",     "Lateral Tool Transfer",    "Lateral Movement"),
    "implant_user_agent":  ("T1071.001", "Web Protocols",            "Command and Control"),

    # ── Known tool families ───────────────────────────────────────────────
    "Cobalt_Strike":       ("S0154",     "Cobalt Strike",            "Command and Control"),
    "Metasploit":          ("S0261",     "Metasploit",               "Execution"),
    "Havoc":               ("S1071",     "Havoc",                    "Command and Control"),
    "Brute_Ratel":         ("S1063",     "Brute Ratel C4",          "Command and Control"),
    "Mimikatz":            ("S0002",     "Mimikatz",                 "Credential Access"),
    "SharpHound":          ("S0521",     "BloodHound",               "Discovery"),
    "Rubeus":              ("S0692",     "Rubeus",                   "Credential Access"),
    "Chisel":              ("S0609",     "Chisel",                   "Command and Control"),
    "Impacket":            ("S0357",     "Impacket",                 "Lateral Movement"),
    "sliver":              ("S0633",     "Sliver",                   "Command and Control"),
    "ligolo-ng":           ("T1572",     "Protocol Tunneling (Ligolo-ng)", "Command and Control"),
    "merlin":              ("S0518",     "Merlin",                   "Command and Control"),
}


# ─── Verdict Generator ──────────────────────────────────────────────────────

def _binary_verdict(result: dict) -> str:
    """Generate a plain-English one-line verdict for a single binary."""
    parts: list[str] = []
    lang = result.get("language") or "native"
    score = result.get("risk_score", 0)

    # Tool identification
    tools = [t["tool"] for t in result.get("offensive_tools", [])]
    go_tools = result.get("go_analysis", {}).get("known_tools", [])
    dn_tools = [t.get("tool", "") for t in result.get("dotnet_analysis", {}).get("offensive_tools", [])]
    all_tools = tools + go_tools + dn_tools
    if all_tools:
        parts.append(f"identified as {', '.join(all_tools)}")

    # Language + type
    is_dll = result.get("pe_info", {}).get("is_dll")
    binary_type = "DLL" if is_dll else "EXE"
    if lang == "go":
        parts.insert(0, f"Go {binary_type}")
    elif lang == "dotnet":
        asm = result.get("dotnet_analysis", {}).get("metadata", {}).get("assembly_name")
        parts.insert(0, f".NET {binary_type}" + (f" ({asm})" if asm else ""))
    elif lang in ("rust", "delphi", "nim"):
        parts.insert(0, f"{lang.capitalize()} {binary_type}")
    else:
        parts.insert(0, f"Native {binary_type}")

    # Key capabilities
    go_caps = list(result.get("go_analysis", {}).get("capabilities", {}).keys())
    if not go_caps:
        # Try go_info-style capabilities (list of strings)
        go_caps = result.get("go_analysis", {}).get("capabilities", [])
        if isinstance(go_caps, dict):
            go_caps = list(go_caps.keys())

    cap_descriptions: list[str] = []
    for cap in go_caps:
        entry = ATTACK_MAP.get(cap)
        if entry:
            cap_descriptions.append(entry[1])
    if cap_descriptions:
        parts.append(f"with {', '.join(cap_descriptions[:4])}")
        if len(cap_descriptions) > 4:
            parts.append(f"and {len(cap_descriptions) - 4} more capabilities")

    # Obfuscation
    if result.get("packer_artifacts"):
        packers = [p["packer"] for p in result["packer_artifacts"]]
        parts.append(f"packed with {', '.join(packers)}")
    if result.get("dotnet_analysis", {}).get("obfuscators"):
        obfs = [o["obfuscator"] for o in result["dotnet_analysis"]["obfuscators"]]
        parts.append(f"obfuscated with {', '.join(obfs)}")

    # Source
    source = result.get("source", "")
    if source == "hidden":
        parts.append("found hidden in memory (not in module list)")

    return " — ".join(parts) if parts else f"{lang} binary"


# ─── ATT&CK Extraction ──────────────────────────────────────────────────────

def _collect_attack_techniques_per_binary(
    binary_results: list[dict],
    c2_results: dict | None,
    injection_report: dict | None,
) -> list[dict]:
    """Collect MITRE ATT&CK techniques grouped by binary.

    Returns a list of dicts, one per binary (+ one for C2/injection
    signals that aren't tied to a specific DLL):
      {"binary": "foo.dll", "risk_score": 75, "language": "go",
       "techniques": [{"technique_id": ..., "technique_name": ...,
                        "tactic": ..., "evidence": ...}, ...]}
    """
    tactic_order = [
        "Resource Development", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Command and Control",
        "Exfiltration",
    ]

    def _sort_key(t: dict) -> tuple:
        tac = t["tactic"]
        idx = tactic_order.index(tac) if tac in tactic_order else 99
        return (idx, t["technique_id"])

    def _map(key: str, evidence: str, seen: set) -> dict | None:
        entry = ATTACK_MAP.get(key)
        if entry and entry[0] not in seen:
            seen.add(entry[0])
            return {
                "technique_id": entry[0],
                "technique_name": entry[1],
                "tactic": entry[2],
                "evidence": evidence,
            }
        return None

    per_binary: list[dict] = []

    for r in binary_results:
        fname = Path(r.get("file", "unknown")).name
        score = r.get("risk_score", 0)
        if score < 10:
            continue

        seen: set[str] = set()
        techs: list[dict] = []

        def _add(key: str, evidence: str) -> None:
            t = _map(key, evidence, seen)
            if t:
                techs.append(t)

        # Offensive tools
        for t in r.get("offensive_tools", []):
            _add(t["tool"], f"byte signature matched")
        for t in r.get("go_analysis", {}).get("known_tools", []):
            _add(t, f"Go tool signature")
        for t in r.get("dotnet_analysis", {}).get("offensive_tools", []):
            _add(t.get("tool", ""), f".NET tool signature")

        # Go capabilities
        go_caps = r.get("go_analysis", {}).get("capabilities", [])
        if isinstance(go_caps, dict):
            go_caps = list(go_caps.keys())
        for cap in go_caps:
            _add(cap, f"Go capability")

        # .NET suspicious categories
        for cat in r.get("dotnet_analysis", {}).get("suspicious_pinvoke", {}).keys():
            _add(cat, f"P/Invoke")
        for cat in r.get("dotnet_analysis", {}).get("suspicious_apis", {}).keys():
            _add(cat, f".NET API")

        # Universal signals
        if r.get("packer_artifacts"):
            packers = ", ".join(p["packer"] for p in r["packer_artifacts"])
            _add("packer_artifacts", packers)
        if r.get("dotnet_analysis", {}).get("obfuscators"):
            _add("dotnet_obfuscators", "obfuscator detected")
        if any(a["type"] == "rwx" for a in r.get("section_anomalies", [])):
            _add("rwx_sections", "RWX section")
        if r.get("high_entropy_sections"):
            _add("high_entropy", "encrypted/packed content")
        if r.get("timestamp_anomaly"):
            _add("timestamp_anomaly", r["timestamp_anomaly"])

        if techs:
            techs.sort(key=_sort_key)
            per_binary.append({
                "binary": fname,
                "risk_score": score,
                "language": r.get("language") or "native",
                "techniques": techs,
            })

    # C2 + injection signals (not tied to a specific DLL)
    infra_seen: set[str] = set()
    infra_techs: list[dict] = []

    def _add_infra(key: str, evidence: str) -> None:
        t = _map(key, evidence, infra_seen)
        if t:
            infra_techs.append(t)

    if c2_results:
        if c2_results.get("urls"):
            _add_infra("c2_url", f"{len(c2_results['urls'])} URL(s) in memory")
        if c2_results.get("private_keys"):
            _add_infra("c2_private_key", f"{len(c2_results['private_keys'])} key(s)")
        if c2_results.get("named_pipes"):
            _add_infra("c2_named_pipe", "named pipe(s)")
        heap_uas = [e for e in c2_results.get("user_agents", [])
                    if any(a < c2_results.get("heap_threshold", HEAP_THRESHOLD_X64) for a in e.get("addresses", []))]
        if heap_uas:
            _add_infra("implant_user_agent", "spoofed UA in heap")

    if injection_report:
        for f in injection_report.get("findings", []):
            if f["type"] == "HIDDEN_PE" and f.get("severity") in ("CRITICAL", "HIGH"):
                _add_infra("hidden_pe", f"hidden PE at {f.get('base', '?')}")

    if infra_techs:
        infra_techs.sort(key=_sort_key)
        per_binary.append({
            "binary": "(process memory)",
            "risk_score": 0,
            "language": "n/a",
            "techniques": infra_techs,
        })

    # Sort groups: highest risk score first, infra group last
    per_binary.sort(key=lambda g: (-g["risk_score"], g["binary"]))

    return per_binary


def _collect_attack_techniques(
    binary_results: list[dict],
    c2_results: dict | None,
    injection_report: dict | None,
) -> list[dict[str, str]]:
    """Flat list of all ATT&CK techniques (for JSON export / summary line)."""
    groups = _collect_attack_techniques_per_binary(
        binary_results, c2_results, injection_report,
    )
    seen: set[str] = set()
    flat: list[dict[str, str]] = []
    for g in groups:
        for t in g["techniques"]:
            if t["technique_id"] not in seen:
                seen.add(t["technique_id"])
                flat.append({**t, "binary": g["binary"]})
    return flat


# ─── Executive Summary Generator ─────────────────────────────────────────────

def generate(
    out_dir: str,
    binary_results: list[dict],
    c2_results: dict | None = None,
    injection_report: dict | None = None,
) -> str:
    """Generate executive summary and ATT&CK mapping.

    Returns path to the saved JSON file.  Also prints a colored summary to
    stdout (which Tee captures into full_report.txt sans ANSI codes).
    """
    suspicious = [r for r in binary_results if r.get("risk_score", 0) >= 30]
    # Sort by "implant significance": known tools and capability count first,
    # then risk score.  A Go implant with 11 capabilities should lead over a
    # .NET loader that merely scores higher on generic API heuristics.
    def _implant_rank(r: dict) -> tuple[int, int]:
        """Rank by total "implant significance" then score.

        A binary with 11 capabilities is far more significant than one with
        a single tool match.  Combine tools + capabilities into one weight.
        """
        tools = (len(r.get("offensive_tools", []))
                 + len(r.get("go_analysis", {}).get("known_tools", []))
                 + len(r.get("dotnet_analysis", {}).get("offensive_tools", [])))
        caps = r.get("go_analysis", {}).get("capabilities", {})
        cap_count = len(caps) if isinstance(caps, (dict, list)) else 0
        return (tools + cap_count, r.get("risk_score", 0))
    suspicious.sort(key=_implant_rank, reverse=True)

    # ── Build verdict list ────────────────────────────────────────────────
    verdicts: list[dict[str, Any]] = []
    for r in suspicious:
        verdicts.append({
            "file": Path(r.get("file", "unknown")).name,
            "risk_score": r.get("risk_score", 0),
            "language": r.get("language") or "native",
            "verdict": _binary_verdict(r),
            "hashes": r.get("hashes", {}),
        })

    # ── Collect ATT&CK techniques ────────────────────────────────────────
    attack_groups = _collect_attack_techniques_per_binary(
        binary_results, c2_results, injection_report,
    )
    techniques = _collect_attack_techniques(binary_results, c2_results, injection_report)

    # ── Build module map for C2 attribution ──────────────────────────────
    module_map = _build_module_map(binary_results, injection_report)

    # ── Build C2 infrastructure summary ──────────────────────────────────
    c2_infra: dict[str, Any] = {}
    c2_by_module: dict[str, list[dict]] = {}
    if c2_results:
        c2_infra["urls"] = [e["value"] for e in c2_results.get("urls", [])]
        c2_infra["hostnames"] = [e["value"] for e in c2_results.get("hostnames", [])]
        c2_infra["ip_ports"] = [e["value"] for e in c2_results.get("ip_ports", [])]
        c2_infra["private_keys"] = len(c2_results.get("private_keys", []))
        c2_infra["certificates"] = len(c2_results.get("certificates", []))
        heap_uas = [e for e in c2_results.get("user_agents", [])
                    if any(a < c2_results.get("heap_threshold", HEAP_THRESHOLD_X64) for a in e.get("addresses", []))]
        c2_infra["implant_user_agents"] = [e["value"][:200] for e in heap_uas]
        # Attribute C2 findings to modules by memory address
        c2_by_module = _attribute_c2_to_modules(c2_results, module_map)

    # ── Build prose summary ──────────────────────────────────────────────
    lines: list[str] = []

    if suspicious:
        top = suspicious[0]
        lang = top.get("language") or "native"
        fname = Path(top.get("file", "?")).name
        lines.append(
            f"A {bold(lang.upper())} implant was found "
            f"{'hidden in process memory' if top.get('source') == 'hidden' else f'as {fname}'} "
            f"with a risk score of {critical(str(top.get('risk_score', 0)))}/100."
        )

    if c2_infra.get("urls"):
        # Group by scheme for readability
        wss_urls = [u for u in c2_infra["urls"] if u.startswith("wss://")]
        http_urls = [u for u in c2_infra["urls"] if u.startswith("http")]
        if wss_urls:
            lines.append(
                f"The implant communicates via {critical('WebSocket')} to "
                f"{bold(str(len(wss_urls)))} endpoint(s)."
            )
        if http_urls:
            lines.append(
                f"{bold(str(len(http_urls)))} HTTP endpoint(s) used for C2 communication."
            )
        # Cloud provider detection
        aws_hosts = [h for h in c2_infra.get("hostnames", []) if "amazonaws.com" in h]
        if aws_hosts:
            # Extract region
            regions = set()
            for h in aws_hosts:
                parts = h.split(".")
                for i, p in enumerate(parts):
                    if p == "elb" and i + 1 < len(parts):
                        regions.add(parts[i + 1])
            region_str = ", ".join(regions) if regions else "unknown"
            lines.append(
                f"C2 infrastructure is hosted on {critical('AWS')} "
                f"({bold(str(len(aws_hosts)))} ELB(s) in {bold(region_str)})."
            )

    if c2_infra.get("private_keys"):
        lines.append(
            f"{critical(str(c2_infra['private_keys']))} private key(s) found in process memory "
            f"(used for mTLS authentication to C2)."
        )

    if c2_infra.get("implant_user_agents"):
        ua = c2_infra["implant_user_agents"][0]
        # Extract browser version for readability
        if "Chrome/" in ua:
            chrome_ver = ua.split("Chrome/")[1].split(" ")[0]
            lines.append(f"The implant spoofs a {bold(f'Chrome {chrome_ver}')} User-Agent.")
        else:
            lines.append(f"The implant uses a custom User-Agent string.")

    # Capability summary
    tactics = set(t["tactic"] for t in techniques)
    if tactics:
        lines.append(
            f"Mapped to {bold(str(len(techniques)))} MITRE ATT&CK techniques "
            f"across {bold(str(len(tactics)))} tactics."
        )

    # ── Print to stdout ──────────────────────────────────────────────────
    bar = "\u2550" * 70
    print(f"\n{info(bar)}")
    print(info(bold("  EXECUTIVE SUMMARY")))
    print(f"{info(bar)}")

    for line in lines:
        print(f"  {line}")

    # Verdicts
    if verdicts:
        print(f"\n  {bold('Suspicious Binaries:')}")
        for v in verdicts:
            score = v["risk_score"]
            if score >= SCORE_CRITICAL:
                label = critical("CRITICAL")
            elif score >= SCORE_HIGH:
                label = high("HIGH")
            else:
                label = dim("MEDIUM")
            print(f"  {label}  {bold(v['file'])}")
            print(f"         {v['verdict']}")

    # ATT&CK mapping — per binary (rich tables)
    if attack_groups:
        from rich.console import Console as _Console
        _con = _Console(width=120, force_terminal=console.is_terminal,
                        no_color=not console.is_terminal)

        print(f"\n  {bold('MITRE ATT&CK Coverage by Binary:')}")

        for group in attack_groups:
            gname = group["binary"]
            glang = group["language"]
            gscore = group["risk_score"]
            techs = group["techniques"]

            if gscore > 0:
                title = f"{gname}  (risk={gscore}/100, {glang})"
            else:
                title = gname

            table = Table(
                title=title,
                title_style="bold cyan",
                show_lines=False,
                padding=(0, 1),
                min_width=110,
            )
            table.add_column("Tactic", style="cyan bold", min_width=22, no_wrap=True)
            table.add_column("ID", style="bold", min_width=10, no_wrap=True)
            table.add_column("Technique", min_width=34, no_wrap=True)
            table.add_column("Evidence", style="dim", min_width=30, no_wrap=True)

            current_tactic = ""
            for t in techs:
                tactic_label = ""
                if t["tactic"] != current_tactic:
                    current_tactic = t["tactic"]
                    tactic_label = current_tactic
                table.add_row(tactic_label, t["technique_id"],
                              t["technique_name"], t["evidence"])

            _con.print(table)

    # C2 infrastructure — grouped by owning module
    if c2_by_module:
        print(f"\n  {bold('C2 Infrastructure by Binary:')}")
        for module_name, findings in sorted(
            c2_by_module.items(),
            key=lambda kv: (kv[0] == "(process memory)", kv[0]),
        ):
            print(f"\n  {info(bold(module_name))}")
            for f in findings:
                ftype = f["type"]
                fval = f["value"]
                if ftype == "url":
                    print(critical(f"    {fval}"))
                elif ftype == "private_key":
                    print(critical(f"    {fval}"))
                elif ftype == "user_agent":
                    print(high(f"    UA: {fval[:120]}"))
                elif ftype in ("hostname", "ip_port"):
                    print(high(f"    {fval}"))
                elif ftype == "named_pipe":
                    print(high(f"    pipe: {fval}"))
                elif ftype == "certificate":
                    print(dim(f"    {fval}"))
    elif c2_infra.get("urls"):
        # Fallback: flat list if no module attribution available
        print(f"\n  {bold('C2 Infrastructure:')}")
        for url in c2_infra["urls"]:
            print(critical(f"    {url}"))

    # Recommended actions
    print(f"\n  {bold('Recommended Actions:')}")
    if c2_infra.get("urls"):
        print(f"  1. {critical('BLOCK')} all C2 URLs/hostnames at network perimeter")
    if c2_infra.get("private_keys"):
        print(f"  2. {critical('REVOKE')} certificates — private key is compromised")
    if suspicious:
        print(f"  {'3' if c2_infra.get('urls') else '1'}. {high('ISOLATE')} affected host from network")
        sha = suspicious[0].get("hashes", {}).get("sha256", "")
        if sha:
            print(f"  {'4' if c2_infra.get('urls') else '2'}. {high('HUNT')} for SHA256 {dim(sha[:32])}... across fleet")
    if techniques:
        tech_ids = ", ".join(t["technique_id"] for t in techniques[:5])
        print(f"  {'5' if c2_infra.get('urls') else '3'}. {info('MAP')} techniques ({tech_ids}) to detection rules")

    print()

    # ── Save JSON ────────────────────────────────────────────────────────
    summary_data: dict[str, Any] = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "verdicts": verdicts,
        "c2_infrastructure": c2_infra,
        "c2_by_binary": c2_by_module,
        "mitre_attack_by_binary": attack_groups,
        "mitre_attack_techniques": techniques,
        "recommended_actions": [],
    }

    # Build recommended actions (plain text for JSON)
    if c2_infra.get("urls"):
        summary_data["recommended_actions"].append(
            "BLOCK all C2 URLs and hostnames at network perimeter"
        )
    if c2_infra.get("private_keys"):
        summary_data["recommended_actions"].append(
            "REVOKE certificates — private key material found in memory"
        )
    if suspicious:
        summary_data["recommended_actions"].append(
            "ISOLATE affected host from network immediately"
        )
        sha = suspicious[0].get("hashes", {}).get("sha256", "")
        if sha:
            summary_data["recommended_actions"].append(
                f"HUNT for SHA256 {sha} across the fleet"
            )
    if techniques:
        summary_data["recommended_actions"].append(
            f"MAP {len(techniques)} ATT&CK techniques to detection rules"
        )

    path = os.path.join(out_dir, "executive_summary.json")
    with open(path, "w") as f:
        json.dump(summary_data, f, indent=2, default=str)

    return path
