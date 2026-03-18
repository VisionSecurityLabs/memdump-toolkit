"""Run the complete analysis pipeline on a process dump.

Orchestrates all modules in sequence, parsing the dump ONCE:
  1. Extract all DLLs (listed + hidden)
  2. Detect injection indicators
  3. Analyze all binaries (universal + Go + .NET + config extraction)
  4. Hunt for C2 indicators in raw process memory
  5. Generate triage summary and IOC export
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from minidump.minidumpfile import MinidumpFile

from memdump_toolkit import extract_dlls, detect_injection, analyze_binary, c2_hunt, executive_summary
from memdump_toolkit.colors import (
    banner, bold, critical, dim, high, info, severity, success,
)
from memdump_toolkit.constants import HEAP_THRESHOLD_X64, SCORE_CRITICAL, SCORE_HIGH
from memdump_toolkit.pe_utils import logger, setup_logging

# Regex to strip ANSI escape codes for file output
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


class Tee:
    """Write to both a file and stdout, stripping ANSI colors from the file."""

    def __init__(self, filepath: str) -> None:
        self._filepath = filepath
        self.stdout = sys.stdout
        self.encoding = getattr(sys.stdout, "encoding", "utf-8")
        self.file: Any = None

    def __enter__(self) -> "Tee":
        self.file = open(self._filepath, "w")
        sys.stdout = self
        return self

    def __exit__(self, *args: Any) -> None:
        sys.stdout = self.stdout
        if self.file is not None:
            try:
                self.file.close()
            except Exception:
                pass

    def write(self, data: str) -> int:
        self.stdout.write(data)
        self.file.write(_ANSI_RE.sub("", data))
        return len(data)

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def fileno(self) -> int:
        return self.stdout.fileno()


def generate_triage_summary(
    out_dir: str, injection_report: dict | None,
    binary_results: list[dict],
    c2_results: dict | None = None,
) -> str:
    """Generate a prioritized triage summary cross-referencing all findings."""
    summary: dict[str, Any] = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "critical_findings": [],
        "high_findings": [],
        "statistics": {},
    }

    # Injection findings
    if injection_report and "findings" in injection_report:
        for f in injection_report["findings"]:
            finding_sev = f.get("severity", "INFO")
            entry = {
                "source": "injection_detection",
                "type": f["type"],
                "severity": finding_sev,
                "details": {k: v for k, v in f.items() if k not in ("type", "severity")},
            }
            if finding_sev == "CRITICAL":
                summary["critical_findings"].append(entry)
            elif finding_sev == "HIGH":
                summary["high_findings"].append(entry)

        sev_counts = Counter(f["severity"] for f in injection_report["findings"])
        type_counts = Counter(f["type"] for f in injection_report["findings"])
        summary["statistics"]["injection"] = {
            "by_severity": dict(sev_counts),
            "by_type": dict(type_counts),
        }

    # Universal binary analysis findings
    if binary_results:
        for r in binary_results:
            score = r.get("risk_score", 0)
            if score < 10:
                continue

            if score >= SCORE_CRITICAL:
                finding_sev = "CRITICAL"
            elif score >= SCORE_HIGH:
                finding_sev = "HIGH"
            else:
                continue  # MEDIUM findings don't go to triage

            lang = r.get("language") or "native"
            entry = {
                "source": "binary_analysis",
                "type": f"SUSPICIOUS_BINARY_{lang.upper()}",
                "severity": finding_sev,
                "details": {
                    "file": Path(r["file"]).name,
                    "source": r.get("source"),
                    "language": lang,
                    "risk_score": score,
                    "risk_factors": r.get("risk_factors", []),
                    "hashes": r.get("hashes", {}),
                    "offensive_tools": [
                        t["tool"] for t in r.get("offensive_tools", [])
                    ],
                },
            }

            # Enrich with language-specific details
            go = r.get("go_analysis", {})
            if go:
                entry["details"]["go_known_tools"] = go.get("known_tools", [])
                entry["details"]["go_capabilities"] = list(
                    go.get("capabilities", {}).keys()
                )

            dn = r.get("dotnet_analysis", {})
            if dn:
                meta = dn.get("metadata", {})
                entry["details"]["dotnet_assembly"] = meta.get("assembly_name")
                entry["details"]["dotnet_obfuscators"] = [
                    o["obfuscator"] for o in dn.get("obfuscators", [])
                ]

            if finding_sev == "CRITICAL":
                summary["critical_findings"].append(entry)
            else:
                summary["high_findings"].append(entry)

        # Statistics
        by_lang = Counter(
            r.get("language") or "native" for r in binary_results
        )
        by_severity = Counter(
            "CRITICAL" if r.get("risk_score", 0) >= SCORE_CRITICAL
            else "HIGH" if r.get("risk_score", 0) >= SCORE_HIGH
            else "MEDIUM" if r.get("risk_score", 0) >= 10
            else "LOW"
            for r in binary_results
        )
        summary["statistics"]["binary_analysis"] = {
            "total_analyzed": len(binary_results),
            "by_language": dict(by_lang),
            "by_severity": dict(by_severity),
        }

        # Config/IOC statistics from embedded config results
        configs = [r.get("config", {}) for r in binary_results if r.get("config")]
        if configs:
            total_urls = sum(
                len(c.get("network", {}).get("urls", [])) for c in configs
            )
            total_ips = sum(
                len(c.get("network", {}).get("ips", [])) for c in configs
            )
            summary["statistics"]["config_extraction"] = {
                "binaries_with_config": len(configs),
                "urls_found": total_urls,
                "ips_found": total_ips,
            }

    # C2 hunt findings
    if c2_results:
        c2_urls = c2_results.get("urls", [])
        c2_keys = c2_results.get("private_keys", [])
        c2_hosts = c2_results.get("hostnames", [])
        heap_uas = [
            e for e in c2_results.get("user_agents", [])
            if any(a < c2_results.get("heap_threshold", HEAP_THRESHOLD_X64) for a in e.get("addresses", []))
        ]

        if c2_urls or c2_keys:
            entry: dict[str, Any] = {
                "source": "c2_hunt",
                "type": "C2_INDICATORS",
                "severity": "CRITICAL",
                "details": {
                    "c2_urls": [e["value"] for e in c2_urls],
                    "c2_hostnames": [e["value"] for e in c2_hosts],
                    "private_keys": len(c2_keys),
                    "implant_user_agents": [e["value"][:120] for e in heap_uas],
                },
            }
            summary["critical_findings"].append(entry)

        summary["statistics"]["c2_hunt"] = {
            "segments_scanned": c2_results.get("segments_scanned", 0),
            "bytes_scanned": c2_results.get("bytes_scanned", 0),
            "urls_found": len(c2_urls),
            "hostnames_found": len(c2_hosts),
            "private_keys_found": len(c2_keys),
            "certificates_found": len(c2_results.get("certificates", [])),
            "implant_user_agents": len(heap_uas),
        }

    summary["critical_findings"].sort(key=lambda x: x.get("type", ""))
    summary["high_findings"].sort(key=lambda x: x.get("type", ""))

    path = os.path.join(out_dir, "triage_summary.json")
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    return path


def generate_ioc_csv(
    out_dir: str, binary_results: list[dict],
    injection_report: dict | None,
    c2_results: dict | None = None,
) -> tuple[str | None, int]:
    """Generate flat IOC CSV for SIEM ingestion."""
    iocs: list[dict[str, str]] = []

    for r in binary_results:
        source = Path(r.get("file", "unknown")).name
        score = r.get("risk_score", 0)

        # Hashes for suspicious binaries
        if score >= SCORE_HIGH:
            hashes = r.get("hashes", {})
            if hashes.get("md5"):
                iocs.append({"type": "md5", "value": hashes["md5"],
                             "context": f"risk={score}", "source": source})
            if hashes.get("sha256"):
                iocs.append({"type": "sha256", "value": hashes["sha256"],
                             "context": f"risk={score}", "source": source})

        # Offensive tools
        for t in r.get("offensive_tools", []):
            iocs.append({"type": "offensive_tool", "value": t["tool"],
                         "context": t.get("signature", ""), "source": source})

        # Go-specific IOCs
        go = r.get("go_analysis", {})
        net_iocs = go.get("network_iocs", {})
        if net_iocs.get("user_agent"):
            iocs.append({"type": "user_agent", "value": net_iocs["user_agent"],
                         "context": "", "source": source})
        for u in net_iocs.get("urls", []):
            iocs.append({"type": "url", "value": u, "context": "", "source": source})
        for p in net_iocs.get("named_pipes", []):
            iocs.append({"type": "named_pipe", "value": p,
                         "context": "", "source": source})
        for tool in go.get("known_tools", []):
            iocs.append({"type": "go_tool", "value": tool,
                         "context": "", "source": source})

        # .NET-specific IOCs
        dn = r.get("dotnet_analysis", {})
        for t in dn.get("offensive_tools", []):
            iocs.append({"type": "dotnet_tool",
                         "value": t.get("tool", ""),
                         "context": t.get("signature", ""),
                         "source": source})

        # Config-extracted IOCs
        config = r.get("config", {})
        net = config.get("network", {})
        for entry in net.get("ips", []):
            iocs.append({"type": "ip", "value": entry["ip"],
                         "context": entry.get("context", ""), "source": source})
        for u in net.get("urls", []):
            iocs.append({"type": "url", "value": u, "context": "", "source": source})
        for h in net.get("hostnames", []):
            iocs.append({"type": "hostname", "value": h,
                         "context": "", "source": source})
        for p in net.get("named_pipes", []):
            iocs.append({"type": "named_pipe", "value": p,
                         "context": "", "source": source})
        crypto = config.get("crypto", {})
        for k in crypto.get("possible_hex_keys", []):
            iocs.append({"type": "hex_key", "value": k,
                         "context": "", "source": source})
        c2 = config.get("c2", {})
        for ua in c2.get("user_agents", []):
            iocs.append({"type": "user_agent", "value": ua,
                         "context": "", "source": source})

    # C2 hunt IOCs
    if c2_results:
        for entry in c2_results.get("urls", []):
            iocs.append({"type": "c2_url", "value": entry["value"],
                         "context": f"seen {entry['count']}x in memory",
                         "source": "c2_hunt"})
        for entry in c2_results.get("hostnames", []):
            iocs.append({"type": "c2_hostname", "value": entry["value"],
                         "context": f"seen {entry['count']}x in memory",
                         "source": "c2_hunt"})
        for entry in c2_results.get("ip_ports", []):
            iocs.append({"type": "c2_ip_port", "value": entry["value"],
                         "context": f"seen {entry['count']}x in memory",
                         "source": "c2_hunt"})
        for entry in c2_results.get("named_pipes", []):
            iocs.append({"type": "c2_named_pipe", "value": entry["value"],
                         "context": "", "source": "c2_hunt"})
        # Heap User-Agents (likely implant)
        for entry in c2_results.get("user_agents", []):
            if any(a < c2_results.get("heap_threshold", HEAP_THRESHOLD_X64) for a in entry.get("addresses", [])):
                iocs.append({"type": "c2_user_agent",
                             "value": entry["value"][:200],
                             "context": "heap memory (likely implant)",
                             "source": "c2_hunt"})
        if c2_results.get("private_keys"):
            iocs.append({"type": "c2_private_key",
                         "value": f"{len(c2_results['private_keys'])} key(s) found",
                         "context": "PEM private key in process memory",
                         "source": "c2_hunt"})

    # Injection IOCs
    if injection_report:
        for f in injection_report.get("findings", []):
            if f.get("type") == "TYPOSQUATTING":
                iocs.append({"type": "typosquatting_dll",
                             "value": f.get("module", ""),
                             "context": f"mimics {f.get('similar_to', '')}",
                             "source": "injection_detection"})

    # Deduplicate
    seen: set[tuple[str, str]] = set()
    unique_iocs: list[dict[str, str]] = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    if unique_iocs:
        path = os.path.join(out_dir, "iocs.csv")
        with open(path, "w", newline="") as f:
            # Sanitize values for CSV (strip control chars, limit length)
            for ioc in unique_iocs:
                for key in ("value", "context", "source"):
                    v = ioc.get(key, "")
                    # Replace control characters and limit length
                    v = "".join(c if c.isprintable() else " " for c in str(v))
                    # Prevent CSV formula injection
                    if v and v[0] in ("=", "+", "-", "@"):
                        v = "'" + v
                    ioc[key] = v[:500]
            writer = csv.DictWriter(
                f, fieldnames=["type", "value", "context", "source"],
                quoting=csv.QUOTE_ALL, escapechar="\\",
            )
            writer.writeheader()
            writer.writerows(unique_iocs)
        return path, len(unique_iocs)

    return None, 0


def run(
    dump_path: str, out_dir: str | None = None,
    verbose: bool = False, yara_rules_dir: str | None = None,
) -> dict[str, Any]:
    """Full pipeline: parse dump once, run all modules, generate reports."""
    setup_logging(verbose)

    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(dump_path) or ".", "output")
    os.makedirs(out_dir, exist_ok=True)

    report_path = os.path.join(out_dir, "full_report.txt")

    with Tee(report_path):
        start = time.time()
        print(banner(f"{'#'*80}"))
        print(banner(f"# MEMORY DUMP FORENSIC ANALYSIS"))
        print(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"# Dump: {bold(dump_path)}")
        print(f"# Output: {out_dir}")
        if yara_rules_dir:
            print(f"# YARA rules: {yara_rules_dir}")
        print(banner(f"{'#'*80}"))

        # Parse dump ONCE
        print(f"\nParsing minidump...")
        mf = MinidumpFile.parse(dump_path)
        reader = mf.get_reader()
        print(success(f"  Parsed successfully.\n"))

        # Step 1: Extract DLLs
        print(f"\n{banner('='*80)}")
        print(banner(f"  STEP 1/5: EXTRACTING PE MODULES"))
        print(f"{banner('='*80)}\n")

        t1 = time.time()
        extract_dlls.analyze(mf, reader, out_dir)
        print(dim(f"\n  [Step 1 completed in {time.time()-t1:.1f}s]"))

        # Step 2: Detect Injection
        print(f"\n{banner('='*80)}")
        print(banner(f"  STEP 2/5: DETECTING INJECTION INDICATORS"))
        print(f"{banner('='*80)}\n")

        t2 = time.time()
        injection_report = detect_injection.analyze(mf, reader, out_dir)
        inj_json_path = os.path.join(out_dir, "injection_report.json")
        with open(inj_json_path, "w") as _f:
            json.dump(injection_report, _f, indent=2, default=str)
        print(dim(f"\n  [Step 2 completed in {time.time()-t2:.1f}s]"))

        # Step 3: Universal Binary Analysis
        print(f"\n{banner('='*80)}")
        print(banner(f"  STEP 3/5: ANALYZING ALL BINARIES"))
        print(f"{banner('='*80)}\n")

        t3 = time.time()
        binary_results: list[dict] = []
        try:
            binary_results = analyze_binary.analyze(
                mf, reader, out_dir, yara_rules_dir,
            )
        except Exception as e:
            print(critical(f"  Binary analysis failed: {e}"))
        print(dim(f"\n  [Step 3 completed in {time.time()-t3:.1f}s]"))

        # Step 4: C2 Hunt
        print(f"\n{banner('='*80)}")
        print(banner(f"  STEP 4/5: HUNTING FOR C2 INDICATORS IN PROCESS MEMORY"))
        print(f"{banner('='*80)}\n")

        t4 = time.time()
        c2_results: dict[str, Any] = {}
        try:
            mf.filename = dump_path
            is_32bit = injection_report.get("bitness", 64) == 32
            c2_results = c2_hunt.analyze(mf, reader, out_dir, is_32bit=is_32bit)
        except Exception as e:
            print(critical(f"  C2 hunt failed: {e}"))
        print(dim(f"\n  [Step 4 completed in {time.time()-t4:.1f}s]"))

        # Step 5: Triage Summary & IOC Export
        print(f"\n{banner('='*80)}")
        print(banner(f"  STEP 5/5: GENERATING TRIAGE SUMMARY & IOC EXPORT"))
        print(f"{banner('='*80)}\n")

        triage_path = generate_triage_summary(
            out_dir, injection_report, binary_results, c2_results,
        )
        print(f"  Triage summary: {triage_path}")

        ioc_path, ioc_count = generate_ioc_csv(
            out_dir, binary_results, injection_report, c2_results,
        )
        if ioc_path:
            print(f"  IOC export: {ioc_path} ({ioc_count} unique IOCs)")
        else:
            print(f"  No IOCs extracted.")

        # Print triage highlights
        try:
            with open(triage_path) as f:
                triage = json.load(f)
            crit = triage.get("critical_findings", [])
            high_findings = triage.get("high_findings", [])
            if crit or high_findings:
                print(f"\n  {bold('_'*70)}")
                print(bold(f"  TRIAGE HIGHLIGHTS"))
                print(f"  {bold('_'*70)}")
                if crit:
                    print(f"  {severity('CRITICAL')} findings: {bold(str(len(crit)))}")
                    for c in crit[:5]:
                        det = c.get("details", {})
                        label = (det.get("export_name") or det.get("file")
                                 or det.get("module", "") or c["type"])
                        print(critical(f"    !!! [{c['type']}] {label}"))
                        # Show C2 URLs inline for immediate analyst action
                        if c.get("type") == "C2_INDICATORS":
                            for url in det.get("c2_urls", [])[:5]:
                                print(critical(f"        → {url}"))
                            if det.get("private_keys"):
                                print(critical(f"        → {det['private_keys']} private key(s) in memory"))
                            for ua in det.get("implant_user_agents", [])[:2]:
                                print(high(f"        UA: {ua}"))
                if high_findings:
                    print(f"  {severity('HIGH')} findings: {bold(str(len(high_findings)))}")
                    for h in high_findings[:5]:
                        det = h.get("details", {})
                        label = det.get("file") or det.get("module", "") or h["type"]
                        print(high(f"     !  [{h['type']}] {label}"))
            else:
                print(success(f"\n  No CRITICAL or HIGH findings."))
        except Exception:
            logger.debug("Failed to parse triage file for highlights")

        # Executive Summary & ATT&CK Mapping
        try:
            exec_path = executive_summary.generate(
                out_dir, binary_results, c2_results, injection_report,
            )
            print(dim(f"  Executive summary: {exec_path}"))
        except Exception as e:
            print(critical(f"  Executive summary failed: {e}"))

        # Interactive HTML Report
        html_path = None
        try:
            from memdump_toolkit import html_report
            exec_data = None
            exec_json_path = os.path.join(out_dir, "executive_summary.json")
            if os.path.exists(exec_json_path):
                with open(exec_json_path) as f:
                    exec_data = json.load(f)
            triage_data = None
            if os.path.exists(triage_path):
                with open(triage_path) as f:
                    triage_data = json.load(f)
            html_path = html_report.generate(
                out_dir, binary_results, c2_results, injection_report, exec_data, triage_data,
            )
        except Exception as e:
            print(critical(f"  HTML report failed: {e}"))

        # Final Summary
        elapsed = time.time() - start
        print(f"\n\n{banner('#'*80)}")
        print(banner(f"# ANALYSIS COMPLETE"))
        print(f"# Total time: {bold(f'{elapsed:.1f}s')}")
        print(f"# Output directory: {out_dir}")
        print(f"#")
        print(f"# Files generated:")
        for root, dirs, files in os.walk(out_dir):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, out_dir)
                size = os.path.getsize(fpath)
                print(dim(f"#   {rel:50s} {size:>12,} bytes"))
        print(banner(f"{'#'*80}"))

    if html_path:
        print(f"\nHTML report: {html_path}")

    return {
        "injection_report": injection_report,
        "binary_results": binary_results,
        "c2_results": c2_results,
    }
