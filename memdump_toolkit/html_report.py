"""Generate an interactive HTML report from analysis results.

Produces a self-contained HTML file with embedded CSS and vanilla JavaScript.
No external dependencies -- works offline in any modern browser.
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from memdump_toolkit.constants import SCORE_CRITICAL, SCORE_HIGH, SCORE_MEDIUM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(value: Any) -> str:
    """HTML-escape any value, converting non-strings first."""
    return html.escape(str(value)) if value is not None else ""


def _severity_color(score: int) -> str:
    """Return CSS variable reference for a risk score."""
    if score >= SCORE_CRITICAL:
        return "var(--critical)"
    if score >= SCORE_HIGH:
        return "var(--high)"
    if score >= SCORE_MEDIUM:
        return "var(--medium)"
    return "var(--low)"


def _severity_label(score: int) -> str:
    if score >= SCORE_CRITICAL:
        return "CRITICAL"
    if score >= SCORE_HIGH:
        return "HIGH"
    if score >= SCORE_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _badge(label: str) -> str:
    """Return a severity badge <span>."""
    css_class = label.lower() if label.lower() in ("critical", "high", "medium", "low") else "low"
    return f'<span class="badge badge-{css_class}">{_esc(label)}</span>'


def _score_bar(score: int) -> str:
    """Inline risk score bar."""
    color = _severity_color(score)
    width = min(score, 100)
    return (
        f'<div class="score-bar">'
        f'<div class="score-fill" style="width:{width}%;background:{color}"></div>'
        f'<span>{_esc(score)}</span>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Section Builders
# ---------------------------------------------------------------------------

def _build_nav() -> str:
    """Sticky sidebar navigation."""
    links = [
        ("dashboard", "Dashboard"),
        ("binaries", "Binaries"),
        ("injection", "Injection"),
        ("c2", "C2 Indicators"),
        ("attack", "ATT&CK"),
        ("iocs", "IOCs"),
    ]
    items = "\n".join(
        f'        <a href="#{_esc(href)}" class="nav-link">{_esc(label)}</a>'
        for href, label in links
    )
    return f'<nav id="sidebar">\n    <div class="nav-title">memdump-toolkit</div>\n{items}\n</nav>'


def _build_dashboard(
    binary_results: list[dict],
    injection_report: dict | None,
    c2_results: dict | None,
) -> str:
    """Build dashboard summary cards."""
    total_binaries = len(binary_results)
    critical_count = sum(1 for r in binary_results if r.get("risk_score", 0) >= SCORE_CRITICAL)
    high_count = sum(1 for r in binary_results if SCORE_HIGH <= r.get("risk_score", 0) < SCORE_CRITICAL)

    ioc_count = 0
    if c2_results:
        for key in ("urls", "hostnames", "ip_ports", "private_keys", "named_pipes"):
            ioc_count += len(c2_results.get(key, []))

    cards = [
        ("Total Binaries", str(total_binaries), "var(--accent)"),
        ("Critical", str(critical_count), "var(--critical)"),
        ("High", str(high_count), "var(--high)"),
        ("IOCs Found", str(ioc_count), "var(--medium)"),
    ]

    card_html = "\n".join(
        f'        <div class="card">'
        f'<div class="card-number" style="color:{color}">{_esc(number)}</div>'
        f'<div class="card-label">{_esc(label)}</div>'
        f'</div>'
        for label, number, color in cards
    )

    # Severity distribution bar
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in binary_results:
        sev_counts[_severity_label(r.get("risk_score", 0))] += 1

    total = max(sum(sev_counts.values()), 1)
    bar_segments = ""
    for label, css_var in [("CRITICAL", "--critical"), ("HIGH", "--high"),
                           ("MEDIUM", "--medium"), ("LOW", "--low")]:
        count = sev_counts[label]
        pct = (count / total) * 100
        if count > 0:
            bar_segments += (
                f'<div class="dist-segment" style="width:{pct:.1f}%;background:var({css_var})"'
                f' title="{_esc(label)}: {count}">{count}</div>'
            )

    return f"""
    <section id="dashboard">
        <h2>Dashboard</h2>
        <div class="card-grid">
{card_html}
        </div>
        <h3>Severity Distribution</h3>
        <div class="dist-bar">{bar_segments}</div>
        <div class="dist-legend">
            <span><span class="dot" style="background:var(--critical)"></span>Critical</span>
            <span><span class="dot" style="background:var(--high)"></span>High</span>
            <span><span class="dot" style="background:var(--medium)"></span>Medium</span>
            <span><span class="dot" style="background:var(--low)"></span>Low</span>
        </div>
    </section>"""


def _build_binary_detail(r: dict) -> str:
    """Build the hidden detail row content for a single binary."""
    parts: list[str] = []

    # Hashes
    hashes = r.get("hashes", {})
    if hashes:
        rows = "".join(
            f"<tr><td>{_esc(k)}</td><td class='mono'>{_esc(v)}</td></tr>"
            for k, v in hashes.items() if v
        )
        if rows:
            parts.append(f"<div class='detail-block'><h4>Hashes</h4><table class='detail-table'>{rows}</table></div>")

    # PE info
    pe = r.get("pe_info", {})
    if pe:
        pe_rows = ""
        for k, v in pe.items():
            if v is not None and k not in ("imports", "exports"):
                pe_rows += f"<tr><td>{_esc(k)}</td><td class='mono'>{_esc(v)}</td></tr>"
        if pe_rows:
            parts.append(f"<div class='detail-block'><h4>PE Info</h4><table class='detail-table'>{pe_rows}</table></div>")

    # YARA matches
    yara = r.get("yara_matches", [])
    if yara:
        yara_items = "".join(f"<li>{_esc(y)}</li>" for y in yara)
        parts.append(f"<div class='detail-block'><h4>YARA Matches</h4><ul>{yara_items}</ul></div>")

    # Offensive tools
    tools = r.get("offensive_tools", [])
    if tools:
        tool_items = "".join(
            f"<li>{_esc(t.get('tool', ''))} &mdash; {_esc(t.get('signature', ''))}</li>"
            for t in tools
        )
        parts.append(f"<div class='detail-block'><h4>Offensive Tools</h4><ul>{tool_items}</ul></div>")

    # Go analysis
    go = r.get("go_analysis", {})
    if go:
        go_parts: list[str] = []
        if go.get("known_tools"):
            go_parts.append(f"<p><strong>Known Tools:</strong> {_esc(', '.join(go['known_tools']))}</p>")
        caps = go.get("capabilities", {})
        if isinstance(caps, dict) and caps:
            cap_items = "".join(f"<li>{_esc(k)}</li>" for k in caps)
            go_parts.append(f"<p><strong>Capabilities:</strong></p><ul>{cap_items}</ul>")
        elif isinstance(caps, list) and caps:
            cap_items = "".join(f"<li>{_esc(c)}</li>" for c in caps)
            go_parts.append(f"<p><strong>Capabilities:</strong></p><ul>{cap_items}</ul>")
        net_iocs = go.get("network_iocs", {})
        if net_iocs:
            for key in ("urls", "named_pipes"):
                items = net_iocs.get(key, [])
                if items:
                    li = "".join(f"<li class='mono'>{_esc(i)}</li>" for i in items)
                    go_parts.append(f"<p><strong>{_esc(key)}:</strong></p><ul>{li}</ul>")
        if go_parts:
            parts.append(f"<div class='detail-block'><h4>Go Analysis</h4>{''.join(go_parts)}</div>")

    # .NET analysis
    dn = r.get("dotnet_analysis", {})
    if dn:
        dn_parts: list[str] = []
        meta = dn.get("metadata", {})
        if meta:
            meta_rows = "".join(
                f"<tr><td>{_esc(k)}</td><td class='mono'>{_esc(v)}</td></tr>"
                for k, v in meta.items() if v
            )
            if meta_rows:
                dn_parts.append(f"<table class='detail-table'>{meta_rows}</table>")
        obfs = dn.get("obfuscators", [])
        if obfs:
            obf_items = "".join(f"<li>{_esc(o.get('obfuscator', ''))}</li>" for o in obfs)
            dn_parts.append(f"<p><strong>Obfuscators:</strong></p><ul>{obf_items}</ul>")
        if dn_parts:
            parts.append(f"<div class='detail-block'><h4>.NET Analysis</h4>{''.join(dn_parts)}</div>")

    # Config extraction
    config = r.get("config", {})
    if config:
        net_cfg = config.get("network", {})
        cfg_parts: list[str] = []
        for key in ("urls", "ips", "hostnames", "named_pipes"):
            items = net_cfg.get(key, [])
            if items:
                if key == "ips":
                    li = "".join(f"<li class='mono'>{_esc(i.get('ip', i) if isinstance(i, dict) else i)}</li>" for i in items)
                else:
                    li = "".join(f"<li class='mono'>{_esc(i)}</li>" for i in items)
                cfg_parts.append(f"<p><strong>{_esc(key)}:</strong></p><ul>{li}</ul>")
        if cfg_parts:
            parts.append(f"<div class='detail-block'><h4>Extracted Config</h4>{''.join(cfg_parts)}</div>")

    # Risk factors
    factors = r.get("risk_factors", [])
    if factors:
        factor_items = "".join(f"<li>{_esc(f)}</li>" for f in factors)
        parts.append(f"<div class='detail-block'><h4>Risk Factors</h4><ul>{factor_items}</ul></div>")

    return f"<div class='detail-content'>{''.join(parts)}</div>" if parts else "<div class='detail-content'><p class='dim'>No additional details.</p></div>"


def _build_binary_table(binary_results: list[dict]) -> str:
    """Build the sortable binary analysis table."""
    if not binary_results:
        return '<section id="binaries"><h2>Binary Analysis</h2><p class="dim">No binaries analyzed.</p></section>'

    rows = ""
    for idx, r in enumerate(sorted(binary_results, key=lambda x: x.get("risk_score", 0), reverse=True)):
        fname = _esc(Path(r.get("file", "unknown")).name)
        source = _esc(r.get("source", ""))
        lang = _esc(r.get("language") or "native")
        score = r.get("risk_score", 0)
        sev = _severity_label(score)
        factors = r.get("risk_factors", [])
        factors_str = _esc(", ".join(factors[:3]))
        if len(factors) > 3:
            factors_str += f" (+{len(factors) - 3})"

        rows += f"""
            <tr class="summary-row" data-idx="{idx}" onclick="toggleDetail({idx})">
                <td>{fname}</td>
                <td>{source}</td>
                <td>{lang}</td>
                <td data-sort="{score}">{_score_bar(score)}</td>
                <td>{_badge(sev)}</td>
                <td>{factors_str}</td>
            </tr>
            <tr class="detail-row" id="detail-{idx}" style="display:none">
                <td colspan="6">{_build_binary_detail(r)}</td>
            </tr>"""

    return f"""
    <section id="binaries">
        <h2>Binary Analysis</h2>
        <div class="filter-bar">
            <input type="text" id="binaryFilter" placeholder="Filter binaries..." oninput="filterTable()">
        </div>
        <div class="table-wrap">
            <table id="binaryTable" class="data-table">
                <thead>
                    <tr>
                        <th onclick="sortTable(0,'str')">File</th>
                        <th onclick="sortTable(1,'str')">Source</th>
                        <th onclick="sortTable(2,'str')">Language</th>
                        <th onclick="sortTable(3,'num')">Risk Score</th>
                        <th onclick="sortTable(4,'str')">Severity</th>
                        <th>Risk Factors</th>
                    </tr>
                </thead>
                <tbody>{rows}
                </tbody>
            </table>
        </div>
    </section>"""


def _build_injection_section(injection_report: dict | None) -> str:
    """Build injection findings section."""
    if not injection_report or not injection_report.get("findings"):
        return '<section id="injection"><h2>Injection Findings</h2><p class="dim">No injection indicators detected.</p></section>'

    rows = ""
    for f in injection_report["findings"]:
        ftype = _esc(f.get("type", ""))
        sev = f.get("severity", "INFO")
        module = _esc(f.get("module", f.get("identity", "")))
        base = _esc(f.get("base", ""))
        detail_parts = []
        for k, v in f.items():
            if k not in ("type", "severity", "module", "base", "identity"):
                detail_parts.append(f"{_esc(k)}: {_esc(v)}")
        details = _esc("; ".join(detail_parts[:5]))

        rows += f"""
            <tr>
                <td>{ftype}</td>
                <td>{_badge(sev)}</td>
                <td>{module}</td>
                <td class="mono">{base}</td>
                <td class="truncate">{details}</td>
            </tr>"""

    return f"""
    <section id="injection">
        <h2>Injection Findings</h2>
        <div class="table-wrap">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Module</th>
                        <th>Base Address</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>{rows}
                </tbody>
            </table>
        </div>
    </section>"""


def _build_c2_section(c2_results: dict | None) -> str:
    """Build C2 indicators section."""
    if not c2_results:
        return '<section id="c2"><h2>C2 Indicators</h2><p class="dim">No C2 indicators found.</p></section>'

    sections: list[str] = []

    def _make_table(title: str, key: str, value_key: str = "value") -> str:
        items = c2_results.get(key, [])
        if not items:
            return ""
        rows = ""
        for entry in items:
            if isinstance(entry, dict):
                val = _esc(entry.get(value_key, str(entry)))
                count = entry.get("count", "")
                rows += f"<tr><td class='mono'>{val}</td><td>{_esc(count)}</td></tr>"
            else:
                rows += f"<tr><td class='mono'>{_esc(entry)}</td><td></td></tr>"
        return f"""
        <div class="c2-group">
            <h3>{_esc(title)}</h3>
            <table class="data-table">
                <thead><tr><th>Value</th><th>Count</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    sections.append(_make_table("URLs", "urls"))
    sections.append(_make_table("Hostnames", "hostnames"))
    sections.append(_make_table("IP:Port", "ip_ports"))

    # Private keys
    keys = c2_results.get("private_keys", [])
    if keys:
        sections.append(
            f'<div class="c2-group"><h3>Private Keys</h3>'
            f'<p class="critical-text">{_esc(len(keys))} private key(s) found in process memory</p></div>'
        )

    # User agents
    uas = c2_results.get("user_agents", [])
    if uas:
        ua_rows = ""
        for entry in uas:
            val = _esc(entry.get("value", "")[:200]) if isinstance(entry, dict) else _esc(str(entry)[:200])
            ua_rows += f"<tr><td class='mono truncate'>{val}</td></tr>"
        sections.append(
            f'<div class="c2-group"><h3>User Agents</h3>'
            f'<table class="data-table"><thead><tr><th>Value</th></tr></thead>'
            f'<tbody>{ua_rows}</tbody></table></div>'
        )

    content = "\n".join(s for s in sections if s)
    return f"""
    <section id="c2">
        <h2>C2 Indicators</h2>
        {content}
    </section>"""


def _build_attack_section(executive_data: dict | None) -> str:
    """Build MITRE ATT&CK coverage section."""
    if not executive_data:
        return '<section id="attack"><h2>MITRE ATT&CK Coverage</h2><p class="dim">No executive data available.</p></section>'

    groups = executive_data.get("mitre_attack_by_binary", [])
    if not groups:
        return '<section id="attack"><h2>MITRE ATT&CK Coverage</h2><p class="dim">No techniques mapped.</p></section>'

    tables = ""
    for group in groups:
        binary_name = _esc(group.get("binary", "unknown"))
        risk = group.get("risk_score", 0)
        lang = _esc(group.get("language", ""))
        title = f"{binary_name}"
        if risk > 0:
            title += f" (risk={risk}/100, {lang})"

        rows = ""
        current_tactic = ""
        for t in group.get("techniques", []):
            tactic = t.get("tactic", "")
            tactic_cell = ""
            if tactic != current_tactic:
                current_tactic = tactic
                tactic_cell = _esc(tactic)

            rows += f"""
                <tr>
                    <td class="tactic-cell">{tactic_cell}</td>
                    <td class="mono">{_esc(t.get('technique_id', ''))}</td>
                    <td>{_esc(t.get('technique_name', ''))}</td>
                    <td class="dim">{_esc(t.get('evidence', ''))}</td>
                </tr>"""

        tables += f"""
        <div class="attack-group">
            <h3>{title}</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Tactic</th>
                        <th>ID</th>
                        <th>Technique</th>
                        <th>Evidence</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    return f"""
    <section id="attack">
        <h2>MITRE ATT&CK Coverage</h2>
        {tables}
    </section>"""


def _build_ioc_section(
    binary_results: list[dict],
    c2_results: dict | None,
    injection_report: dict | None,
) -> str:
    """Build IOC export table with copy buttons."""
    iocs: list[tuple[str, str, str]] = []  # (type, value, source)

    for r in binary_results:
        fname = Path(r.get("file", "unknown")).name
        score = r.get("risk_score", 0)

        if score >= SCORE_HIGH:
            hashes = r.get("hashes", {})
            for algo in ("md5", "sha1", "sha256"):
                h = hashes.get(algo)
                if h:
                    iocs.append((algo, h, fname))

        for t in r.get("offensive_tools", []):
            iocs.append(("offensive_tool", t.get("tool", ""), fname))

        go = r.get("go_analysis", {})
        for t in go.get("known_tools", []):
            iocs.append(("go_tool", t, fname))

        config = r.get("config", {})
        net = config.get("network", {})
        for u in net.get("urls", []):
            iocs.append(("url", u, fname))
        for ip_entry in net.get("ips", []):
            ip_val = ip_entry.get("ip", ip_entry) if isinstance(ip_entry, dict) else ip_entry
            iocs.append(("ip", str(ip_val), fname))

    if c2_results:
        for entry in c2_results.get("urls", []):
            iocs.append(("c2_url", entry.get("value", ""), "c2_hunt"))
        for entry in c2_results.get("hostnames", []):
            iocs.append(("c2_hostname", entry.get("value", ""), "c2_hunt"))
        for entry in c2_results.get("ip_ports", []):
            iocs.append(("c2_ip_port", entry.get("value", ""), "c2_hunt"))

    if injection_report:
        for f in injection_report.get("findings", []):
            if f.get("type") == "TYPOSQUATTING":
                iocs.append(("typosquatting", f.get("module", ""), "injection"))

    # Deduplicate
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str, str]] = []
    for ioc_type, ioc_val, ioc_src in iocs:
        key = (ioc_type, ioc_val)
        if key not in seen and ioc_val:
            seen.add(key)
            unique.append((ioc_type, ioc_val, ioc_src))

    if not unique:
        return '<section id="iocs"><h2>IOC Export</h2><p class="dim">No IOCs extracted.</p></section>'

    rows = ""
    for idx, (ioc_type, ioc_val, ioc_src) in enumerate(unique):
        rows += f"""
            <tr>
                <td>{_badge(ioc_type)}</td>
                <td class="mono truncate" id="ioc-val-{idx}">{_esc(ioc_val)}</td>
                <td>{_esc(ioc_src)}</td>
                <td><button class="copy-btn" onclick="copyIOC({idx})">Copy</button></td>
            </tr>"""

    return f"""
    <section id="iocs">
        <h2>IOC Export ({len(unique)})</h2>
        <div class="table-wrap">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Source</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </section>"""


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """\
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --border: #30363d;
    --critical: #ff4444;
    --high: #ff8800;
    --medium: #e3b341;
    --low: #8b949e;
    --accent: #58a6ff;
    --font-mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.6;
    display: flex;
    min-height: 100vh;
}

#sidebar {
    position: fixed;
    top: 0; left: 0;
    width: 200px;
    height: 100vh;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    padding: 24px 0;
    display: flex;
    flex-direction: column;
    z-index: 100;
    overflow-y: auto;
}

.nav-title {
    font-size: 15px;
    font-weight: 700;
    color: var(--accent);
    padding: 0 20px 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 8px;
    font-family: var(--font-mono);
}

.nav-link {
    display: block;
    padding: 8px 20px;
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 13px;
    transition: color 0.15s, background 0.15s;
}
.nav-link:hover {
    color: var(--text-primary);
    background: var(--bg-tertiary);
}

#main {
    margin-left: 200px;
    flex: 1;
    padding: 32px 40px;
    max-width: 1400px;
}

.report-header {
    margin-bottom: 32px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 24px;
}
.report-header h1 {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 8px;
}
.report-header .meta {
    color: var(--text-secondary);
    font-size: 13px;
    font-family: var(--font-mono);
}

section {
    margin-bottom: 40px;
}
section h2 {
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    color: var(--accent);
}
section h3 {
    font-size: 15px;
    font-weight: 600;
    margin: 16px 0 8px;
    color: var(--text-primary);
}

/* Cards */
.card-grid {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 24px;
}
.card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 28px;
    min-width: 160px;
    flex: 1;
    text-align: center;
}
.card-number {
    font-size: 36px;
    font-weight: 800;
    font-family: var(--font-mono);
    line-height: 1.2;
}
.card-label {
    font-size: 13px;
    color: var(--text-secondary);
    margin-top: 4px;
}

/* Severity distribution bar */
.dist-bar {
    display: flex;
    height: 28px;
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 8px;
    background: var(--bg-tertiary);
}
.dist-segment {
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 700;
    color: var(--bg-primary);
    min-width: 24px;
}
.dist-legend {
    display: flex;
    gap: 16px;
    font-size: 12px;
    color: var(--text-secondary);
}
.dot {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 4px;
    vertical-align: middle;
}

/* Tables */
.table-wrap { overflow-x: auto; }
.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.data-table thead th {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-weight: 600;
    text-align: left;
    padding: 10px 12px;
    border-bottom: 2px solid var(--border);
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
}
.data-table thead th:hover { color: var(--accent); }
.data-table tbody td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}
.data-table tbody tr:hover:not(.detail-row) {
    background: var(--bg-tertiary);
}
.summary-row { cursor: pointer; }

/* Score bar */
.score-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 100px;
}
.score-bar > div:first-child {
    flex: 1;
    height: 6px;
    background: var(--bg-tertiary);
    border-radius: 3px;
    overflow: hidden;
}
.score-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.3s;
}
.score-bar span {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
    min-width: 24px;
    text-align: right;
}

/* Badges */
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    font-family: var(--font-mono);
    text-transform: uppercase;
}
.badge-critical { background: rgba(255,68,68,0.15); color: var(--critical); }
.badge-high { background: rgba(255,136,0,0.15); color: var(--high); }
.badge-medium { background: rgba(227,179,65,0.15); color: var(--medium); }
.badge-low { background: rgba(139,148,158,0.15); color: var(--low); }
.badge-info { background: rgba(88,166,255,0.15); color: var(--accent); }

/* Detail rows */
.detail-row td { padding: 0 !important; }
.detail-content {
    padding: 16px 24px;
    background: var(--bg-secondary);
    border-left: 3px solid var(--accent);
}
.detail-block {
    margin-bottom: 16px;
}
.detail-block h4 {
    font-size: 13px;
    font-weight: 700;
    color: var(--accent);
    margin-bottom: 6px;
}
.detail-table {
    width: auto;
    border-collapse: collapse;
    font-size: 12px;
    margin-bottom: 8px;
}
.detail-table td {
    padding: 3px 12px 3px 0;
    border: none;
    vertical-align: top;
}
.detail-table td:first-child {
    color: var(--text-secondary);
    font-weight: 600;
    white-space: nowrap;
}
.detail-content ul {
    list-style: none;
    padding-left: 0;
}
.detail-content li {
    padding: 2px 0;
    font-size: 12px;
}
.detail-content li::before {
    content: "\\2022  ";
    color: var(--text-secondary);
}

/* Filter bar */
.filter-bar { margin-bottom: 12px; }
.filter-bar input {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-primary);
    padding: 8px 14px;
    font-size: 13px;
    width: 300px;
    outline: none;
    font-family: var(--font-sans);
}
.filter-bar input:focus { border-color: var(--accent); }

/* C2 groups */
.c2-group { margin-bottom: 20px; }
.critical-text { color: var(--critical); font-weight: 700; }

/* ATT&CK */
.attack-group { margin-bottom: 24px; }
.tactic-cell { font-weight: 600; color: var(--accent); white-space: nowrap; }

/* Copy button */
.copy-btn {
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-secondary);
    padding: 3px 10px;
    font-size: 11px;
    cursor: pointer;
    font-family: var(--font-mono);
    transition: background 0.15s, color 0.15s;
}
.copy-btn:hover { background: var(--accent); color: var(--bg-primary); }

/* Utility */
.mono { font-family: var(--font-mono); font-size: 12px; }
.dim { color: var(--text-secondary); }
.truncate {
    max-width: 400px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

/* Footer */
.report-footer {
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    color: var(--text-secondary);
    font-size: 12px;
    text-align: center;
}

/* Responsive */
@media (max-width: 900px) {
    #sidebar { display: none; }
    #main { margin-left: 0; padding: 16px; }
    .card-grid { flex-direction: column; }
    .filter-bar input { width: 100%; }
}
"""


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

_JS = """\
function toggleDetail(idx) {
    var row = document.getElementById('detail-' + idx);
    if (!row) return;
    row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}

function filterTable() {
    var input = document.getElementById('binaryFilter');
    if (!input) return;
    var filter = input.value.toLowerCase();
    var table = document.getElementById('binaryTable');
    if (!table) return;
    var rows = table.querySelectorAll('tbody tr.summary-row');
    rows.forEach(function(row) {
        var text = row.textContent.toLowerCase();
        var idx = row.getAttribute('data-idx');
        var detail = document.getElementById('detail-' + idx);
        if (text.indexOf(filter) > -1) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
            if (detail) detail.style.display = 'none';
        }
    });
}

var sortState = {};
function sortTable(colIdx, type) {
    var table = document.getElementById('binaryTable');
    if (!table) return;
    var tbody = table.querySelector('tbody');
    var summaryRows = Array.from(tbody.querySelectorAll('tr.summary-row'));

    var dir = sortState[colIdx] === 'asc' ? 'desc' : 'asc';
    sortState[colIdx] = dir;

    summaryRows.sort(function(a, b) {
        var aCell = a.children[colIdx];
        var bCell = b.children[colIdx];
        var aVal, bVal;
        if (type === 'num') {
            aVal = parseFloat(aCell.getAttribute('data-sort') || aCell.textContent) || 0;
            bVal = parseFloat(bCell.getAttribute('data-sort') || bCell.textContent) || 0;
        } else {
            aVal = aCell.textContent.trim().toLowerCase();
            bVal = bCell.textContent.trim().toLowerCase();
        }
        if (aVal < bVal) return dir === 'asc' ? -1 : 1;
        if (aVal > bVal) return dir === 'asc' ? 1 : -1;
        return 0;
    });

    summaryRows.forEach(function(row) {
        var idx = row.getAttribute('data-idx');
        var detail = document.getElementById('detail-' + idx);
        tbody.appendChild(row);
        if (detail) tbody.appendChild(detail);
    });
}

function copyIOC(idx) {
    var el = document.getElementById('ioc-val-' + idx);
    if (!el) return;
    var text = el.textContent;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function() {
            showCopyFeedback(idx);
        });
    } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showCopyFeedback(idx);
    }
}

function showCopyFeedback(idx) {
    var btn = document.querySelector('tr:has(#ioc-val-' + idx + ') .copy-btn');
    if (!btn) {
        var el = document.getElementById('ioc-val-' + idx);
        if (el) btn = el.closest('tr').querySelector('.copy-btn');
    }
    if (btn) {
        var orig = btn.textContent;
        btn.textContent = 'Copied';
        btn.style.background = 'var(--accent)';
        btn.style.color = 'var(--bg-primary)';
        setTimeout(function() {
            btn.textContent = orig;
            btn.style.background = '';
            btn.style.color = '';
        }, 1200);
    }
}
"""


# ---------------------------------------------------------------------------
# Main Generator
# ---------------------------------------------------------------------------

def generate(
    out_dir: str,
    binary_results: list[dict],
    c2_results: dict | None = None,
    injection_report: dict | None = None,
    executive_data: dict | None = None,
) -> str:
    """Generate interactive HTML report.

    Args:
        out_dir: Output directory.
        binary_results: Results from analyze_binary.analyze().
        c2_results: Results from c2_hunt.analyze().
        injection_report: Results from detect_injection.analyze().
        executive_data: Executive summary JSON (loaded from executive_summary.json).

    Returns:
        Path to generated HTML file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dump_name = ""
    if injection_report and injection_report.get("dump"):
        dump_name = Path(injection_report["dump"]).name

    nav = _build_nav()
    dashboard = _build_dashboard(binary_results, injection_report, c2_results)
    binaries = _build_binary_table(binary_results)
    injection = _build_injection_section(injection_report)
    c2 = _build_c2_section(c2_results)
    attack = _build_attack_section(executive_data)
    iocs = _build_ioc_section(binary_results, c2_results, injection_report)

    dump_line = f'<div class="meta">Dump: {_esc(dump_name)}</div>' if dump_name else ""

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>memdump-toolkit Report</title>
    <style>
{_CSS}
    </style>
</head>
<body>
    {nav}
    <div id="main">
        <div class="report-header">
            <h1>Memory Dump Forensic Analysis</h1>
            <div class="meta">Generated: {_esc(timestamp)}</div>
            {dump_line}
        </div>
{dashboard}
{binaries}
{injection}
{c2}
{attack}
{iocs}
        <div class="report-footer">
            Generated by memdump-toolkit &middot; {_esc(timestamp)}
        </div>
    </div>
    <script>
{_JS}
    </script>
</body>
</html>"""

    path = os.path.join(out_dir, "report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    return path
