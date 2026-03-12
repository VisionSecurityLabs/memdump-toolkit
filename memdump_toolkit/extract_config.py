"""Extract embedded configuration from implant binaries."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from memdump_toolkit.constants import MAX_SCAN_SIZE, PAGE_SIZE
from memdump_toolkit.pe_utils import (
    check_pe_header, compute_hashes, get_known_bases, get_pe_info, logger,
    read_pe_data, scan_with_yara, setup_logging,
)

# Pre-compiled regex for string extraction (hot path, default min_len=6)
_RE_ASCII = re.compile(rb'[\x20-\x7e]{6,500}')
_RE_UTF16 = re.compile(r'[\x20-\x7e]{6,500}')

# Pre-compiled network-detection regexes (moved from extract_network_config hot loop)
_ip_re = re.compile(
    r'(?:^|(?<=[\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]))'  # non-alnum before
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?=$|[^0-9.])',                                          # non-digit/dot after
)
_url_re = re.compile(
    r'((?:https?|wss?|socks[45]?|tcp|udp)://'
    r'(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'       # IP address
    r'|[a-zA-Z0-9][\w\-]*\.[a-zA-Z]{2,})'           # or dotted hostname
    r'(?::\d{1,5})?'                                  # optional port
    r'(?:[/\w\.\-:?&=@#%]*)?)',                       # optional path/query
)
_host_re = re.compile(
    r'(?:^|(?<=[^a-zA-Z0-9]))'   # must be preceded by non-alnum or start
    r'([a-zA-Z][\w\-]{1,60}\.(?:com|net|org|io|dev|me|co|info|biz|xyz|top|cc|tk|ml|ga|cf|onion))'
    r'(?=$|[^a-zA-Z0-9])',         # must be followed by non-alnum or end
)

# IPs to filter out (loopback, link-local, common version-like patterns)
_FILTERED_IP_PREFIXES = (0, 127, 169)


def extract_strings(data: bytes, min_len: int = 6) -> tuple[set[str], set[str]]:
    """Extract ASCII and UTF-16 strings."""
    # Use pre-compiled module-level constants for the common case (min_len=6),
    # fall back to dynamic compilation for non-default values.
    if min_len == 6:
        re_ascii = _RE_ASCII
        re_utf16 = _RE_UTF16
    else:
        re_ascii = re.compile(rb'[\x20-\x7e]{' + f'{min_len},500'.encode() + rb'}')
        re_utf16 = re.compile(r'[\x20-\x7e]{' + f'{min_len},500' + r'}')
    ascii_strings: set[str] = set()
    for m in re_ascii.finditer(data):
        ascii_strings.add(m.group().decode("ascii"))

    utf16_strings: set[str] = set()
    decode_limit = min(len(data), 2 * 1024 * 1024)
    try:
        text16 = data[:decode_limit].decode("utf-16-le", errors="ignore")
        for m in re_utf16.finditer(text16):
            s = m.group()
            if s not in ascii_strings:
                utf16_strings.add(s)
    except Exception:
        logger.debug("UTF-16 string extraction failed")

    return ascii_strings, utf16_strings


def extract_network_config(data: bytes, all_strings: set[str]) -> dict[str, Any]:
    """Extract network-related configuration."""
    config: dict[str, Any] = {}
    joined = "\n".join(all_strings)

    # IPs — search per-string to validate boundaries and filter noise.
    # Go binaries embed X.509 OID sequences (2.5.4.6, 2.5.4.3, ...) and
    # TLS version numbers that produce false-positive IPs.
    ips: set[tuple[str, str]] = set()
    for s in all_strings:
        for m in _ip_re.finditer(s):
            ip = m.group(1)
            octets = [int(o) for o in ip.split(".")]
            if not all(0 <= o <= 255 for o in octets):
                continue
            if octets[0] in _FILTERED_IP_PREFIXES:
                continue
            # Skip IPs embedded in crypto/tls, ASN.1 OID, or error message contexts
            ctx_start = max(0, m.start() - 60)
            context = s[ctx_start:m.end() + 60]
            if any(kw in context for kw in ("crypto/tls", "marshal.func",
                                             "SHA-", "2.5.4", "Ed25519",
                                             "expected opts", "Bad Request")):
                continue
            # Skip small-octet IPs that look like version numbers (1.2.1.1)
            if all(o < 10 for o in octets):
                continue
            # Skip IPs where 3+ octets are 0 (e.g. 134.0.0.0 — not real)
            if sum(1 for o in octets if o == 0) >= 3:
                continue
            ips.add((ip, s[:120] if len(s) > len(ip) + 2 else ""))
    config["ips"] = [{"ip": ip, "context": ctx} for ip, ctx in sorted(ips)]

    # IP:port combinations
    ip_ports: set[str] = set()
    for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})\b', joined):
        ip_ports.add(m.group(1))
    config["ip_ports"] = sorted(ip_ports)

    # URLs — require a valid hostname (dotted domain or IP) after the scheme.
    # Go binaries concatenate strings without null terminators, so bare
    # "http://" can run into random symbol names producing garbage URLs.
    urls: set[str] = set()
    for s in all_strings:
        for m in _url_re.finditer(s):
            urls.add(m.group(1))
    config["urls"] = sorted(urls)

    # Hostnames / FQDNs
    # Match hostnames within each individual string to avoid cross-string
    # boundary issues.  Validate that the label preceding the TLD looks like
    # a real hostname component (not a concatenation artifact from Go binaries
    # where strings are packed without null terminators, producing things like
    # "capturegolang.org").
    # Domains that are Go packages / infrastructure — not C2 servers.
    # Keep them out of the hostname IOC list to reduce analyst noise.
    _GO_INFRA_DOMAINS = {
        "golang.org", "github.com", "google.com", "googleapis.com",
        "nhooyr.io",   # Go WebSocket library (pkg.go.dev/nhooyr.io/websocket)
        "gopkg.in", "go.dev",
    }
    _KNOWN_DOMAINS = _GO_INFRA_DOMAINS
    hostnames: set[str] = set()
    for s in all_strings:
        for m in _host_re.finditer(s):
            hostname = m.group(1)
            # Accept known domains as-is (e.g. "github.com")
            if hostname.lower() in _KNOWN_DOMAINS:
                hostnames.add(hostname)
                continue
            # Reject very short labels (likely concatenation noise)
            label = hostname.split(".")[0].lower()
            if len(label) < 3:
                continue
            # Reject if the first label contains a known domain suffix
            # (concatenation artifact: "capturegolang" contains "golang")
            if any(d.split(".")[0] in label and label != d.split(".")[0]
                   for d in _KNOWN_DOMAINS):
                continue
            hostnames.add(hostname)
    config["hostnames"] = sorted(hostnames)

    # Named pipes
    pipes: set[str] = set()
    for m in re.finditer(r'(\\\\.\\pipe\\[\w\-\.]+)', joined):
        pipes.add(m.group(1))
    config["named_pipes"] = sorted(pipes)

    # UNC paths — require at least a server + share component, and the
    # server portion must look like a hostname or IP (not "." or short noise).
    unc: set[str] = set()
    for s in all_strings:
        for m in re.finditer(r'(\\\\[\w\.\-]{3,}\\[\w\$\-]{2,}(?:\\[\w\.\-]+)*)', s):
            path = m.group(1)
            server = path.split("\\")[2]  # \\server\share → server
            if server in (".", ".."):
                continue
            unc.add(path)
    config["unc_paths"] = sorted(unc)

    # Ports
    ports: set[int] = set()
    for m in re.finditer(r':(\d{2,5})\b', joined):
        port = int(m.group(1))
        if 1 <= port <= 65535 and port not in (80, 443):
            ports.add(port)
    config["ports"] = sorted(ports)[:20]

    return config


def extract_crypto_config(data: bytes, all_strings: set[str]) -> dict[str, Any]:
    """Extract cryptographic configuration."""
    config: dict[str, Any] = {}
    joined = "\n".join(all_strings)

    pem_certs: list[str] = []
    for m in re.finditer(rb'-----BEGIN [A-Z ]+-----[\s\S]{20,4000}?-----END [A-Z ]+-----', data):
        pem_certs.append(m.group().decode("ascii", errors="replace"))
    config["pem_certificates"] = pem_certs

    hex_keys: set[str] = set()
    for s in all_strings:
        for m in re.finditer(r'(?:^|(?<=[^0-9a-fA-F]))([0-9a-fA-F]{32})(?=$|[^0-9a-fA-F])', s):
            hex_keys.add(m.group(1))
        for m in re.finditer(r'(?:^|(?<=[^0-9a-fA-F]))([0-9a-fA-F]{64})(?=$|[^0-9a-fA-F])', s):
            hex_keys.add(m.group(1))
    # Filter noise: require sufficient entropy (>4 unique chars) and reject
    # sequential patterns like "B10B11B12..." which are lookup table indices.
    def _looks_like_real_key(h: str) -> bool:
        if len(set(h)) <= 8:
            return False
        # Reject sequential patterns like B10B11B12, 0123456789ABCDEF
        upper = h.upper()
        if "0123456789ABCDEF" in upper:
            return False
        # Check for repeating short chunks (lookup table indices)
        for chunk_sz in (3, 4):
            chunks = [h[i:i+chunk_sz] for i in range(0, len(h), chunk_sz)]
            if len(chunks) >= 4:
                # If sorted chunks form a near-sequential run, it's a table
                try:
                    vals = [int(c, 16) for c in chunks if len(c) == chunk_sz]
                    if len(vals) >= 4:
                        diffs = [vals[i+1] - vals[i] for i in range(len(vals)-1)]
                        if diffs and all(d == diffs[0] for d in diffs):
                            return False
                except ValueError:
                    pass
        return True
    hex_keys = {k for k in hex_keys if _looks_like_real_key(k)}
    config["possible_hex_keys"] = sorted(hex_keys)[:20]

    b64_blobs: set[str] = set()
    for m in re.finditer(r'([A-Za-z0-9+/]{40,}={0,2})', joined):
        b64_blobs.add(m.group(1)[:200])
    config["base64_blobs"] = sorted(b64_blobs)[:10]

    fingerprints: set[str] = set()
    for s in all_strings:
        if "fingerprint" in s.lower():
            for m in re.finditer(r'[0-9a-fA-F]{64}', s):
                fingerprints.add(m.group())
    config["fingerprints"] = sorted(fingerprints)

    return config


def extract_c2_config(data: bytes, all_strings: set[str]) -> dict[str, Any]:
    """Extract C2-specific configuration."""
    config: dict[str, Any] = {}
    joined = "\n".join(all_strings)

    uas: set[str] = set()
    for m in re.finditer(r'(Mozilla/5\.0[^\x00]{10,200})', joined):
        uas.add(m.group(1))
    config["user_agents"] = sorted(uas)

    # HTTP headers — match per-string with boundary checks.
    # Limit X-Header length to avoid concatenation noise from Go binaries
    # (e.g. "X-Forwarded-ForRegCreateKeyExW" is not a real header).
    _KNOWN_HEADERS = {
        "Authorization", "Cookie", "Content-Type", "Content-Length",
        "X-Forwarded-For", "X-Real-IP", "X-Api-Key", "X-Auth-Token",
        "X-Request-ID", "X-Correlation-ID", "X-Idempotency-Key",
        "X-Content-Type-Options", "X-Frame-Options", "X-Powered-By",
        "X-Forwarded-Host", "X-Forwarded-Proto",
    }
    headers: set[str] = set()
    for s in all_strings:
        for kh in _KNOWN_HEADERS:
            # Exact match within the string (surrounded by non-alpha or edges)
            idx = s.find(kh)
            if idx == -1:
                continue
            end = idx + len(kh)
            # Verify the match isn't part of a longer concatenated word
            if end < len(s) and s[end].isalpha():
                continue
            if idx > 0 and s[idx - 1].isalpha():
                continue
            headers.add(kh)
    config["http_headers"] = sorted(headers)

    # Timing/sleep configuration — filter out Go runtime and stdlib noise.
    _TIMING_NOISE = {
        "runtime:", "http.timeout", "http.tlsHandshake", "net.timeout",
        "os.timeout", "interface { Timeout",
        "net.KeepAliveConfig",  # stdlib type, not C2 config
        "context.deadlineExceeded", "context.canceled",
        "types from different scopes",
        "failed to get system page size", "assignment to entry in nil map",
        "found in object at",
    }
    sleep_patterns: set[str] = set()
    for s in all_strings:
        sl = s.lower()
        if any(kw in sl for kw in ["sleep", "interval", "jitter", "beacon",
                                     "timeout", "keepalive", "reconnect"]):
            # Skip Go runtime / stdlib strings
            if any(noise in s for noise in _TIMING_NOISE):
                continue
            # Skip very long strings (likely concatenated runtime messages)
            if len(s) > 100:
                continue
            sleep_patterns.add(s)
    config["timing_strings"] = sorted(sleep_patterns)[:20]

    json_configs: list[str] = []
    # Scan in bounded chunks to avoid ReDoS on large binary data
    chunk_size = 512 * 1024  # 512 KB
    for offset in range(0, min(len(data), MAX_SCAN_SIZE), chunk_size):
        chunk = data[offset:offset + chunk_size + 2048]  # overlap for boundary matches
        for m in re.finditer(rb'\{["\'][\w]+["\']\s*:\s*["\'\d\[\{][^}]{10,2000}\}', chunk):
            try:
                candidate = m.group().decode("ascii", errors="replace")
                json.loads(candidate)
                json_configs.append(candidate[:500])
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            if len(json_configs) >= 5:
                break
        if len(json_configs) >= 5:
            break
    config["embedded_json"] = json_configs[:5]

    return config


def extract_flatbuffers_config(data: bytes) -> dict[str, Any]:
    """Find FlatBuffers config type names."""
    fb_strings: set[str] = set()
    for m in re.finditer(
        rb'(Config|Setting|Option|Server|Client|Listen|Connect|Proxy|Auth|Tunnel)[\w]*T\b',
        data,
    ):
        fb_strings.add(m.group().decode("ascii", errors="replace"))
    return {"flatbuffers_types": sorted(fb_strings)}


def extract_config_from_binary(
    filepath: str, data: bytes | None = None,
    memory_mapped: bool = True,
    yara_rules_dir: str | None = None,
    quiet: bool = False,
) -> dict[str, Any]:
    """Full configuration extraction from a single binary."""
    if data is None:
        with open(filepath, "rb") as f:
            data = f.read()
        memory_mapped = False

    logger.info(f"\nAnalyzing: {filepath} ({len(data):,} bytes)")

    all_ascii, all_utf16 = extract_strings(data)
    all_strings = all_ascii | all_utf16
    hashes = compute_hashes(data)

    result: dict[str, Any] = {
        "file": str(filepath),
        "size": len(data),
        "total_strings": len(all_strings),
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
    }

    logger.info("  Extracting network configuration...")
    result["network"] = extract_network_config(data, all_strings)

    logger.info("  Extracting cryptographic material...")
    result["crypto"] = extract_crypto_config(data, all_strings)

    logger.info("  Extracting C2 configuration...")
    result["c2"] = extract_c2_config(data, all_strings)

    logger.info("  Checking FlatBuffers structures...")
    result["flatbuffers"] = extract_flatbuffers_config(data)

    # YARA scan
    if yara_rules_dir:
        yara_hits = scan_with_yara(data, yara_rules_dir)
        if yara_hits:
            result["yara_matches"] = yara_hits

    if not quiet:
        _print_config_report(result, hashes)
    return result


def _print_config_report(result: dict[str, Any], hashes: dict[str, str]) -> None:
    """Print human-readable config extraction report."""
    filepath = result["file"]
    print(f"\n{'_'*70}")
    print(f"CONFIGURATION EXTRACTED: {Path(filepath).name}")
    print(f"{'_'*70}")
    print(f"  MD5:    {hashes['md5']}")
    print(f"  SHA256: {hashes['sha256']}")

    net = result["network"]
    if net["ip_ports"]:
        print(f"\n  IP:Port combinations:")
        for ip in net["ip_ports"]:
            print(f"    {ip}")
    if net["urls"]:
        print(f"\n  URLs ({len(net['urls'])}):")
        for u in net["urls"][:15]:
            print(f"    {u}")
    if net["hostnames"]:
        print(f"\n  Hostnames:")
        for h in net["hostnames"]:
            print(f"    {h}")
    if net["named_pipes"]:
        print(f"\n  Named Pipes:")
        for p in net["named_pipes"]:
            print(f"    {p}")
    if net["unc_paths"]:
        print(f"\n  UNC Paths:")
        for u in net["unc_paths"]:
            print(f"    {u}")
    if net["ips"]:
        print(f"\n  IP Addresses ({len(net['ips'])}):")
        for entry in net["ips"][:15]:
            ctx = f"  ctx: {entry['context']}" if entry["context"] else ""
            print(f"    {entry['ip']:20s}{ctx}")

    crypto = result["crypto"]
    if crypto["pem_certificates"]:
        print(f"\n  PEM Certificates ({len(crypto['pem_certificates'])}):")
        for cert in crypto["pem_certificates"][:3]:
            print(f"    {cert[:80]}...")
    if crypto["possible_hex_keys"]:
        print(f"\n  Possible Hex Keys ({len(crypto['possible_hex_keys'])}):")
        for k in crypto["possible_hex_keys"][:10]:
            print(f"    {k}")
    if crypto["fingerprints"]:
        print(f"\n  Certificate Fingerprints:")
        for fp in crypto["fingerprints"]:
            print(f"    {fp}")

    c2 = result["c2"]
    if c2["user_agents"]:
        print(f"\n  User-Agent Strings:")
        for ua in c2["user_agents"]:
            print(f"    {ua[:100]}")
    if c2["http_headers"]:
        print(f"\n  HTTP Headers:")
        for h in c2["http_headers"]:
            print(f"    {h}")
    if c2["timing_strings"]:
        print(f"\n  Timing/Sleep Configuration:")
        for s in c2["timing_strings"][:10]:
            print(f"    {s}")
    if c2["embedded_json"]:
        print(f"\n  Embedded JSON Configs:")
        for j in c2["embedded_json"]:
            print(f"    {j[:200]}")

    fb = result["flatbuffers"]
    if fb["flatbuffers_types"]:
        print(f"\n  FlatBuffers Config Types:")
        for t in fb["flatbuffers_types"]:
            print(f"    {t}")

    if result.get("yara_matches"):
        print(f"\n  YARA Matches:")
        for ym in result["yara_matches"]:
            print(f"    Rule: {ym['rule']}  Tags: {', '.join(ym.get('tags', []))}")


def analyze(
    mf: Any, reader: Any, out_dir: str,
    yara_rules_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Core config extraction (called by orchestrator with pre-parsed dump)."""
    known_bases = get_known_bases(mf)
    results: list[dict[str, Any]] = []

    for seg in reader.memory_segments:
        base = seg.start_virtual_address
        seg_size = seg.end_virtual_address - base

        hdr_result = check_pe_header(reader, base, seg_size)
        if not hdr_result or base in known_bases:
            continue

        pe_off, img_size, hdr = hdr_result

        is_target = (b"Go build" in hdr or b"_cgo_" in hdr or
                     b".symtab" in hdr or img_size > 2_000_000)
        if not is_target:
            continue

        logger.info(f"\nReading PE @ 0x{base:x} ({img_size:,} bytes)...")
        data = read_pe_data(reader, base, img_size)

        result = extract_config_from_binary(
            f"hidden_0x{base:x}", bytes(data),
            memory_mapped=True, yara_rules_dir=yara_rules_dir,
        )
        result["base_address"] = f"0x{base:016x}"
        results.append(result)

    return results


def run(
    input_path: str, out_dir: str | None = None,
    is_dump_mode: bool = False, verbose: bool = False,
    yara_rules_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Standalone entry point."""
    setup_logging(verbose)

    if is_dump_mode:
        from minidump.minidumpfile import MinidumpFile
        mf = MinidumpFile.parse(input_path)
        reader = mf.get_reader()
        if out_dir is None:
            out_dir = os.path.join(os.path.dirname(input_path) or ".", "output")
        os.makedirs(out_dir, exist_ok=True)
        results = analyze(mf, reader, out_dir, yara_rules_dir)
    else:
        results = [extract_config_from_binary(input_path, yara_rules_dir=yara_rules_dir)]

    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(input_path) or ".", "output")
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "extracted_config.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nConfig report saved: {report_path}")

    return results
