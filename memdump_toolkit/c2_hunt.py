"""Hunt for C2 indicators in raw process memory (heap, stack, data segments).

Unlike static binary analysis, this module scans ALL memory segments of a
minidump for live runtime C2 artifacts: URLs, hostnames, IP:port combos,
private keys, certificates, named pipes, and User-Agent strings.

Entry points:
    analyze(mf, reader, out_dir=None) -> dict   # called by orchestrator
    run(dump_path, out_dir=None, verbose=False) -> dict  # standalone
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from typing import Any

from minidump.minidumpfile import MinidumpFile

from memdump_toolkit.constants import MAX_SEGMENT_SCAN_SIZE
from memdump_toolkit.pe_utils import logger, setup_logging


# ─── Constants ───────────────────────────────────────────────────────────────

# Maximum segment size to attempt reading (50 MB guard)
_MAX_SEG_SIZE = MAX_SEGMENT_SCAN_SIZE
# Maximum bytes to read from a single segment
_MAX_READ = 10_000_000
# Context bytes to capture around each match
_CONTEXT_BYTES = 80

# Domains we consider system/CDN noise — exact base-domain match only.
# Sub-domains of cloud providers (*.elb.amazonaws.com, *.cloudfront.net, etc.)
# are intentionally NOT in this set so they surface as C2 indicators.
_NOISE_DOMAINS: frozenset[str] = frozenset({
    # Microsoft / Windows
    "microsoft.com", "windows.com", "windowsupdate.com", "msn.com",
    "bing.com", "live.com", "office.com", "office365.com",
    "microsoftonline.com", "aka.ms", "msocsp.com", "msocdn.com",
    # Google
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    # Certificate authorities and PKI infrastructure
    "digicert.com", "symantec.com", "verisign.com", "thawte.com",
    "globalsign.com", "globalsign.net", "sectigo.com", "comodo.com",
    "comodoca.com", "usertrust.com", "entrust.net", "entrust.com",
    "letsencrypt.org", "identrust.com", "godaddy.com",
    "starfieldtech.com", "startcom.org", "buypass.com",
    "quovadisglobal.com", "certum.pl", "camerfirma.com",
    "disig.sk", "edicomgroup.com", "icpbrasil.gov.br",
    "mtin.es", "pki.gva.es", "catcert.net", "cert.fnmt.es",
    "certeurope.fr", "certigna.fr", "dhimyotis.com",
    # Standards / schemas
    "w3.org", "xmlsoap.org", "schema.org", "schemas.microsoft.com",
    # Dev infrastructure (not C2)
    "golang.org", "github.com", "gopkg.in", "go.dev",
    "mozilla.org", "firefox.com", "chromium.org",
    "apple.com", "icloud.com",
    "ubuntu.com", "debian.org", "redhat.com", "centos.org",
    # SQL Server / database
    "sqlserver.com", "trafficmanager.net",
    "localhost",
})

# Loopback / reserved first-octet values to skip for bare IPs
_SKIP_IP_FIRST_OCTETS: frozenset[int] = frozenset({0, 127, 169, 255})

# TLDs considered inherently suspicious (tor, typosquats, burner registrars)
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "onion", "bit", "i2p", "exit", "coin", "bazar", "lib",
})

# Cloud provider patterns that always surface regardless of noise filtering
_CLOUD_C2_PATTERNS: tuple[str, ...] = (
    ".elb.", "cloudfront.net", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "workers.dev", "pages.dev",
    "githubusercontent.com",
)


# ─── Compiled Regexes (built once) ───────────────────────────────────────────

# URL: scheme + hostname-or-IP + optional port + optional path
_RE_URL = re.compile(
    rb'((?:https?|wss?|socks[45]?|tcp|udp)://'
    rb'(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'    # bare IP
    rb'|[a-zA-Z0-9][\w\-]*(?:\.[a-zA-Z0-9][\w\-]*)+)'  # dotted hostname
    rb'(?::\d{1,5})?'
    rb'(?:[/\w.\-:?&=@#%+]*)?)',
)

# Bare hostname (no scheme) matching cloud/suspicious patterns.
# We only grab these when they look like real hostnames (2+ labels, known TLD or
# cloud suffix). Keeping this tighter than URL matching to reduce noise.
_RE_HOSTNAME = re.compile(
    rb'(?<![.\w])'
    rb'([a-zA-Z0-9][\w\-]{1,63}'
    rb'(?:\.[a-zA-Z0-9][\w\-]{1,63})+'
    rb'\.(?:amazonaws\.com|azure\.com|azurewebsites\.net'
    rb'|cloudfront\.net|ngrok\.io|ngrok-free\.app'
    rb'|trycloudflare\.com|workers\.dev|pages\.dev'
    rb'|onion|bit|i2p))'
    rb'(?![.\w])',
)

# IP:port  e.g.  10.0.5.12:4444
_RE_IP_PORT = re.compile(
    rb'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b)',
)

# PEM private key header (various types)
_RE_KEY_BEGIN = re.compile(
    rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
)
_RE_KEY_END = re.compile(
    rb'-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
)

# PEM certificate
_RE_CERT_BEGIN = re.compile(rb'-----BEGIN CERTIFICATE-----')
_RE_CERT_END = re.compile(rb'-----END CERTIFICATE-----')

# Named pipe
_RE_PIPE = re.compile(
    rb'(\\\\\\.\\pipe\\[\w\-. ]{1,128})',
    re.IGNORECASE,
)

# User-Agent string (Mozilla/x.y prefix)
_RE_UA = re.compile(
    rb'(Mozilla/[45]\.\d[^\r\n\x00]{10,300})',
)

# Private / loopback IP ranges — used to suppress noise in URL filtering
_RE_PRIVATE_IP = re.compile(
    r'^(?:127\.\d+\.\d+\.\d+'                    # 127.0.0.0/8  loopback
    r'|10\.\d+\.\d+\.\d+'                         # 10.0.0.0/8
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'      # 172.16.0.0/12
    r'|192\.168\.\d+\.\d+)$'                      # 192.168.0.0/16
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _context(data: bytes, start: int, end: int, window: int = _CONTEXT_BYTES) -> str:
    """Return a printable snippet around [start:end] in data."""
    lo = max(0, start - window)
    hi = min(len(data), end + window)
    raw = data[lo:hi]
    return raw.decode("latin-1", errors="replace").replace("\x00", ".")


def _base_domain(hostname: str) -> str:
    """Extract base domain (last two labels) from a hostname."""
    parts = hostname.rstrip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


def _is_cloud_c2(hostname: str) -> bool:
    """Return True if hostname matches a known cloud-C2 pattern."""
    lh = hostname.lower()
    return any(pat in lh for pat in _CLOUD_C2_PATTERNS)


def _filter_url(url_bytes: bytes) -> tuple[str, bool]:
    """Return (url_str, keep) applying noise filters.

    Strategy: whitelist-first.  Only keep URLs that match a C2-relevant
    pattern (cloud infra, non-standard ports, WebSocket, SOCKS, suspicious
    path keywords) OR are on a non-system domain.  Everything else is noise
    from the Windows certificate store, WCF/SOAP schemas, etc.
    """
    try:
        url = url_bytes.decode("latin-1")
    except Exception:
        return "", False

    # Strip trailing non-URL garbage (null-byte artifacts from raw memory)
    url = re.sub(r'[^\x20-\x7e]+$', '', url)   # trailing non-printable
    url = re.sub(r'[^a-zA-Z0-9/_.~:@!$&\'()*+,;=?#%\[\]-]+$', '', url)  # trailing invalid URL chars

    # Drop obvious XML/DTD fragments that happen to start with http
    if "//DTD" in url or "<!DOCTYPE" in url:
        return url, False

    # Extract hostname from URL
    m = re.match(r'([a-z+]+)://([^/:?#\s]+)(?::(\d+))?', url, re.IGNORECASE)
    if not m:
        return url, False
    scheme = m.group(1).lower()
    host = m.group(2).lower()
    port = int(m.group(3)) if m.group(3) else None

    # 0. Drop obviously broken hostnames (memory artifacts)
    if len(host) < 4 or "." not in host:
        return url, False

    # 0b. Drop private/loopback IP addresses in URLs — they're internal traffic
    #     and add noise rather than C2 signal.  Mirrors _SKIP_IP_FIRST_OCTETS
    #     logic used for bare IP:port filtering.
    if _RE_PRIVATE_IP.match(host):
        return url, False

    # 1. Always keep: WebSocket, SOCKS, TCP/UDP schemes (not HTTP noise)
    if scheme in ("wss", "ws", "socks4", "socks5", "tcp", "udp"):
        return url, True

    # 2. Always keep: cloud C2 load balancers
    if _is_cloud_c2(host):
        return url, True

    # 3. Always keep: non-standard ports (C2 often uses 8080, 4444, etc.)
    if port and port not in (80, 443):
        base = _base_domain(host)
        if base not in _NOISE_DOMAINS:
            return url, True

    # 4. Drop known noise domains early (before path keyword heuristics)
    if _base_domain(host) in _NOISE_DOMAINS:
        return url, False

    # 5. Drop certificate/PKI infrastructure URLs
    url_lower = url.lower()
    if any(kw in url_lower for kw in (".crl", "/crl", "/ocsp", "/cps",
                                        "/cacert", "/caissuer",
                                        "certificate", "revocation",
                                        "/policy", "/repository",
                                        "/pkiops/", "/aia/")):
        return url, False

    # 6. Drop SOAP/WCF/XML schema URLs
    if any(kw in url_lower for kw in ("xmlsoap", "schemas.", "docs.oasis",
                                        "tempuri.org", ".xsd", ".wsdl",
                                        "/xml/", "www.w3.org")):
        return url, False

    # 7. Drop certificate authority / government PKI / WCF / system URLs
    if any(kw in host for kw in (".gov.", ".gob.", ".gub.", ".edu.",
                                   "pki.", "cert.", "certif",
                                   "accv.es", "dnie.es", "ecee.",
                                   "disig.", "netlock.", "certigna.",
                                   "acabogacia.", "anf.es", "datev.",
                                   "registradores.", "digidentity.",
                                   "lencr.org", "purl.org",
                                   "modern.ie", "msn.cn",
                                   "tempuri.org",
                                   "e-szigno.", "pkioverheid.",
                                   "camerfirma.", "certicamara.",
                                   "ca.posta.", "wikipedia.org",
                                   "connect.microsoft.com")):
        return url, False

    # 8. Suspicious path keywords (after noise filtering)
    _C2_PATH_KEYWORDS = ("/beacon", "/stager", "/login", "/gate",
                          "/panel", "/c2/", "/callback", "/shell",
                          "/upload", "/download", "/implant", "/agent",
                          "/events", "/connect", "/session")
    if any(kw in url_lower for kw in _C2_PATH_KEYWORDS):
        return url, True

    # 9. Keep bare IP URLs — they're interesting for C2
    if re.match(r'\d+\.\d+\.\d+\.\d+', host):
        return url, True

    # 10. Keep remaining URLs only if they look actionable
    path_start = url.find("/", url.find("://") + 3)
    if path_start > 0:
        path = url[path_start:]
        if len(path) > 1 and not re.match(r'^/[\w]+\.(pdf|htm|html|asp|txt|xml|css|js|png|gif|jpg)\d*$', path):
            return url, True

    return url, False


def _filter_hostname(host_bytes: bytes) -> tuple[str, bool]:
    """Return (host_str, keep) for a bare hostname match."""
    try:
        host = host_bytes.decode("latin-1").lower()
    except Exception:
        return "", False

    # Cloud C2 always kept
    if _is_cloud_c2(host):
        return host, True

    # Check suspicious TLD
    tld = host.rstrip(".").rsplit(".", 1)[-1]
    if tld in _SUSPICIOUS_TLDS:
        return host, True

    # Filter noise
    if _base_domain(host) in _NOISE_DOMAINS:
        return host, False

    return host, True


def _filter_ip_port(ip_port_bytes: bytes) -> tuple[str, bool]:
    """Return (ip_port_str, keep) for an IP:port match."""
    try:
        s = ip_port_bytes.decode("ascii")
    except Exception:
        return "", False

    ip, _, port_str = s.rpartition(":")
    try:
        octets = [int(o) for o in ip.split(".")]
        port = int(port_str)
    except ValueError:
        return s, False

    if not all(0 <= o <= 255 for o in octets):
        return s, False
    if octets[0] in _SKIP_IP_FIRST_OCTETS:
        return s, False
    # Version-number-like IPs (all octets < 10)
    if all(o < 10 for o in octets):
        return s, False
    # Ephemeral / unprivileged port sanity: port must be 1–65535
    if not 1 <= port <= 65535:
        return s, False

    return s, True


def _extract_pem_blocks(
    data: bytes,
    begin_re: re.Pattern[bytes],
    end_re: re.Pattern[bytes],
    max_block: int = 8192,
) -> list[tuple[int, str]]:
    """Extract complete PEM blocks from raw bytes.

    Returns list of (absolute_offset, pem_string).
    """
    results: list[tuple[int, str]] = []
    for bm in begin_re.finditer(data):
        start = bm.start()
        end_search = data[start: start + max_block]
        em = end_re.search(end_search)
        if em:
            block_bytes = end_search[:em.end()]
            try:
                block = block_bytes.decode("ascii", errors="replace")
                results.append((start, block))
            except Exception:
                pass
    return results


# ─── Per-Segment Scanner ─────────────────────────────────────────────────────

def _scan_segment(
    data: bytes,
    base_addr: int,
    results: dict[str, Any],
) -> None:
    """Scan one memory segment's bytes, accumulating results in-place."""

    # ── URLs ──────────────────────────────────────────────────────────────────
    for m in _RE_URL.finditer(data):
        match = m.group(1)
        # Skip matches longer than 2048 bytes — almost certainly garbage from
        # raw memory rather than a real URL (ReDoS safety net too).
        if len(match) > 2048:
            continue
        url_str, keep = _filter_url(match)
        if keep:
            addr = base_addr + m.start()
            ctx = _context(data, m.start(), m.end())
            results["urls"][url_str]["addresses"].append(addr)
            results["urls"][url_str]["context"] = ctx  # last context wins (dedup)

    # ── Bare hostnames ────────────────────────────────────────────────────────
    for m in _RE_HOSTNAME.finditer(data):
        host_str, keep = _filter_hostname(m.group(1))
        if keep:
            addr = base_addr + m.start()
            results["hostnames"][host_str]["addresses"].append(addr)

    # ── IP:port ───────────────────────────────────────────────────────────────
    for m in _RE_IP_PORT.finditer(data):
        ip_port_str, keep = _filter_ip_port(m.group(1))
        if keep:
            addr = base_addr + m.start()
            results["ip_ports"][ip_port_str]["addresses"].append(addr)

    # ── Private keys (full PEM block) ─────────────────────────────────────────
    for offset, block in _extract_pem_blocks(data, _RE_KEY_BEGIN, _RE_KEY_END):
        addr = base_addr + offset
        results["private_keys"].append({"address": addr, "pem": block})

    # ── Certificates (full PEM block) ─────────────────────────────────────────
    for offset, block in _extract_pem_blocks(data, _RE_CERT_BEGIN, _RE_CERT_END):
        addr = base_addr + offset
        results["certificates"].append({"address": addr, "pem": block})

    # ── Named pipes ───────────────────────────────────────────────────────────
    for m in _RE_PIPE.finditer(data):
        try:
            pipe = m.group(1).decode("latin-1")
        except Exception:
            continue
        addr = base_addr + m.start()
        results["named_pipes"][pipe]["addresses"].append(addr)

    # ── User-Agents ─────────────────────────────────────────────────────────
    for m in _RE_UA.finditer(data):
        try:
            ua = m.group(1).decode("latin-1").strip()
        except Exception:
            continue
        if len(ua) < 30:
            continue
        addr = base_addr + m.start()
        results["user_agents"][ua[:200]]["addresses"].append(addr)


# ─── Core Analysis ───────────────────────────────────────────────────────────

def analyze(
    mf: MinidumpFile,
    reader: Any,
    out_dir: str | None = None,
    is_32bit: bool = False,
) -> dict[str, Any]:
    """Scan all memory segments in *mf* for C2 indicators.

    Args:
        mf:       Pre-parsed MinidumpFile object.
        reader:   Memory reader from mf.get_reader().
        out_dir:  If provided, write ``c2_hunt.json`` here.
        is_32bit: True for 32-bit process dumps (changes heap/system address boundary).

    Returns:
        Structured result dict.
    """
    dump_name = os.path.basename(getattr(mf, "filename", "unknown.dmp"))

    # Accumulator: dicts of value → {addresses: [...], context: str}
    raw: dict[str, Any] = {
        "urls":        defaultdict(lambda: {"addresses": [], "context": ""}),
        "hostnames":   defaultdict(lambda: {"addresses": []}),
        "ip_ports":    defaultdict(lambda: {"addresses": []}),
        "private_keys":  [],  # list of {address, pem}
        "certificates":  [],  # list of {address, pem}
        "named_pipes": defaultdict(lambda: {"addresses": []}),
        "user_agents": defaultdict(lambda: {"addresses": []}),
    }

    segments = list(reader.memory_segments)
    total_segs = len(segments)
    bytes_scanned = 0
    segs_scanned = 0

    for idx, seg in enumerate(segments):
        base = seg.start_virtual_address
        size = seg.end_virtual_address - base

        if size <= 0 or size > _MAX_SEG_SIZE:
            logger.debug("Skipping segment 0x%x (size=%d)", base, size)
            continue

        read_size = min(size, _MAX_READ)
        try:
            data = reader.read(base, read_size)
        except Exception as exc:
            logger.info("Failed to read segment 0x%x: %s", base, exc)
            continue

        if not data:
            continue

        _scan_segment(data, base, raw)
        bytes_scanned += len(data)
        segs_scanned += 1

        if logger.isEnabledFor(logging.DEBUG):
            if segs_scanned % 50 == 0:
                logger.debug(
                    "Scanning segment %d/%d (0x%x, %d bytes)...",
                    idx + 1, total_segs, base, read_size,
                )

    # ── Build final result ────────────────────────────────────────────────────
    def _flatten(d: dict) -> list[dict]:
        """Convert defaultdict of value→info into sorted list of result dicts."""
        out = []
        for val, info in sorted(d.items()):
            addrs = info["addresses"]
            entry: dict[str, Any] = {
                "value": val,
                "count": len(addrs),
                "addresses": addrs[:10],  # cap stored addresses
            }
            if "context" in info and info["context"]:
                entry["context"] = info["context"]
            out.append(entry)
        return out

    # Deduplicate PEM blocks by content
    def _dedup_pem(lst: list[dict]) -> list[dict]:
        seen: set[str] = set()
        out = []
        for item in lst:
            key = item["pem"].strip()
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    def _dedup_prefix(entries: list[dict]) -> list[dict]:
        """Remove entries that are just another entry + trailing garbage bytes.

        e.g., 'https://host.comc' is dropped if 'https://host.com' exists,
        because the extra 'c' is a memory artifact.

        O(n²): sort by length, then for each entry check if any shorter
        entry is a prefix within 3 chars difference.  A trie would give
        O(n·k) but isn't worth the complexity for typical small input sizes.
        """
        if not entries:
            return entries
        # Sort by value length so shorter entries come first
        sorted_entries = sorted(entries, key=lambda e: len(e["value"]))
        # Collect all values for quick lookup
        shorter_values: list[str] = []
        keep_set: set[str] = set()
        out: list[dict] = []
        for e in sorted_entries:
            val = e["value"]
            is_garbage = False
            # Only check against shorter values (already processed)
            for shorter in shorter_values:
                if val.startswith(shorter) and len(val) - len(shorter) <= 3:
                    is_garbage = True
                    break
            if not is_garbage:
                shorter_values.append(val)
                keep_set.add(val)
        # Preserve original order
        for e in entries:
            if e["value"] in keep_set:
                out.append(e)
        return out

    # Heap vs system address threshold (bitness-aware)
    # x64: user-space image base starts around 0x7FF000000000
    # x86: user-space tops at 0x80000000 (2 GB, or 3 GB with /3GB)
    heap_threshold = 0x70000000 if is_32bit else 0x7f0000000000

    result: dict[str, Any] = {
        "dump": dump_name,
        "segments_scanned": segs_scanned,
        "bytes_scanned": bytes_scanned,
        "is_32bit": is_32bit,
        "heap_threshold": heap_threshold,
        "urls": _dedup_prefix(_flatten(raw["urls"])),
        "hostnames": _flatten(raw["hostnames"]),
        "ip_ports": _flatten(raw["ip_ports"]),
        "private_keys": _dedup_pem(raw["private_keys"]),
        "certificates": _dedup_pem(raw["certificates"]),
        "named_pipes": _flatten(raw["named_pipes"]),
        "user_agents": _flatten(raw["user_agents"]),
    }

    _print_report(result)

    if out_dir is not None:
        os.makedirs(out_dir, exist_ok=True)
        report_path = os.path.join(out_dir, "c2_hunt.json")
        with open(report_path, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        logger.info(f"\nJSON report: {report_path}")

    return result


# ─── Report Printer ──────────────────────────────────────────────────────────

def _print_report(result: dict[str, Any]) -> None:
    from memdump_toolkit.colors import (
        bold, critical, dim, high, info, success,
    )

    bar = "\u2550" * 70
    print(f"\n{info(bar)}")
    print(info(f"C2 HUNT: {result['dump']}"))
    print(f"{info(bar)}")

    gb = result["bytes_scanned"] / 1_073_741_824
    mb = result["bytes_scanned"] / 1_048_576
    size_str = f"{gb:.1f} GB" if gb >= 1.0 else f"{mb:.1f} MB"
    print(f"  Segments scanned: {result['segments_scanned']}")
    print(f"  Memory scanned:   {size_str}")

    # ── URLs ──────────────────────────────────────────────────────────────────
    urls = result["urls"]
    print(f"\n  {bold(f'URLs ({len(urls)} unique):')}")
    if urls:
        for entry in urls:
            count = entry["count"]
            addrs = ", ".join(f"0x{a:016x}" for a in entry["addresses"][:4])
            suffix = ", ..." if len(entry["addresses"]) == 10 and entry["count"] > 10 else ""
            print(critical(f"    [{count}x] {entry['value']}"))
            print(dim(f"         @ {addrs}{suffix}"))
    else:
        print(dim("    (none found)"))

    # ── Hostnames ─────────────────────────────────────────────────────────────
    hosts = result["hostnames"]
    print(f"\n  {bold(f'Suspicious Hostnames ({len(hosts)} unique):')}")
    if hosts:
        for entry in hosts:
            count = entry["count"]
            addrs = ", ".join(f"0x{a:016x}" for a in entry["addresses"][:4])
            print(high(f"    [{count}x] {entry['value']}"))
            print(dim(f"         @ {addrs}"))
    else:
        print(dim("    (none found)"))

    # ── Private Keys ──────────────────────────────────────────────────────────
    keys = result["private_keys"]
    label = critical(f"Private Keys ({len(keys)}):") if keys else f"Private Keys ({len(keys)}):"
    print(f"\n  {bold(label)}")
    if keys:
        for item in keys:
            lines = item["pem"].strip().splitlines()
            print(critical(f"    @ 0x{item['address']:016x}"))
            for line in lines[:3]:
                print(f"    {line}")
            if len(lines) > 3:
                print(dim(f"    ... ({len(lines) - 3} more lines)"))
            print()
    else:
        print(dim("    (none found)"))

    # ── Certificates ──────────────────────────────────────────────────────────
    certs = result["certificates"]
    print(f"\n  {bold(f'Certificates ({len(certs)}):')}")
    if certs:
        for item in certs:
            lines = item["pem"].strip().splitlines()
            print(f"    @ 0x{item['address']:016x}")
            for line in lines[:3]:
                print(f"    {line}")
            if len(lines) > 3:
                print(dim(f"    ... ({len(lines) - 3} more lines)"))
            print()
    else:
        print(dim("    (none found)"))

    # ── Named Pipes ───────────────────────────────────────────────────────────
    pipes = result["named_pipes"]
    print(f"\n  {bold(f'Named Pipes ({len(pipes)} unique):')}")
    if pipes:
        for entry in pipes:
            count = entry["count"]
            addrs = ", ".join(f"0x{a:016x}" for a in entry["addresses"][:4])
            print(high(f"    [{count}x] {entry['value']}"))
            print(dim(f"         @ {addrs}"))
    else:
        print(dim("    (none found)"))

    # ── IP:Port ───────────────────────────────────────────────────────────────
    ip_ports = result["ip_ports"]
    print(f"\n  {bold(f'IP:Port Combinations ({len(ip_ports)} unique):')}")
    if ip_ports:
        for entry in ip_ports:
            count = entry["count"]
            addrs = ", ".join(f"0x{a:016x}" for a in entry["addresses"][:4])
            print(high(f"    [{count}x] {entry['value']}"))
            print(dim(f"         @ {addrs}"))
    else:
        print(dim("    (none found)"))

    # ── User-Agents — split into heap (likely implant) vs DLL (system) ──────
    uas = result["user_agents"]
    threshold = result.get("heap_threshold", 0x7f0000000000)
    heap_uas = [e for e in uas if any(a < threshold for a in e["addresses"])]
    sys_uas = [e for e in uas if all(a >= threshold for a in e["addresses"])]
    if heap_uas:
        print(f"\n  {critical(f'User-Agents in HEAP ({len(heap_uas)} — likely implant):')}")
        for entry in heap_uas:
            count = entry["count"]
            addrs = ", ".join(f"0x{a:016x}" for a in entry["addresses"][:4])
            print(critical(f"    [{count}x] {entry['value'][:120]}"))
            print(dim(f"         @ {addrs}"))
    if sys_uas:
        print(dim(f"\n  User-Agents in system DLLs ({len(sys_uas)} — likely benign):"))
        for entry in sys_uas[:3]:
            print(dim(f"    {entry['value'][:100]}"))
        if len(sys_uas) > 3:
            print(dim(f"    ... and {len(sys_uas) - 3} more"))
    if not uas:
        print(dim(f"\n  User-Agents: (none found)"))

    print()


# ─── Standalone Entry Point ───────────────────────────────────────────────────

def run(
    dump_path: str,
    out_dir: str | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """Standalone entry point: parse dump and run C2 hunt.

    Args:
        dump_path:  Path to the minidump file.
        out_dir:    If provided, write ``c2_hunt.json`` here.
        verbose:    Enable debug logging.

    Returns:
        Structured result dict.
    """
    setup_logging(verbose)

    if not os.path.isfile(dump_path):
        logger.error("Dump file not found: %s", dump_path)
        return {}

    logger.debug("Parsing minidump: %s", dump_path)
    try:
        mf = MinidumpFile.parse(dump_path)
        mf.filename = dump_path
        reader = mf.get_reader()
    except Exception as exc:
        logger.error("Failed to parse minidump: %s", exc)
        return {}

    # Detect bitness from first module
    is_32bit = False
    try:
        from memdump_toolkit.pe_utils import detect_pe_bitness
        if mf.modules and mf.modules.modules:
            first = mf.modules.modules[0]
            data = reader.read(first.baseaddress, min(0x400, first.size))
            is_32bit = detect_pe_bitness(data) == 32
    except Exception:
        pass

    return analyze(mf, reader, out_dir, is_32bit=is_32bit)
