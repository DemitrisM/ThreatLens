"""Indicator of Compromise (IOC) extraction module.

Applies regex patterns against extracted strings to identify IPv4 addresses,
URLs, domains, Windows file paths, registry keys, email addresses, and other
IOCs. Filters known false positives.
Returns a standard module result dict with score_delta and reason.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IOC regex patterns (from CLAUDE.md spec)
# ---------------------------------------------------------------------------

_IOC_PATTERNS: dict[str, re.Pattern] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "url": re.compile(
        r"https?://[^\s<>\"{}|\\^`\[\]\x00-\x1f%]+"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}\b"
    ),
    "windows_path": re.compile(
        r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
    ),
    "registry_key": re.compile(
        r"HKEY_[A-Z_]+(?:\\[^\r\n\"]+)+"
    ),
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
}

# ---------------------------------------------------------------------------
# False-positive filters
# ---------------------------------------------------------------------------

# IPs that are almost always false positives.
_FP_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "255.255.255.0", "255.255.0.0", "255.0.0.0",
    "1.0.0.0", "1.0.0.1",  # version-like
    "2.0.0.0", "3.0.0.0", "4.0.0.0", "6.0.0.0",
}

# IP prefixes that are almost always internal / benign.
_FP_IP_PREFIXES = ("192.168.", "10.", "169.254.", "224.")

# Common DLL and system file names that trigger domain/path FPs.
_FP_DOMAINS = {
    "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
    "ws2_32.dll", "wininet.dll", "msvcrt.dll", "shell32.dll",
    "ole32.dll", "gdi32.dll", "comctl32.dll", "comdlg32.dll",
    "crypt32.dll", "shlwapi.dll", "urlmon.dll", "winhttp.dll",
    "mswsock.dll", "secur32.dll", "rpcrt4.dll", "iphlpapi.dll",
    "mscoree.dll", "mscorlib.dll", "clr.dll",
    # Common benign domains.
    "www.w3.org", "schemas.microsoft.com", "schemas.xmlsoap.org",
    "www.microsoft.com", "go.microsoft.com",
    "ocsp.digicert.com", "crl.digicert.com",
    "ocsp.verisign.com", "crl.verisign.com",
    "cacerts.digicert.com",
    "localhost",
    # Common TLD-like false positives from PE metadata.
    "api.example.com", "test.com", "example.com",
    # .NET XML namespace defaults — appear in every WCF/serialization binary
    "tempuri.org", "www.tempuri.org",
    "schemas.datacontract.org", "schemas.openxmlformats.org",
    "purl.org", "www.purl.org",
}

# Public-suffix-style allow list of real TLDs. Domains whose final label
# is NOT in this set are dropped — this kills the bulk of Go / Nim / Rust /
# Python source-filename pseudo-domains (arena.go, fatal.nim, lib.rs, …)
# without requiring a per-language deny list.
#
# Sourced from IANA + commonly abused malicious TLDs. Kept deliberately
# tight: ~210 entries cover ~99% of legitimate Internet domains.
_REAL_TLDS = {
    # Generic TLDs
    "com", "org", "net", "info", "biz", "name", "pro", "xyz", "top",
    "club", "site", "store", "shop", "online", "tech", "live",
    "world", "today", "news", "blog", "app", "dev", "io", "co",
    "ai", "ly", "me", "tv", "fm", "cc", "sh", "to", "ws", "la",
    "link", "click", "lol", "fun", "win", "vip", "icu", "wtf",
    "support", "host", "press", "space", "website", "cloud",
    "digital", "agency", "design", "studio", "expert", "global",
    "media", "network", "services", "solutions", "systems",
    "academy", "center", "company", "email", "group", "guru",
    "international", "marketing", "school", "team", "tools",
    "training", "world", "zone", "art", "best", "city", "fund",
    "game", "games", "gold", "house", "land", "life", "money",
    # Country code TLDs (most common)
    "us", "uk", "ca", "au", "nz", "ie", "za",
    "de", "fr", "es", "it", "nl", "be", "ch", "at", "se", "no",
    "fi", "dk", "pl", "cz", "sk", "hu", "ro", "bg", "gr", "pt",
    "ru", "ua", "by", "kz", "uz", "ge",
    "cn", "jp", "kr", "tw", "hk", "mo", "sg", "my", "th", "vn",
    "id", "ph", "in", "pk", "bd", "lk", "np",
    "il", "tr", "ae", "sa", "qa", "kw", "bh", "om", "lb", "jo",
    "mx", "br", "ar", "cl", "co", "pe", "ve", "uy", "py", "bo",
    "eg", "ma", "tn", "dz", "ng", "ke", "gh", "et", "tz", "ug",
    # Country TLDs commonly abused for malicious infrastructure
    "tk", "ml", "ga", "cf", "gq", "su", "pw", "nu",
    # Educational / govt
    "edu", "gov", "mil", "int",
    # XML / IDN punycode markers (for benign infra appearing in samples)
    "arpa",
}

# Source-file pseudo-TLDs (common in compiled Go / Nim / Rust / Python
# binaries) — even if a label like "go" or "rs" matches a real TLD,
# certain combinations are unmistakably source filenames, not hosts.
# Filtered separately so they're never counted as IOCs.
_SOURCE_PSEUDO_TLDS = {
    "go", "nim", "rs", "py", "rb", "lua", "swift", "kt", "ts", "tsx",
    "vb", "cs", "fs", "hs", "ml", "cpp", "cxx", "hpp", "hxx", "asm",
    "s", "S", "def", "exp", "pyx", "pyi", "pxd",
}

# Go standard-library package names. When a 2-label "domain" begins with
# one of these AND ends in a short Go-internal-style word (link, group,
# pin, recv, send, gc, …), it's almost certainly a Go runtime symbol
# leaking through the .symtab section, not a real host.
_GO_STDLIB_PACKAGES = {
    "runtime", "syscall", "fmt", "errors", "os", "io", "net", "http",
    "url", "tls", "crypto", "hash", "sql", "sync", "atomic", "time",
    "context", "reflect", "strconv", "strings", "bytes", "bufio",
    "unicode", "regexp", "sort", "path", "filepath", "encoding",
    "json", "xml", "csv", "base64", "base32", "hex", "binary", "pem",
    "math", "rand", "big", "log", "flag", "testing", "compress",
    "gzip", "flate", "zlib", "lzw", "tar", "zip", "image", "gif",
    "jpeg", "png", "color", "draw", "html", "template", "text",
    "container", "list", "ring", "heap", "database", "debug",
    "elf", "macho", "pe", "plan9", "ast", "build", "doc", "format",
    "importer", "parser", "printer", "scanner", "token", "types",
    "internal", "mime", "multipart", "quotedprintable", "smtp", "mail",
    "textproto", "syslog", "user", "exec", "signal", "expvar", "trace",
    "pprof", "cgo", "unsafe", "gob", "asn1", "elliptic", "rsa", "dsa",
    "ecdsa", "ed25519", "aes", "des", "rc4", "cipher", "hmac", "md5",
    "sha1", "sha256", "sha512", "subtle", "x509", "constant", "chan",
    "iter", "any", "map",
}

# Short identifier-style words that frequently appear as the second label
# of Go runtime symbols. These collide with real TLDs (.link, .group, …)
# but in combination with a Go stdlib first label they are diagnostic
# of leaked debug symbols, not network hosts.
_GO_SYMBOL_TLDS = {
    "link", "group", "pin", "recv", "send", "gc", "now", "lock",
    "unlock", "wait", "signal", "sleep", "tick", "panic", "goexit",
    "init", "main", "new", "make", "len", "cap", "copy", "append",
    "close", "delete", "print", "println", "recover", "complex",
    "real", "imag", "string", "int", "uint", "bool", "byte", "rune",
    "float", "error", "true", "false", "nil",
}

# Version-string patterns that look like IPs (e.g. "6.0.0.0", "14.0.0.0").
_VERSION_LIKE_RE = re.compile(r"^\d{1,2}\.0\.0\.\d{1,2}$")

# Common Windows system paths that are FPs.
_FP_PATH_PREFIXES = (
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Windows\\Microsoft.NET",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
)

# Minimum domain segment count (single-label names are FPs).
_MIN_DOMAIN_LABELS = 2

# File-extension-like strings that look like TLDs but aren't domains.
_FP_TLDS = {
    "config", "xml", "txt", "json", "log", "dat", "ini", "cfg",
    "sqlite", "db", "bak", "tmp", "old", "orig", "lock",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg",
    "html", "htm", "css", "csv", "tsv",
    "zip", "gz", "tar", "rar",
    "pdb", "lib", "obj", "res", "manifest",
}

# Maximum number of IOCs to store per category.
_MAX_IOCS_PER_CATEGORY = 50


def run(file_path: Path, config: dict) -> dict:
    """Extract IOCs from the file's string content.

    Reads the file as bytes, extracts printable strings, then applies
    IOC regexes with false-positive filtering.

    If a string_analysis module has already run upstream, we also
    check the pipeline for its extracted strings — but since modules
    run independently, we do our own extraction here for reliability.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict.

    Returns:
        Standard module result dict.
    """
    strings = _extract_strings(file_path)
    if not strings:
        return {
            "module": "ioc_extractor",
            "status": "success",
            "data": {"iocs": {}, "total_iocs": 0},
            "score_delta": 0,
            "reason": "No strings extracted — no IOCs found",
        }

    # Join all strings for regex scanning.
    blob = "\n".join(strings)

    iocs: dict[str, list[str]] = {}
    for ioc_type, pattern in _IOC_PATTERNS.items():
        matches = set(pattern.findall(blob))
        filtered = _filter_fps(ioc_type, matches)
        if filtered:
            iocs[ioc_type] = sorted(filtered)[:_MAX_IOCS_PER_CATEGORY]

    total = sum(len(v) for v in iocs.values())

    # Score based on IOC findings.
    score_delta = 0
    reasons: list[str] = []

    # Network IOCs (URLs, non-private IPs, domains) are significant.
    network_iocs = len(iocs.get("url", [])) + len(iocs.get("ipv4", []))
    if network_iocs > 0:
        score_delta += 10
        reasons.append(f"Network IOCs found: {network_iocs} URLs/IPs")

    # Suspicious domains (after filtering benign ones).
    suspicious_domains = iocs.get("domain", [])
    if suspicious_domains:
        score_delta += 5
        top = suspicious_domains[:3]
        suffix = f" (+{len(suspicious_domains) - 3} more)" if len(suspicious_domains) > 3 else ""
        reasons.append(f"Domains: {', '.join(top)}{suffix}")

    # Registry keys suggest persistence / system modification.
    reg_keys = iocs.get("registry_key", [])
    if reg_keys:
        score_delta += 5
        reasons.append(f"{len(reg_keys)} registry key reference(s)")

    # Email addresses — potential C2 or exfil target.
    emails = iocs.get("email", [])
    if emails:
        score_delta += 5
        reasons.append(f"{len(emails)} email address(es) found")

    reason_text = "; ".join(reasons) if reasons else "No significant IOCs found"

    return {
        "module": "ioc_extractor",
        "status": "success",
        "data": {
            "iocs": iocs,
            "total_iocs": total,
        },
        "score_delta": score_delta,
        "reason": reason_text,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_MAX_READ_SIZE = 50 * 1024 * 1024  # 50 MiB


def _extract_strings(file_path: Path) -> list[str]:
    """Extract printable ASCII and UTF-16LE strings from the file."""
    try:
        with file_path.open("rb") as fh:
            data = fh.read(_MAX_READ_SIZE)
    except OSError as exc:
        logger.warning("Could not read file for IOC extraction: %s", exc)
        return []

    ascii_strings = [m.group().decode("ascii") for m in _ASCII_RE.finditer(data)]

    wide_strings = []
    for m in _WIDE_RE.finditer(data):
        try:
            wide_strings.append(m.group().decode("utf-16-le"))
        except UnicodeDecodeError:
            continue

    # Deduplicate while preserving order.
    seen: set[str] = set()
    result: list[str] = []
    for s in ascii_strings + wide_strings:
        if s not in seen:
            seen.add(s)
            result.append(s)

    return result


def _filter_fps(ioc_type: str, matches: set[str]) -> set[str]:
    """Remove known false positives from a set of IOC matches."""
    if ioc_type == "ipv4":
        return _filter_ip_fps(matches)
    if ioc_type == "domain":
        return _filter_domain_fps(matches)
    if ioc_type == "url":
        return _filter_url_fps(matches)
    if ioc_type == "windows_path":
        return _filter_path_fps(matches)
    if ioc_type == "email":
        return _filter_email_fps(matches)
    return matches


# URL substrings that indicate the URL is a benign XML namespace, schema
# reference, or version-info pointer rather than a real network endpoint.
_FP_URL_SUBSTRINGS = (
    "tempuri.org",
    "schemas.microsoft.com",
    "schemas.xmlsoap.org",
    "schemas.openxmlformats.org",
    "schemas.datacontract.org",
    "www.w3.org",
    "ns.adobe.com",
    "purl.org",
    "ocsp.digicert.com",
    "crl.digicert.com",
    "ocsp.verisign.com",
    "crl.verisign.com",
    "go.microsoft.com/fwlink",
)


def _filter_url_fps(urls: set[str]) -> set[str]:
    """Drop URLs whose host is a known XML/namespace/schema artefact.

    Many .NET binaries embed http://tempuri.org/* and similar URLs as
    XML namespaces — they are not C2 endpoints and should not inflate
    the network IOC count.
    """
    result: set[str] = set()
    for url in urls:
        lower = url.lower()
        if any(fp in lower for fp in _FP_URL_SUBSTRINGS):
            continue
        result.add(url)
    return result


def _filter_ip_fps(ips: set[str]) -> set[str]:
    """Filter false-positive IPv4 addresses."""
    result: set[str] = set()
    for ip in ips:
        if ip in _FP_IPS:
            continue
        if any(ip.startswith(p) for p in _FP_IP_PREFIXES):
            continue
        if _VERSION_LIKE_RE.match(ip):
            continue
        # Validate each octet is 0-255 (regex allows 999.999...).
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            result.add(ip)
    return result


def _filter_domain_fps(domains: set[str]) -> set[str]:
    """Filter false-positive domain names.

    Strategy: require the TLD to be in a curated allow-list of real
    public-suffix TLDs. This drops the bulk of source-filename and
    code-identifier matches that plague Go / Nim / Rust / .NET binaries
    while still catching real C2 domains.
    """
    result: set[str] = set()
    for domain in domains:
        lower = domain.lower()
        if lower in _FP_DOMAINS:
            continue
        # Filter single-label names (not real domains).
        labels = lower.split(".")
        if len(labels) < _MIN_DOMAIN_LABELS:
            continue
        # Filter DLL/exe names that match domain pattern.
        if lower.endswith((".dll", ".exe", ".sys", ".ocx", ".drv",
                           ".pdb", ".lib", ".obj", ".so", ".dylib")):
            continue
        # Filter known Microsoft / system domains.
        if lower.endswith((".microsoft.com", ".windows.com",
                           ".windowsupdate.com", ".live.com",
                           ".microsoftonline.com", ".office.com",
                           ".office365.com", ".apple.com", ".icloud.com")):
            continue
        # Filter version-like strings (e.g., "v2.0.50727").
        if any(c.isdigit() for c in labels[0]) and labels[0][0].isdigit():
            continue
        # Filter domains that are too short overall (e.g., "C.dE", "B.SE").
        if len(lower) < 6:
            continue
        # Filter camelCase / PascalCase identifiers (code, not domains).
        # Real domains are lowercase; .NET names like "BCrypt.BCryptGetProperty"
        # and Go names like "byteOrder.Uint64" have mixed case.
        if any(c.isupper() for c in domain):
            continue
        tld = labels[-1]
        # Source-filename pseudo-TLDs (.go, .nim, .rs, .py, …) — never
        # counted, even though some collide with real ccTLDs.
        if tld in _SOURCE_PSEUDO_TLDS:
            continue
        # Filter file-extension-like pseudo-TLDs (.config, .json, …).
        if tld in _FP_TLDS:
            continue
        # The decisive check: TLD must look like a real public suffix.
        if tld not in _REAL_TLDS:
            continue
        # Filter random-looking domains: any label with no vowels is suspicious.
        vowels = set("aeiou")
        if any(len(lab) > 2 and not (set(lab) & vowels) for lab in labels):
            continue
        # Require at least one label (excluding TLD) to be >= 3 chars.
        non_tld_labels = labels[:-1]
        if all(len(lab) < 3 for lab in non_tld_labels):
            continue
        # Drop "schemas.<anything>" — XML namespace artefacts.
        if labels[0] == "schemas":
            continue
        # Drop Go runtime symbols leaking through .symtab as 2-label
        # "domains" (e.g. runtime.link, map.group, chan.recv, time.now).
        if (
            len(labels) == 2
            and labels[0] in _GO_STDLIB_PACKAGES
            and tld in _GO_SYMBOL_TLDS
        ):
            continue
        result.add(domain)
    return result


def _filter_path_fps(paths: set[str]) -> set[str]:
    """Filter false-positive Windows file paths."""
    result: set[str] = set()
    for path in paths:
        # Skip standard system paths.
        if any(path.startswith(prefix) for prefix in _FP_PATH_PREFIXES):
            continue
        # Very short paths are usually FPs (e.g., "C:\\").
        if len(path) <= 4:
            continue
        result.add(path)
    return result


def _filter_email_fps(emails: set[str]) -> set[str]:
    """Filter false-positive email addresses."""
    result: set[str] = set()
    for email in emails:
        lower = email.lower()
        # Filter obviously fake/placeholder emails.
        if lower.endswith(("@example.com", "@test.com", "@localhost")):
            continue
        # Filter Microsoft/system addresses.
        if lower.endswith(("@microsoft.com",)):
            continue
        result.add(email)
    return result
