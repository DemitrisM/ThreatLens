"""Indicator of Compromise (IOC) extraction module.

Applies regex patterns against extracted strings to identify IPv4 addresses,
URLs, domains, Windows file paths, registry keys, email addresses, and other
IOCs. Filters known false positives.
Returns a standard module result dict with score_delta and reason.

Design notes
------------
The regexes are the easy half. Extracting dotted quads and http:// URLs from
a binary takes six patterns; making the result *usable* takes the six hundred
lines of false-positive filtering below, because a compiled binary is full of
strings that look exactly like indicators and are not. A Go executable leaks
its symbol table as "runtime.link" and "chan.recv"; a .NET assembly embeds
"http://tempuri.org/"; every PE names a dozen DLLs that parse as domains; and
"6.0.0.0" is a version string in every second import descriptor. Reporting
those as IOCs is worse than reporting nothing, because an analyst who pastes
one into a threat feed and gets a shrug stops trusting the whole section.

The filters are therefore allow-list shaped wherever an allow-list is
possible. Requiring the final label to be a known public suffix drops every
source filename (arena.go, lib.rs, fatal.nim) in one rule, without a deny
list that grows by one entry per language the tool meets. The cost is that a
domain on a TLD missing from ``_REAL_TLDS`` is silently lost, which is why
that set is the first place to look when a real C2 fails to appear.

Filter *order* inside _filter_domain_fps() is load-bearing: the cheap
membership tests run before the character scans, and the pseudo-TLD check
runs before the real-TLD check, so a label present in both sets resolves as a
source filename rather than a host.

String extraction is done here rather than reused from string_analysis. The
duplication is deliberate — modules must stand alone under ``--modules``
(a scan of ioc_extractor alone has no upstream to read from), and
string_analysis may itself be skipped when FLOSS is absent.
"""

import ipaddress
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IOC regex patterns (from the project specification)
#
# All six are applied to one newline-joined blob of every extracted string,
# so a pattern must not rely on anchors: \b does the work instead. The IPv4
# pattern validates octet range in the regex itself (25[0-5]|2[0-4]\d|…)
# rather than post-hoc, which is what keeps 999.1.1.1 out of the match set
# before any filter sees it — though _filter_ip_fps still re-parses through
# the stdlib, since the regex cannot express "not a version number".
#
# The URL pattern excludes % deliberately: percent-encoded bytes are how a
# long run of binary data ends up looking like one enormous URL. Truncating
# at the first % costs the query string of a legitimate encoded URL and buys
# immunity from multi-kilobyte garbage matches.
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
#
# These survive the ipaddress-module check in _filter_ip_fps because they are
# genuinely routable-looking (1.0.0.1 is a real Cloudflare resolver), yet in a
# PE they are overwhelmingly version numbers or subnet masks. Listed by exact
# value rather than by range: the point is that these *specific* quads carry
# no signal, not that their networks are uninteresting.
_FP_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "255.255.255.0", "255.255.0.0", "255.0.0.0",
    "1.0.0.0", "1.0.0.1",  # version-like
    "2.0.0.0", "3.0.0.0", "4.0.0.0", "6.0.0.0",
}

# Common DLL and system file names that trigger domain/path FPs.
#
# A DLL name is a two-label dotted string, so "kernel32.dll" is structurally
# indistinguishable from a domain. _filter_domain_fps() also rejects the .dll
# suffix generically; this exact-match set exists for the cases the generic
# rules cannot reach — real hostnames on real TLDs that are simply never
# interesting (certificate OCSP responders, XML namespace hosts, Microsoft
# update endpoints), which no structural rule could distinguish from C2.
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
#
# This set is checked BEFORE _REAL_TLDS, so any label appearing in both is
# resolved as a source extension. That is the right trade for .go and .py —
# a panic path from the Go runtime appears in every Go binary, while .py as
# a hostname suffix does not exist — but it means an entry added to both
# sets is unreachable in _REAL_TLDS, which is a silent loss rather than an
# error. Check this set first when a domain on a short ccTLD goes missing.
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
#
# Deliberately narrow: it requires the two middle octets to be exactly zero,
# which is the shape of a PE version resource and not of a real address.
# A looser "any four small numbers" rule would eat 10.20.30.40-style C2.
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
# Applied after sorting, so truncation is alphabetical rather than by
# interest. Acceptable because a sample emitting more than fifty domains is
# one where the analyst needs the raw strings anyway, not a longer table.
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
        config:    Pipeline configuration dict. Not read — the module has
                   no tunables, which is why it behaves identically under
                   every scan profile.

    Returns:
        Standard module result dict. ``data["iocs"]`` maps category name to
        a sorted, capped list; categories with nothing left after filtering
        are omitted entirely rather than carried as empty lists, so the
        reporters can treat presence as significance.
    """
    # ------------------------------------------------------------------
    # Phase 1: Pull printable strings out of the file.
    #
    # An unreadable file and a file genuinely containing no printable runs
    # are not distinguished here — both yield an empty list. file_intake
    # has already errored on a path that cannot be opened, so a scan as a
    # whole is not misled, but the status below is optimistic for the
    # unreadable case. Tracked in CLAUDE.md under "Still open".
    # ------------------------------------------------------------------
    strings = _extract_strings(file_path)
    if not strings:
        return {
            "module": "ioc_extractor",
            "status": "success",
            "data": {"iocs": {}, "total_iocs": 0},
            "score_delta": 0,
            "reason": "No strings extracted — no IOCs found",
        }

    # ------------------------------------------------------------------
    # Phase 2: Sweep every pattern over one joined blob, then filter.
    #
    # Joining with "\n" rather than "" matters: concatenating adjacent
    # strings would manufacture indicators that never existed in the file,
    # gluing a trailing "http://" onto whatever string followed it. The
    # newline is also excluded from every pattern's character class, so it
    # acts as a hard boundary rather than merely a separator.
    #
    # set() before filtering: a string table repeats the same domain
    # hundreds of times, and dedup before the per-item filters is what
    # keeps the character-level scans in _filter_domain_fps cheap.
    # ------------------------------------------------------------------
    blob = "\n".join(strings)

    iocs: dict[str, list[str]] = {}
    for ioc_type, pattern in _IOC_PATTERNS.items():
        matches = set(pattern.findall(blob))
        filtered = _filter_fps(ioc_type, matches)
        if filtered:
            iocs[ioc_type] = sorted(filtered)[:_MAX_IOCS_PER_CATEGORY]

    # Counted after the cap, so total_iocs describes what is reported
    # rather than what was found. The two differ only past fifty in a
    # category, where the exact number has stopped being actionable.
    total = sum(len(v) for v in iocs.values())

    # ------------------------------------------------------------------
    # Phase 3: Score.
    #
    # The weights are deliberately small (10 + 5 + 5 + 5 = 25 maximum, and
    # only for a sample tripping all four). IOCs are *context*, not a
    # verdict: benign installers carry URLs, registry keys and support
    # email addresses too. What earns the score here is the presence of
    # network reachability at all, not any judgement about the endpoint —
    # that judgement belongs to VirusTotal and the YARA rules.
    # ------------------------------------------------------------------
    score_delta = 0
    reasons: list[str] = []

    # URLs and IPs share one flat contribution rather than scoring per
    # item: a dropper with one hardcoded C2 is no less dangerous than one
    # with forty, and per-item scoring would rank a chatty installer above
    # a targeted implant. Domains are scored separately and lower because
    # they survive a much weaker filter than the two above.
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

    # A registry key in the string table is only ever a hint — the module
    # cannot tell a Run-key write from a settings read, which is why this
    # scores the same 5 as an email address and leaves the distinction to
    # string_analysis, whose patterns are persistence-aware.
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
    """Extract printable ASCII and UTF-16LE strings from the file.

    Args:
        file_path: File to read. Only the first ``_MAX_READ_SIZE`` bytes
                   are examined.

    Returns:
        Deduplicated strings in encounter order — ASCII runs first, then
        UTF-16LE. Empty on any read error, which the caller reports as a
        successful scan with no IOCs.
    """
    # A bounded read, not a stream: 50 MiB of a sample is far past the point
    # where more strings add information, and an unbounded read on a padded
    # 4 GiB installer would hold the whole file in memory for the regexes.
    try:
        with file_path.open("rb") as fh:
            data = fh.read(_MAX_READ_SIZE)
    except OSError as exc:
        logger.warning("Could not read file for IOC extraction: %s", exc)
        return []

    # decode("ascii") is safe without a guard because _ASCII_RE only ever
    # matches bytes in the printable range, unlike the UTF-16 pass below
    # where a lone surrogate can still make the decode fail.
    ascii_strings = [m.group().decode("ascii") for m in _ASCII_RE.finditer(data)]

    # UTF-16LE is scanned separately rather than by decoding the whole file:
    # a PE interleaves wide and narrow strings, so any whole-file decode is
    # wrong for half of it.
    wide_strings = []
    for m in _WIDE_RE.finditer(data):
        try:
            wide_strings.append(m.group().decode("utf-16-le"))
        except UnicodeDecodeError:
            continue

    # Order-preserving dedup rather than a set, so the blob the regexes see
    # keeps the file's own layout. It costs nothing here and makes the
    # extraction reproducible, which the snapshot tests depend on.
    seen: set[str] = set()
    result: list[str] = []
    for s in ascii_strings + wide_strings:
        if s not in seen:
            seen.add(s)
            result.append(s)

    return result


def _filter_fps(ioc_type: str, matches: set[str]) -> set[str]:
    """Remove known false positives from a set of IOC matches.

    Args:
        ioc_type: Category key from ``_IOC_PATTERNS``.
        matches:  Raw regex hits for that category.

    Returns:
        The surviving matches. Categories with no dedicated filter —
        currently only ``registry_key``, which the pattern already
        constrains to an HKEY_ prefix — pass through untouched.
    """
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
#
# Matched as substrings of the whole URL, not of its host — which is why
# "go.microsoft.com/fwlink" can appear here as a path-bearing entry. The
# looseness is a known weakness: a benign substring anywhere in the URL,
# including its query string, suppresses the match.
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

    Args:
        urls: Candidate URLs from the regex sweep.

    Returns:
        URLs with no known-benign substring. Case-folded for the test only;
        the original casing is preserved in the output, since a URL path is
        case-sensitive and the analyst may need it verbatim.
    """
    result: set[str] = set()
    for url in urls:
        lower = url.lower()
        if any(fp in lower for fp in _FP_URL_SUBSTRINGS):
            continue
        result.add(url)
    return result


def _filter_ip_fps(ips: set[str]) -> set[str]:
    """Filter false-positive IPv4 addresses.

    Args:
        ips: Candidate dotted quads straight from the regex sweep.

    Returns:
        Only addresses that could plausibly be an external indicator.

    Non-routable addresses are dropped through the stdlib ``ipaddress``
    module rather than a list of string prefixes. The prefix list this
    replaced omitted 172.16.0.0/12 entirely, so every internal address
    from 172.16.x to 172.31.x — a whole RFC 1918 block, and the default
    range for Docker bridge networks — was reported as an external IOC.
    Prefix strings cannot express a /12 without enumerating sixteen of
    them, which is exactly how that gap survived.
    """
    result: set[str] = set()
    for ip in ips:
        if ip in _FP_IPS:
            continue
        if _VERSION_LIKE_RE.match(ip):
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # The regex admits things like 999.1.1.1; ip_address does not.
            continue
        # Everything that cannot appear as an external C2: RFC 1918
        # private space, loopback, link-local, multicast, and the
        # reserved and unspecified ranges.
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved
                or addr.is_unspecified):
            continue
        result.add(ip)
    return result


def _filter_domain_fps(domains: set[str]) -> set[str]:
    """Filter false-positive domain names.

    Strategy: require the TLD to be in a curated allow-list of real
    public-suffix TLDs. This drops the bulk of source-filename and
    code-identifier matches that plague Go / Nim / Rust / .NET binaries
    while still catching real C2 domains.

    Args:
        domains: Candidate dotted names from the regex sweep, in their
                 original casing.

    Returns:
        The survivors, original casing preserved.

    The checks below are ordered cheapest-first — set membership, then
    length and suffix tests, then the per-character scans — because this
    runs once per unique candidate and a Go binary can offer thousands.
    Each check is a separate early ``continue`` rather than one compound
    condition so that a rule can be removed or reordered on its own; the
    only ordering that carries meaning is _SOURCE_PSEUDO_TLDS before
    _REAL_TLDS, described at the pseudo-TLD set above.
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
        # Keyed on the first label starting with a digit, which is what
        # separates "2.0.50727.4927" from a hostname. The cost is that a
        # real domain beginning with a digit is lost with it.
        if any(c.isdigit() for c in labels[0]) and labels[0][0].isdigit():
            continue
        # Filter domains that are too short overall (e.g., "C.dE", "B.SE").
        # Six characters is the shortest a plausible host reaches once a
        # two-letter TLD and a dot are accounted for; below that the match
        # is nearly always an abbreviation pair from a symbol table.
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
        # Any label longer than two characters with no vowel at all reads
        # as an identifier or a hash fragment rather than a name. Note this
        # also rejects genuinely random DGA domains, which is a deliberate
        # trade: DGA output belongs to string_analysis and the YARA rules,
        # while an IOC list is only useful when its entries are pastable.
        vowels = set("aeiou")
        if any(len(lab) > 2 and not (set(lab) & vowels) for lab in labels):
            continue
        # A hostname whose every non-TLD label is one or two characters is
        # far more often an initialism from code ("a.b.com") than a host.
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
    """Filter false-positive Windows file paths.

    Args:
        paths: Candidate ``X:\\...`` paths from the regex sweep.

    Returns:
        Paths outside the standard system locations.

    Only the well-known system roots are dropped. A path under AppData,
    ProgramData, Temp or a user profile is kept even though benign software
    writes there constantly, because those are exactly the directories
    droppers stage payloads in — the false positives are worth the recall.
    """
    result: set[str] = set()
    for path in paths:
        # Prefix match, and case-sensitive: a lowercased "c:\\windows" in a
        # sample is worth seeing, since the system itself always emits the
        # canonical casing.
        if any(path.startswith(prefix) for prefix in _FP_PATH_PREFIXES):
            continue
        # Very short paths are usually FPs (e.g., "C:\\").
        if len(path) <= 4:
            continue
        result.add(path)
    return result


def _filter_email_fps(emails: set[str]) -> set[str]:
    """Filter false-positive email addresses.

    Args:
        emails: Candidate addresses from the regex sweep.

    Returns:
        Addresses that are neither placeholders nor Microsoft's own.

    Kept short on purpose. An email address in a binary is rare enough to
    be worth reporting even when it turns out to be a developer's, so this
    filter only removes the two categories that are never informative:
    documentation placeholders and vendor contact addresses.
    """
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
