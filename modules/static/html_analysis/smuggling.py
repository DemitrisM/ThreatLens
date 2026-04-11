"""HTML smuggling detection — Passes 2 and 3.

Pass 2 — Base64 blob detection and payload extraction:
  Locates large base64 strings in inline script content, decodes them,
  identifies embedded payloads by magic bytes (PE/ZIP/OLE2/RAR/7z/…),
  and computes a SHA256 of each decoded payload.  A second-pass scan
  runs on blobs that decode to JavaScript, catching two-stage samples
  like FormBook+xloader where the outer eval(atob()) contains a second
  base64 blob that is the actual binary payload.

Pass 3 — Smuggling mechanism sweep:
  Pattern-matches the full HTML text for atob(), Blob creation,
  URL.createObjectURL, auto-click download triggers, window.onload,
  and navigator.msSaveOrOpenBlob.

No external dependencies beyond stdlib (base64, binascii, hashlib, re).
"""

import base64
import binascii
import hashlib
import logging
import re

logger = logging.getLogger(__name__)

# ── Limits ────────────────────────────────────────────────────────────────────

# Minimum base64 string length to be worth examining (~900 decoded bytes).
_B64_MIN_CHARS = 1200
# Maximum bytes to decode fully per blob (50 MiB memory guard).
_B64_DECODE_CAP = 50 * 1024 * 1024
# Maximum blobs to analyse per file (time guard).
_MAX_BLOBS = 20

# ── Magic-byte table (longest prefix first to avoid short-prefix false matches) ──

_MAGIC_MAP: list[tuple[bytes, str]] = [
    (b"\x4d\x5a\x90\x00",     "PE"),       # MZ\x90 — most common PE header
    (b"\x4d\x5a",             "PE"),       # MZ — generic Windows executable
    (b"\x50\x4b\x07\x08",     "ZIP"),
    (b"\x50\x4b\x05\x06",     "ZIP"),
    (b"\x50\x4b\x03\x04",     "ZIP"),      # PK — ZIP / Office OpenXML / JAR
    (b"\x52\x61\x72\x21\x1a", "RAR"),      # Rar!
    (b"\x37\x7a\xbc\xaf\x27", "7-Zip"),
    (b"\xd0\xcf\x11\xe0",     "OLE2"),     # Office 97–2003 compound doc / MSI
    (b"\x7b\x5c\x72\x74\x66", "RTF"),      # {\rtf
    (b"\x25\x50\x44\x46",     "PDF"),      # %PDF
    (b"\x4d\x53\x43\x46",     "CAB"),      # MSCF — Windows Cabinet
    (b"\x1f\x8b",             "gzip"),
]

# ── Known-benign base64 prefixes to skip (avoids decoding large legit blobs) ──
# These are base64 encodings of JPEG/PNG/GIF/WebP magic bytes.
_SKIP_B64_PREFIXES: frozenset[str] = frozenset({
    "/9j/",   # JPEG (0xFF 0xD8 0xFF)
    "iVBOR",  # PNG  (0x89 0x50 0x4E)
    "R0lGO",  # GIF
    "UklGR",  # RIFF (WebP/WAV)
    "AAAB",   # common ICO header
})

# ── Dangerous download extensions ──────────────────────────────────────────────
_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".wsf", ".hta", ".msi", ".js", ".jse", ".lnk", ".scr",
    ".pif", ".jar", ".cab", ".cpl", ".msc", ".reg",
})

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Base64 strings ≥ _B64_MIN_CHARS inside JS string literals (quote-delimited).
_B64_RE = re.compile(
    r"""(?:["'`])([A-Za-z0-9+/\r\n\t ]{"""
    + str(_B64_MIN_CHARS)
    + r""",}={0,3})(?:["'`])""",
    re.DOTALL,
)

# Nearby download= attribute for filename extraction.
_DOWNLOAD_ATTR_RE = re.compile(r"""\.download\s*=\s*['"]([^'"]{1,120})['"]""")
_DOWNLOAD_HTML_RE = re.compile(r"""download\s*=\s*['"]([^'"]{1,120})['"]""")

# ── Smuggling mechanism patterns (Pass 3) ─────────────────────────────────────

_MECH_PATTERNS: dict[str, re.Pattern] = {
    "has_atob":               re.compile(r"\batob\s*\("),
    "has_eval_atob":          re.compile(r"\beval\s*\(\s*atob\s*\("),
    "has_blob_creation":      re.compile(r"\bnew\s+Blob\s*\("),
    "has_blob_url":           re.compile(
        r"\bURL\.createObjectURL\s*\(|window\.URL\.createObjectURL\s*\("
    ),
    "has_mssave":             re.compile(
        r"\bnav(?:igator)?\.msSave(?:OrOpen)?Blob\s*\(|window\.navigator\.msSave"
    ),
    "has_auto_download":      re.compile(
        r"\.download\s*=\s*['\"]|link\.click\s*\(\s*\)|a\.click\s*\(\s*\)"
    ),
    "has_onload_trigger":     re.compile(
        r"\bwindow\.onload\s*=|window\.addEventListener\s*\(\s*['\"]load['\"]"
    ),
    "has_window_loc_blob":    re.compile(
        r"window\.location(?:\.href)?\s*=\s*(?:url|blobUrl|objectUrl|blob)\b"
    ),
    "has_data_uri_link":      re.compile(r"""href\s*=\s*['"]data:application/"""),
    "has_settimeout_exec":    re.compile(r"\bsetTimeout\s*\("),
}


def detect_mechanisms(html_text: str) -> dict:
    """Return a dict of smuggling-mechanism boolean flags for the full HTML text."""
    return {key: bool(pat.search(html_text)) for key, pat in _MECH_PATTERNS.items()}


def find_base64_blobs(
    script_blocks: list[str],
    html_text: str,
) -> tuple[list[dict], list[str], bool]:
    """Find and characterise large base64 blobs in script content.

    Returns:
        blobs:           list of blob descriptor dicts (metadata only, no raw bytes)
        dangerous_exts:  distinct dangerous extensions found in download filenames
        has_double_ext:  True if any filename has a double extension (.pdf.exe)
    """
    all_blobs: list[dict] = []
    dangerous_exts: list[str] = []
    has_double_ext = False
    seen_prefixes: set[str] = set()

    # Pass 2a: primary scan — script blocks + full HTML.
    sources = script_blocks + [html_text]
    for source in sources:
        _scan_source(source, all_blobs, seen_prefixes, dangerous_exts,
                     nested=False, limit=_MAX_BLOBS)

    # Pass 2b: secondary scan — decode any "JavaScript" blobs and search their
    # content for nested binary payloads (e.g. FormBook outer eval(atob()) shell).
    js_blobs_to_expand = [b for b in list(all_blobs) if b.get("decoded_magic") == "JavaScript"
                          and b.get("_decoded") is not None]
    for blob in js_blobs_to_expand:
        if len(all_blobs) >= _MAX_BLOBS:
            break
        try:
            decoded_text = blob["_decoded"].decode("utf-8", errors="replace")
            _scan_source(decoded_text, all_blobs, seen_prefixes, dangerous_exts,
                         nested=True, limit=_MAX_BLOBS)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Nested blob scan failed: %s", exc)

    # Strip internal _decoded bytes before returning.
    clean_blobs: list[dict] = []
    for blob in all_blobs:
        clean = {k: v for k, v in blob.items() if k != "_decoded"}
        if clean.get("double_extension"):
            has_double_ext = True
        clean_blobs.append(clean)

    return clean_blobs, list(dict.fromkeys(dangerous_exts)), has_double_ext


def _scan_source(
    text: str,
    blobs: list[dict],
    seen_prefixes: set[str],
    dangerous_exts: list[str],
    nested: bool,
    limit: int,
) -> None:
    """Scan a text source for base64 blobs and append findings to blobs."""
    for m in _B64_RE.finditer(text):
        if len(blobs) >= limit:
            return

        raw = m.group(1).translate(str.maketrans("", "", " \t\r\n"))

        # Deduplicate by first 32 chars.
        prefix = raw[:32]
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)

        # Skip known-benign image blobs.
        if any(raw.startswith(skip) for skip in _SKIP_B64_PREFIXES):
            continue

        blob_info = _characterise_blob(raw)
        if blob_info is None:
            continue

        if nested:
            blob_info["from_nested_decode"] = True

        # Look for a nearby download= attribute.
        start = m.start()
        context = text[max(0, start - 600): start + 600]
        suggested = _extract_download_name(context)
        if suggested:
            blob_info["suggested_filename"] = suggested
            ext = _last_extension(suggested).lower()
            if ext in _DANGEROUS_EXTENSIONS:
                if ext not in dangerous_exts:
                    dangerous_exts.append(ext)
                blob_info["dangerous_extension"] = True
            else:
                blob_info["dangerous_extension"] = False
            # Double-extension check: name.pdf.exe, name..exe, etc.
            parts = suggested.lower().rsplit(".", 2)
            blob_info["double_extension"] = (
                len(parts) >= 3
                and f".{parts[-1]}" in _DANGEROUS_EXTENSIONS
            )
        else:
            blob_info["suggested_filename"] = ""
            blob_info["dangerous_extension"] = False
            blob_info["double_extension"] = False

        blobs.append(blob_info)


def _characterise_blob(raw_b64: str) -> dict | None:
    """Decode a base64 string and return its characteristics, or None if invalid.

    The returned dict includes an internal ``_decoded`` key (bytes | None)
    used for the nested-scan second pass; callers strip it before returning
    to the reporter layer.
    """
    # Validate: length must be ≥ min and modular remainder must allow padding.
    stripped = raw_b64.rstrip("=")
    if len(stripped) % 4 not in (0, 2, 3):
        return None

    # Decode just the first 16 bytes to check magic (fast path).
    head_raw = raw_b64[:24] + "=" * (-len(raw_b64[:24]) % 4)
    try:
        head_bytes = base64.b64decode(head_raw, validate=False)
    except (binascii.Error, ValueError):
        return None

    magic_type = _identify_magic(head_bytes)
    estimated_size = (len(raw_b64) * 3) // 4

    # If the blob is too large to fully decode, return a size-only record.
    if estimated_size > _B64_DECODE_CAP:
        return {
            "size_bytes": estimated_size,
            "decoded_magic": magic_type or "unknown",
            "sha256": None,
            "_decoded": None,
        }

    # Full decode.
    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
    try:
        decoded = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError, MemoryError):
        return None

    sha256 = hashlib.sha256(decoded).hexdigest()
    actual_size = len(decoded)

    # Refine magic type from full decoded bytes.
    full_magic = _identify_magic(decoded[:16])
    magic_type = full_magic or magic_type

    # Check if decoded content is readable JavaScript (two-stage smuggling).
    if magic_type is None:
        magic_type = _probe_text_type(decoded)

    return {
        "size_bytes": actual_size,
        "decoded_magic": magic_type or "unknown",
        "sha256": sha256,
        "_decoded": decoded if magic_type == "JavaScript" else None,
    }


def _identify_magic(data: bytes) -> str | None:
    for magic_bytes, label in _MAGIC_MAP:
        if data[:len(magic_bytes)] == magic_bytes:
            return label
    return None


def _probe_text_type(decoded: bytes) -> str | None:
    """Try to detect JavaScript or other text payload."""
    try:
        sample = decoded[:300].decode("utf-8", errors="strict")
        js_keywords = ("var ", "function", "const ", "let ", "window.", "document.")
        if any(kw in sample for kw in js_keywords):
            return "JavaScript"
    except UnicodeDecodeError:
        pass
    return None


def _extract_download_name(context: str) -> str:
    m = _DOWNLOAD_ATTR_RE.search(context)
    if m:
        return m.group(1)
    m = _DOWNLOAD_HTML_RE.search(context)
    if m:
        return m.group(1)
    return ""


def _last_extension(filename: str) -> str:
    idx = filename.rfind(".")
    return filename[idx:] if idx != -1 else ""
