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

Design notes
------------
HTML smuggling never downloads the payload. The bytes arrive inside the
page as a base64 literal and the browser assembles them locally, so no
network inspection sees a file transfer and no download reputation
applies. The payload is therefore *present in the file being analysed*,
which is what makes this statically decidable at all.

Detection is in two halves for that reason. Pass 2 recovers the payload
and identifies it by magic bytes; pass 3 looks for the assembly
mechanism — atob, Blob, createObjectURL, a synthetic click. Either alone
is weak: a base64 blob might be an image, and Blob machinery is ordinary
on real sites. Together they are the technique.

The nested pass exists because two-stage samples are common: the outer
blob decodes to JavaScript which itself holds the binary blob. FormBook
and xloader ship exactly that, and stopping at the first decode reports
"JavaScript" for a file carrying a PE.

Everything is bounded — a minimum blob length, a decode cap, a blob
count, and de-duplication by prefix — because every one of these
operates on attacker-supplied data whose size the attacker chooses.
Known image prefixes are skipped before decoding rather than after, so
a page full of inline JPEGs costs nothing.

The decoded bytes never leave the module. Blob descriptors carry a
SHA256, a size and a type; the raw payload is held only long enough to
hash it and to feed the nested scan, and the internal key holding it is
stripped before the result is returned.
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
    """Return a dict of smuggling-mechanism boolean flags.

    Args:
        html_text: The full page text, not just script blocks.

    Returns:
        One boolean per mechanism pattern.

    Matched against the whole document rather than the parsed script
    blocks, deliberately: the assembly machinery is frequently split
    across an inline handler, an attribute and a block, and a page that
    defeats the structural parser still has its text searched here.
    """
    return {key: bool(pat.search(html_text)) for key, pat in _MECH_PATTERNS.items()}


def find_base64_blobs(
    script_blocks: list[str],
    html_text: str,
) -> tuple[list[dict], list[str], bool]:
    """Find and characterise large base64 blobs in script content.

    Args:
        script_blocks: Inline script bodies from the structural parse.
        html_text:     The full page, scanned as a source in its own
                       right so a blob outside any ``<script>`` — in an
                       attribute, or in a page the parser could not
                       tokenise — is still found.

    Returns:
        ``(blobs, dangerous_exts, has_double_ext)``. Blob descriptors
        carry metadata only; the decoded bytes are stripped before
        returning.

    The two passes are ordered and the second depends on the first: only
    blobs that decoded to JavaScript are expanded, and only those still
    holding their decoded bytes. The cap is re-checked between them so a
    page cannot use nesting to exceed the blob budget.
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
    """Scan one text source for base64 blobs, appending what it finds.

    Args:
        text:           The source to scan.
        blobs:          Accumulator, mutated in place.
        seen_prefixes:  Shared across sources so the same blob found in
                        both a script block and the raw HTML counts once.
        dangerous_exts: Accumulator for extensions seen on download names.
        nested:         Marks findings recovered from a decoded blob, so
                        the report can say a payload was two layers deep.
        limit:          Blob budget, checked per iteration.

    Returns:
        None.

    The filename is looked for in a 600-byte window either side of the
    blob rather than anywhere in the document. A page carrying several
    payloads has several ``download =`` assignments, and searching
    globally would attribute the first one to all of them — naming the
    wrong file in the report.
    """
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
    """Decode a base64 string and characterise it, or None if invalid.

    Args:
        raw_b64: A whitespace-stripped candidate string.

    Returns:
        A descriptor dict, or None when the string is not decodable.
        The dict includes an internal ``_decoded`` key that callers strip
        before the result reaches the reporter layer.

    The head is decoded first and the whole blob only afterwards. A
    24-character prefix is enough for every magic in the table, so a
    blob too large to decode still gets a type and a size — and the
    expensive path is not entered for something that was never a
    payload.

    ``validate=False`` throughout. The strings come from JavaScript
    source and routinely carry stray characters a strict decoder
    rejects outright; refusing them would lose real payloads for a
    cosmetic reason.

    ``_decoded`` is retained only for JavaScript, since that is the one
    type the nested pass can expand. Keeping a decoded PE would mean
    holding the payload in memory for no purpose.
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
    """Match the leading bytes against the magic table.

    Args:
        data: The first bytes of a decoded blob.

    Returns:
        The type label, or None.

    The table is ordered longest-prefix-first, which is what makes a
    linear scan correct: ``MZ\x90\x00`` must be tried before the generic
    ``MZ``, and the three ZIP spellings before anything shorter could
    shadow them.
    """
    for magic_bytes, label in _MAGIC_MAP:
        if data[:len(magic_bytes)] == magic_bytes:
            return label
    return None


def _probe_text_type(decoded: bytes) -> str | None:
    """Identify a text payload when no magic matched.

    Args:
        decoded: The decoded blob.

    Returns:
        ``"JavaScript"`` or None.

    Strict UTF-8 decoding is the gate, not ``errors="replace"``: binary
    data will usually fail to decode strictly, and that failure is the
    cheapest available "this is not text" test. Only the first 300 bytes
    are examined, which is where a script's opening declarations are.
    """
    try:
        sample = decoded[:300].decode("utf-8", errors="strict")
        js_keywords = ("var ", "function", "const ", "let ", "window.", "document.")
        if any(kw in sample for kw in js_keywords):
            return "JavaScript"
    except UnicodeDecodeError:
        pass
    return None


def _extract_download_name(context: str) -> str:
    """The filename the page intends to save, from nearby source.

    Args:
        context: The window of text around a blob.

    Returns:
        The filename, or ``""``.

    The JavaScript property form is tried before the HTML attribute
    form. Smuggling assembles the anchor in script, so when both appear
    the scripted one is the operative assignment and the markup one is
    often a decoy or a leftover.
    """
    m = _DOWNLOAD_ATTR_RE.search(context)
    if m:
        return m.group(1)
    m = _DOWNLOAD_HTML_RE.search(context)
    if m:
        return m.group(1)
    return ""


def _last_extension(filename: str) -> str:
    """The final extension of a filename, including the dot.

    Args:
        filename: A suggested download name.

    Returns:
        The extension, or ``""`` when there is no dot.

    The last one is what Windows executes, which is the only one that
    matters for the dangerous-extension test. The separate
    double-extension check is what reads the one before it.
    """
    idx = filename.rfind(".")
    return filename[idx:] if idx != -1 else ""
