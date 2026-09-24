"""HTML analysis module — HTML smuggling, ClickFix, obfuscation, C2 detection.

Six analysis passes on ``.html`` / ``.htm`` files (also triggered by HTML
magic bytes regardless of extension):

  1. **Structure** — script blocks, external scripts, iframes, download
     anchors, form actions, meta-refresh (``structure.py``)
  2. **Base64 blobs** — find large b64 strings, decode them, identify
     payload type by magic bytes (PE/ZIP/OLE2/RAR/…), compute SHA256,
     second-pass scan of decoded JavaScript for nested payloads
     (``smuggling.py``)
  3. **Smuggling mechanisms** — atob(), Blob, createObjectURL, onload
     trigger, msSaveOrOpenBlob, auto-click download (``smuggling.py``)
  4. **Obfuscation** — eval(), fromCharCode(), junk-comment camouflage,
     obfuscated variable names (``obfuscation.py``)
  5. **ClickFix / clipboard poisoning** — writeText(), execCommand copy,
     LOLBin payload extraction, social-engineering lure text
     (``clickfix.py``)
  6. **External resources** — injected non-CDN scripts, C2 random-path
     URLs, XHR/Fetch beacons, WebSockets (``external.py``)

No external dependencies — pure stdlib.
Hard file cap: 100 MiB.  Score cap: 60.  See ``docs/scoring.md``.

Design notes
------------
The six passes are independent and each reads the structural parse
rather than the file. That is why the document is tokenised once and the
script blocks handed around: a page is parsed a single time no matter
how many indicators run over it, and no pass can desynchronise another.

**Scoring is an additive if-chain here, not the frozenset combo engine
the other modules use.** The difference is deliberate but worth knowing
when comparing weights across modules: this one reasons about a single
document with a handful of independent mechanisms, where each finding
has a standalone meaning, while the combo engine exists for formats
whose indicators only mean something in combination. The `elif` runs
inside it are the exception and are load-bearing — see `_compute_score`.

Only two pieces of state cross a pass boundary: the unified
`has_auto_download` flag, which folds three delivery triggers into one
because the scoring cares that a download fires and not which API did
it, and the blob list, which pass 2 fills and the scorer reads.

Everything the module knows ends up in one flat data dict, built by
merging each pass's result. The passes therefore have to agree on key
names, which is why each returns a flat dict of its own rather than a
nested one — a nested shape would push the reporters into knowing which
pass found what.
"""

import logging
from pathlib import Path

from .structure import parse_structure
from .smuggling import find_base64_blobs, detect_mechanisms
from .obfuscation import detect_obfuscation
from .clickfix import detect_clickfix
from .external import detect_external_resources

logger = logging.getLogger(__name__)

_MAX_FILE_SIZE = 100 * 1024 * 1024   # 100 MiB
_HTML_SCORE_CAP = 60

_HTML_EXTENSIONS: frozenset[str] = frozenset({".html", ".htm", ".xhtml"})


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(file_path: Path, config: dict) -> dict:
    """Analyse an HTML file for smuggling, obfuscation, and social engineering.

    Args:
        file_path: The file to analyse.
        config:    Unused. This module has no tunables — every threshold
                   is a published figure or a measured one, and the size
                   cap is a memory bound rather than a policy.

    Returns:
        The standard module dict.

    Note the size cap skips the file rather than bounding the read, which
    is the shape that turned out to be an evasion in ``lnk_analysis``.
    It is far less pressing here — 100 MiB of HTML is not a delivery
    shape anyone uses, and the whole document has to be in memory for
    the passes to run — but it is the same trade and is recorded as such
    in the project notes.
    """
    if not _is_html_target(file_path):
        return _skipped("Not applicable — not an HTML file")

    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return _error(f"Could not stat file: {exc}")

    if size > _MAX_FILE_SIZE:
        return _skipped(
            f"File too large for html_analysis ({size // (1024 * 1024)} MiB > 100 MiB)"
        )

    try:
        return _analyse(file_path, size)
    except Exception as exc:  # noqa: BLE001
        logger.error("html_analysis failed on %s: %s", file_path.name, exc)
        return _error(f"Analysis error: {exc}")


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def _is_html_target(file_path: Path) -> bool:
    """True if the file should be analysed as HTML.

    Args:
        file_path: The candidate file.

    Returns:
        Whether the module owns it.

    Accepts the extension **or** the magic, never requiring both. A
    smuggling page is routinely delivered with a misleading extension —
    ``.svg``, ``.shtml``, no extension at all — and is still opened as
    HTML by the browser, so the extension alone would miss the case the
    module exists for.

    The sniff is deliberately narrow: only a leading doctype or ``<html``
    after whitespace. A looser test — searching for ``<script``
    anywhere, say — would claim every text file that mentions one.
    """
    if file_path.suffix.lower() in _HTML_EXTENSIONS:
        return True
    try:
        with file_path.open("rb") as fh:
            head = fh.read(256)
    except OSError:
        return False

    # Decoded before comparing, not compared as raw bytes. A byte-order
    # mark sits in front of `<html` and a UTF-16 page spells it
    # `<\x00h\x00`, so a raw comparison failed on both — and both are
    # ordinary ways to save an HTML file that a browser opens as HTML
    # whatever the extension claims. Decoy extensions are exactly the
    # case this fallback exists for.
    text = _decode_prefix(head).lstrip().lower()
    return text.startswith("<!doctype html") or text.startswith("<html")


def _decode_prefix(head: bytes) -> str:
    """Decode a leading chunk for sniffing, BOM-aware and never raising.

    Args:
        head: The first bytes of the file.

    Returns:
        The decoded prefix, with any BOM consumed.

    ``errors="replace"`` throughout because a fixed-size read routinely
    cuts a multi-byte sequence in half. The tail of the prefix is
    allowed to be mangled; only its first few characters are examined.
    """
    for bom, codec in _BOMS:
        if head.startswith(bom):
            return head.decode(codec, errors="replace")
    try:
        return head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return head.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

#: Byte-order marks that identify a codec outright, longest first so
#: UTF-32's mark is not read as UTF-16's prefix.
#: Byte-order marks that identify a codec outright.
#:
#: **UTF-32 is deliberately absent.** Its little-endian mark is the
#: UTF-16-LE mark followed by two NULs, so listing it makes a UTF-16
#: document whose first character is U+0000 decode as UTF-32 — one
#: character of payload, and the text becomes mojibake. HTML5 settles
#: which reading is right: the UTF-32 encodings are not supported, and a
#: browser handed ``ff fe 00 00`` decodes UTF-16-LE. Matching the
#: browser is the contract.
#:
#: The endian-agnostic codec name is also deliberate: ``utf-16-le``
#: decodes the mark as a literal U+FEFF and leaves it in front of
#: ``<html>``, breaking every prefix test downstream, while ``utf-16``
#: consumes it.
_BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe",     "utf-16"),
    (b"\xfe\xff",     "utf-16"),
)


def _read_html(file_path: Path) -> tuple[str, str]:
    """Read the file and decode it, returning the text and the codec used.

    Args:
        file_path: The HTML file.

    Returns:
        ``(text, encoding_label)``.

    Every pattern in this module runs against the returned text, so the
    codec decides whether there is anything to match. A wrong choice does
    not fail loudly — it produces mojibake, and every indicator silently
    finds nothing.

    **UTF-16 is only used when a BOM says so.** It used to be tried
    speculatively between UTF-8 and Latin-1, and ``bytes.decode("utf-16")``
    without a BOM assumes little-endian and pairs the bytes up, which
    succeeds for essentially any even-length input. So a Windows-1252
    page — anything carrying an accented character, which fails strict
    UTF-8 — was claimed by UTF-16 whenever its length happened to be
    even. Measured: a 50-byte latin-1 page decoded to '格浴㹬猼牣灩㹴…'
    and the ``eval(atob(`` call in it vanished, so the module reported
    nothing on a page that plainly carried one.

    UTF-32 is deliberately not in the table — see ``_BOMS``.

    A BOM-less UTF-16 page is deliberately not guessed at. HTML5 sniffing
    does not select UTF-16 without one either, and the spec explicitly
    overrides a ``<meta charset="utf-16">`` declaration to UTF-8 to stop
    exactly that being an attack surface — so such a page is not
    something a browser runs as UTF-16, and guessing would reintroduce
    the Windows-1252 false positive the BOM rule exists to prevent.
    Matching the browser is the contract here, not maximal recovery.

    Latin-1 is last and cannot fail: it maps all 256 byte values, so
    strict decoding always succeeds. That makes it the terminator rather
    than one more attempt, and it is why there is no ``errors="replace"``
    fallback after it — such a line would be unreachable.
    """
    raw = file_path.read_bytes()

    for bom, codec in _BOMS:
        if raw.startswith(bom):
            return raw.decode(codec, errors="replace"), codec

    try:
        return raw.decode("utf-8", errors="strict"), "utf-8"
    except UnicodeDecodeError:
        pass

    return raw.decode("latin-1", errors="strict"), "latin-1"


def _analyse(file_path: Path, file_size: int) -> dict:
    html_text, encoding = _read_html(file_path)

    # ── Pass 1: structure ──────────────────────────────────────────────────
    struct = parse_structure(html_text)
    script_blocks: list[str] = struct["script_blocks"]
    external_script_urls: list[str] = struct["external_script_urls"]
    iframe_urls: list[str] = struct["iframe_urls"]
    download_anchors: list[dict] = struct["download_anchors"]

    # ── Passes 2 + 3: smuggling ────────────────────────────────────────────
    blobs, dangerous_exts, has_double_ext = find_base64_blobs(script_blocks, html_text)
    mechanisms = detect_mechanisms(html_text)

    # Unified auto-download flag (any delivery trigger counts).
    has_auto_download = (
        mechanisms.get("has_auto_download", False)
        or mechanisms.get("has_mssave", False)
        or mechanisms.get("has_window_loc_blob", False)
    )

    # ── Pass 4: obfuscation ────────────────────────────────────────────────
    obf = detect_obfuscation(script_blocks)

    # ── Pass 5: ClickFix ───────────────────────────────────────────────────
    cf = detect_clickfix(html_text, script_blocks)

    # ── Pass 6: external resources ─────────────────────────────────────────
    ext = detect_external_resources(external_script_urls, iframe_urls, script_blocks)

    # ── Assemble data dict ─────────────────────────────────────────────────
    data: dict = {
        "encoding": encoding,
        "file_size_bytes": file_size,
        # Structure counts
        "num_script_blocks": struct["num_script_blocks"],
        "num_external_scripts": struct["num_external_scripts"],
        "num_iframes": struct["num_iframes"],
        "num_download_anchors": struct["num_download_anchors"],
        "form_actions": struct["form_actions"],
        "meta_refresh_target": struct["meta_refresh_target"],
        # Smuggling mechanisms
        **mechanisms,
        "has_auto_download": has_auto_download,
        "download_filenames": [
            a["download"] for a in download_anchors if a.get("download")
        ],
        "dangerous_extensions": dangerous_exts,
        "double_extension": has_double_ext,
        # Blob findings (internal _decoded key already stripped by smuggling.py)
        "base64_blobs": blobs,
        "embedded_payload_types": list(dict.fromkeys(
            b["decoded_magic"]
            for b in blobs
            if b.get("decoded_magic") not in ("unknown", "JavaScript", None)
        )),
        # Obfuscation
        **obf,
        # ClickFix
        **cf,
        # External resources
        **ext,
    }

    score_delta, reasons = _compute_score(data)
    score_delta = min(score_delta, _HTML_SCORE_CAP)
    reason_text = "; ".join(reasons) if reasons else "No suspicious HTML indicators detected"

    return {
        "module": "html_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _compute_score(data: dict) -> tuple[int, list[str]]:  # noqa: C901 (complex but necessary)
    """Score the assembled findings and explain each contribution.

    Args:
        data: The merged result of all six passes.

    Returns:
        ``(score, reasons)`` — the uncapped total and one human-readable
        string per contribution. The caller applies the cap, so the
        reasons always describe what was actually found rather than what
        survived it.

    Every branch appends its reason as it scores. That coupling is the
    point: a score with no matching reason would be unexplainable in the
    report, and the two cannot drift because neither can be written
    without the other.

    Three deliberate exclusivity runs, each preventing one observation
    from being paid for twice:

    * Payload type — PE beats ZIP/OLE2/CAB beats RAR/7-Zip/gzip beats a
      large unidentified blob. One payload is one finding, and the
      highest-confidence identification is the one worth reporting.
    * ``clipboard_contains_lolbin`` beats a bare clipboard write, which
      is the same event seen with and without its payload.
    * ``has_eval`` is skipped when ``has_eval_atob`` already fired,
      since the latter is a more specific description of the same call.

    The random-path C2 check likewise supersedes the plain non-CDN
    domain check rather than adding to it — the path is what makes the
    domain interesting, and a compromised legitimate site would
    otherwise score twice for one injection.
    """
    score = 0
    reasons: list[str] = []

    # ── Embedded payload type ──────────────────────────────────────────────
    blobs: list[dict] = data.get("base64_blobs", [])
    blob_types = {b.get("decoded_magic") for b in blobs}

    if "PE" in blob_types:
        score += 30
        pe = next(b for b in blobs if b.get("decoded_magic") == "PE")
        sha = (pe.get("sha256") or "")[:16]
        sz = pe.get("size_bytes", 0) // 1024
        suffix = f"SHA256: {sha}…" if sha else ""
        nested = " [nested]" if pe.get("from_nested_decode") else ""
        reasons.append(
            f"Embedded PE payload{nested} ({sz} KiB{(', ' + suffix) if suffix else ''})"
        )
    elif blob_types & {"ZIP", "OLE2", "CAB"}:
        match = (blob_types & {"ZIP", "OLE2", "CAB"}).pop()
        score += 20
        b = next(b for b in blobs if b.get("decoded_magic") == match)
        nested = " [nested]" if b.get("from_nested_decode") else ""
        reasons.append(
            f"Embedded {match} payload{nested} ({b.get('size_bytes', 0) // 1024} KiB)"
        )
    elif blob_types & {"RAR", "7-Zip", "gzip"}:
        match = (blob_types & {"RAR", "7-Zip", "gzip"}).pop()
        score += 15
        reasons.append(f"Embedded {match} archive in base64 blob")
    elif any(b.get("size_bytes", 0) >= 10_000 for b in blobs):
        score += 10
        large = max(blobs, key=lambda b: b.get("size_bytes", 0))
        reasons.append(
            f"Large embedded blob ({large.get('size_bytes', 0) // 1024} KiB, type unidentified)"
        )

    # ── Smuggling mechanisms ───────────────────────────────────────────────
    if data.get("has_eval_atob"):
        score += 30
        reasons.append("eval(atob(…)) — inline base64-encoded JS execution")

    if data.get("has_blob_url") and data.get("has_blob_creation"):
        score += 20
        reasons.append("Blob delivery chain (new Blob + URL.createObjectURL)")

    if data.get("has_onload_trigger") and (
        data.get("has_blob_url")
        or data.get("has_auto_download")
        or data.get("has_eval_atob")
    ):
        score += 10
        reasons.append(
            "window.onload trigger — payload delivered on page open (zero user interaction)"
        )

    if data.get("has_mssave"):
        score += 10
        reasons.append("navigator.msSaveOrOpenBlob — auto-save to disk (IE/Edge fallback)")

    if data.get("dangerous_extensions"):
        exts = data["dangerous_extensions"]
        score += 10
        reasons.append(
            f"Auto-download anchor with dangerous extension: {', '.join(exts[:3])}"
        )

    if data.get("double_extension"):
        score += 5
        reasons.append("Double extension in download filename (e.g. .pdf.exe) — AV evasion")

    # ── ClickFix ───────────────────────────────────────────────────────────
    if data.get("clipboard_contains_lolbin"):
        score += 35
        lolbins = data.get("clipboard_lolbins_found", [])
        reasons.append(f"Clipboard poisoning with LOLBin: {', '.join(lolbins[:3])}")
    elif data.get("has_clipboard_write"):
        score += 15
        reasons.append("Clipboard write (navigator.clipboard.writeText)")

    if data.get("social_eng_patterns"):
        score += 15
        pats = data["social_eng_patterns"]
        reasons.append(f"Social-engineering lure: {'; '.join(pats[:2])}")

    # ── Obfuscation ────────────────────────────────────────────────────────
    # Only score eval() if not already scored via eval(atob()) above.
    if data.get("has_eval") and not data.get("has_eval_atob"):
        score += 10
        reasons.append("eval() call in inline script")

    if data.get("has_fromcharcode"):
        score += 10
        reasons.append("String.fromCharCode() — character-code array obfuscation")

    if data.get("has_junk_comments"):
        score += 10
        reasons.append("Junk-comment camouflage (AI-generated obfuscation noise)")

    if data.get("has_function_constructor"):
        score += 10
        reasons.append("new Function() constructor — eval proxy")

    if data.get("has_obfuscated_varnames") and data.get("has_junk_comments"):
        score += 5
        reasons.append("Obfuscated variable names alongside junk-comment cover")

    if data.get("has_unescape"):
        score += 5
        reasons.append("unescape() — percent-encoding obfuscation")

    # ── External resources ─────────────────────────────────────────────────
    random_paths = data.get("random_path_scripts", [])
    suspicious_domains = data.get("suspicious_external_domains", [])

    if random_paths:
        # C2 callback-style path in injected script — strong signal.
        score += 15
        reasons.append(
            f"{len(random_paths)} injected script(s) with C2-style random-path URL"
        )
    elif suspicious_domains:
        score += min(10 * len(suspicious_domains), 20)
        reasons.append(
            f"External script(s) from non-CDN domain(s): {', '.join(suspicious_domains[:2])}"
        )

    if data.get("has_xhr_beacon") or data.get("has_fetch_beacon"):
        method = "XHR" if data.get("has_xhr_beacon") else "Fetch"
        score += 10
        reasons.append(f"{method} beacon to external domain")

    if data.get("has_websocket"):
        score += 10
        reasons.append("WebSocket connection — potential live C2 channel")

    if data.get("suspicious_iframe_urls"):
        score += 5
        reasons.append(f"External iframe: {data['suspicious_iframe_urls'][0][:80]}")

    if data.get("meta_refresh_target") and not data["meta_refresh_target"].startswith("/"):
        score += 5
        reasons.append("Meta-refresh redirect to external URL")

    return score, reasons


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skipped(reason: str) -> dict:
    """A file this module does not own, or will not open.

    Args:
        reason: Shown to the user as the skip explanation.

    Returns:
        The standard dict with ``status="skipped"`` and no score.
    """
    return {
        "module": "html_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    """A file this module should have handled and could not.

    Args:
        reason: Shown to the user as the failure explanation.

    Returns:
        The standard dict with ``status="error"`` and no score — an
        analysis that did not run must not move a verdict either way.
    """
    return {
        "module": "html_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
