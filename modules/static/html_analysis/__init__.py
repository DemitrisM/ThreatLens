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
    """Analyse an HTML file for smuggling, obfuscation, and social engineering."""
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

    Accepts ``.html`` / ``.htm`` extensions OR any file whose leading bytes
    start with ``<!DOCTYPE html`` or ``<html``.
    """
    if file_path.suffix.lower() in _HTML_EXTENSIONS:
        return True
    try:
        with file_path.open("rb") as fh:
            head = fh.read(256).lstrip()
        lower = head.lower()
        return lower.startswith(b"<!doctype html") or lower.startswith(b"<html")
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _read_html(file_path: Path) -> tuple[str, str]:
    """Read raw bytes and decode to str, trying UTF-8 then Latin-1."""
    raw = file_path.read_bytes()
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(enc, errors="strict"), enc
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1 (fallback)"


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
    return {
        "module": "html_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    return {
        "module": "html_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
