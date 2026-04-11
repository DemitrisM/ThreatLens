"""PDF analysis module — peepdf + raw byte sweep.

Two-pass analysis: (1) raw byte keyword sweep runs unconditionally,
so malformed / encrypted / HTML-smuggled PDFs still yield signal;
(2) peepdf structural parse runs only when the file has a real
`%PDF` header.

**Header check**: if the file claims a `.pdf` extension but begins
with `<!DOCTYPE html` or `<html`, we flag +40 for HTML smuggling
(catches the gamaredon*.pdf family). Any other non-`%PDF` header is
+15.

**Raw keyword sweep**: counts PDF dictionary markers in the raw
bytes (`/OpenAction`, `/Launch`, `/EmbeddedFile`, `/JavaScript`,
`/JS`, `/AA`, `/SubmitForm`, `/RichMedia`, `/XFA`, `/GoToR`,
`/GoToE`, `/ImportData`). Tallies `/URI` and `/Action` for density
scoring. `/Encrypt` combined with `pwd=` / `password` in the filename
adds +20 (hand-delivered encrypted malware).

**peepdf parse** (best-effort, forceMode + looseMode): extracts JS,
URIs, URLs, encryption state, suspicious components, and parse
errors. Matches JS content against exploit patterns (`eval`,
`unescape`, shellcode, heap spray, `ActiveXObject`, `WScript.Shell`,
`ADODB.Stream`, `util.printf`, `Collab.collectEmailInfo`) and
social-engineering alert strings (including Italian "non compatibile"
/ "aprilo nel browser" seen in ValleyRat / booking samples).

Safety: hard 100 MiB file cap, all exceptions wrapped. peepdf is
not invoked on header-mismatched files to avoid parser edge cases.
Total pdf_analysis contribution capped at 60. See `docs/scoring.md`
for per-indicator weights.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from peepdf.PDFCore import PDFParser
    _HAS_PEEPDF = True
except ImportError:
    _HAS_PEEPDF = False
    logger.warning("peepdf not available — structural PDF analysis disabled")

_PDF_MIMES = {"application/pdf", "application/x-pdf"}

# Hard cap — refuse files larger than 100 MiB to avoid memory exhaustion.
_MAX_FILE_SIZE = 100 * 1024 * 1024
_PDF_SCORE_CAP = 60

# Raw PDF keywords scored when present. Values are (score_per_hit, cap_hits).
# Most keywords are binary (present/not); URIs and Actions cap to avoid
# runaway scoring on legitimate bookmark-heavy documents.
_KEYWORD_WEIGHTS = {
    b"/OpenAction": (15, 1),          # auto-run on open
    b"/AA": (10, 1),                  # Additional-Actions (triggered on events)
    b"/Launch": (15, 1),              # launch external application
    b"/JavaScript": (10, 1),
    b"/JS": (5, 1),
    b"/EmbeddedFile": (15, 1),
    b"/EmbeddedFiles": (5, 1),
    b"/SubmitForm": (10, 1),
    b"/ImportData": (5, 1),
    b"/RichMedia": (10, 1),           # Flash/media exploit vectors
    b"/XFA": (5, 1),                  # XFA forms — historically abused
    b"/GoToR": (5, 1),                # remote GoTo
    b"/GoToE": (5, 1),                # embedded GoTo
}

_JS_EXPLOIT_PATTERNS = {
    "eval(":                 "eval() call",
    "unescape(":             "unescape() call",
    "shellcode":             "shellcode reference",
    "spray":                 "heap spray pattern",
    "string.fromcharcode":   "character code obfuscation",
    "activexobject":         "ActiveX instantiation",
    "wscript.shell":         "WScript.Shell access",
    "adodb.stream":          "ADODB.Stream access",
    "util.printf":           "Collab.getIcon / util.printf (CVE-2008-2992)",
    "getannots":             "getAnnots() abuse",
    "collab.collectemailinfo": "Collab.collectEmailInfo (CVE-2007-5659)",
}

_SOCIAL_ENG_PATTERNS = (
    "not compatible",
    "non compatibile",          # Italian — seen in booking.pdf / ValleyRat.pdf
    "open in browser",
    "aprilo nel browser",       # Italian
    "enable content",
    "click here",
)


def run(file_path: Path, config: dict) -> dict:
    """Analyse a PDF file for suspicious structures and embedded code."""
    if not _is_pdf_target(file_path):
        return _skipped("Not applicable — not a PDF file")

    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return _error(f"Could not stat file: {exc}")
    if size > _MAX_FILE_SIZE:
        return _skipped(f"File too large for pdf_analysis ({size} bytes > {_MAX_FILE_SIZE})")

    try:
        return _analyse(file_path, size)
    except Exception as exc:  # noqa: BLE001
        logger.error("pdf_analysis failed on %s: %s", file_path.name, exc)
        return _error(f"Analysis error: {exc}")


def _is_pdf_target(file_path: Path) -> bool:
    """The module runs on anything with a .pdf extension or %PDF header.

    A .pdf extension alone is enough — a header mismatch is itself a
    finding (HTML-smuggling PDFs rely on the extension).
    """
    if file_path.suffix.lower() == ".pdf":
        return True
    try:
        with file_path.open("rb") as fh:
            head = fh.read(1024)
        return b"%PDF-" in head
    except OSError:
        return False


def _read_header(file_path: Path, size: int = 1024) -> bytes:
    try:
        with file_path.open("rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _analyse(file_path: Path, file_size: int) -> dict:
    score_delta = 0
    reasons: list[str] = []
    data: dict = {
        "version": None,
        "num_objects": 0,
        "num_streams": 0,
        "num_uris": 0,
        "encrypted": False,
        "has_javascript": False,
        "javascript_count": 0,
        "javascript_code": [],
        "uris": [],
        "urls": [],
        "suspicious_elements": [],
        "raw_keyword_hits": {},
        "header_mismatch": False,
        "peepdf_errors": [],
        "parsed": False,
    }

    # ── Header check first — catch HTML-smuggling PDFs (e.g. gamaredon*.pdf) ──
    header = _read_header(file_path, 512)
    if not header.lstrip().startswith(b"%PDF-"):
        data["header_mismatch"] = True
        head_preview = header.lstrip()[:40].decode("latin-1", errors="replace")
        lower_head = header.lower().lstrip()
        if lower_head.startswith(b"<!doctype html") or lower_head.startswith(b"<html"):
            score_delta += 40
            reasons.append("File has .pdf extension but contains HTML — likely HTML smuggling")
        else:
            score_delta += 15
            reasons.append(f"Missing %PDF header — header begins: {head_preview!r}")
        # Still run raw keyword scan even on malformed PDFs — some flag anyway.

    # ── Raw byte keyword sweep (always runs, independent of peepdf) ──
    raw_delta, raw_reasons, raw_hits = _raw_keyword_scan(file_path, file_size)
    data["raw_keyword_hits"] = raw_hits
    score_delta += raw_delta
    reasons.extend(raw_reasons)

    # ── peepdf structural parse (best-effort) ──
    if _HAS_PEEPDF and not data["header_mismatch"]:
        pd_delta, pd_reasons = _peepdf_parse(file_path, data)
        score_delta += pd_delta
        reasons.extend(pd_reasons)
    elif not _HAS_PEEPDF:
        reasons.append("peepdf not available — raw keyword scan only")

    score_delta = min(score_delta, _PDF_SCORE_CAP)
    reason_text = "; ".join(reasons) if reasons else "No suspicious PDF elements detected"

    return {
        "module": "pdf_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


def _raw_keyword_scan(file_path: Path, file_size: int) -> tuple[int, list[str], dict]:
    """Scan the raw bytes for PDF marker keywords without parsing."""
    score_delta = 0
    reasons: list[str] = []
    hits: dict = {}

    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        logger.debug("Could not read PDF bytes: %s", exc)
        return 0, [], {}

    for kw, (weight, cap) in _KEYWORD_WEIGHTS.items():
        count = raw.count(kw)
        if count > 0:
            hits[kw.decode()] = count
            effective = min(count, cap)
            score_delta += weight * effective

    if hits:
        # Summarise the highest-impact hits.
        summary = ", ".join(f"{k}({v})" for k, v in list(hits.items())[:5])
        reasons.append(f"Raw PDF markers: {summary}")

    # URI density — bookmark-heavy legit PDFs have a few, phishing PDFs often have 10+.
    uri_count = raw.count(b"/URI")
    if uri_count >= 30:
        score_delta += 10
        reasons.append(f"Very high URI density ({uri_count} /URI markers)")
    elif uri_count >= 10:
        score_delta += 5
        reasons.append(f"High URI density ({uri_count} /URI markers)")

    # Action density.
    action_count = raw.count(b"/Action")
    if action_count >= 20:
        score_delta += 10
        reasons.append(f"Very high action density ({action_count} /Action markers)")
    elif action_count >= 10:
        score_delta += 5
        reasons.append(f"High action density ({action_count} /Action markers)")

    # Encryption via raw tag — the /Encrypt dictionary is present even when peepdf fails.
    if b"/Encrypt" in raw:
        score_delta += 10
        reasons.append("PDF is encrypted — content hidden from static scanners")
        # Password hinted in filename ("pwd=", "password") strongly suggests
        # hand-delivered malware that bypasses AV by requiring the key.
        name_lower = file_path.name.lower()
        if "pwd" in name_lower or "password" in name_lower or "passwd" in name_lower:
            score_delta += 20
            reasons.append("Password hint in filename — encrypted PDF hand-delivered to bypass AV")

    return score_delta, reasons, hits


def _peepdf_parse(file_path: Path, data: dict) -> tuple[int, list[str]]:
    score_delta = 0
    reasons: list[str] = []

    parser = PDFParser()
    try:
        ret, pdf_file = parser.parse(str(file_path), forceMode=True, looseMode=True)
    except Exception as exc:  # noqa: BLE001
        logger.info("peepdf parse crashed on %s: %s", file_path.name, exc)
        return 0, [f"peepdf parse failure: {exc}"]

    if ret != 0 or pdf_file is None:
        return 0, ["peepdf could not parse PDF structure"]

    data["parsed"] = True
    try:
        data["version"] = pdf_file.getVersion()
        data["encrypted"] = bool(pdf_file.isEncrypted())
    except Exception:  # noqa: BLE001
        pass

    try:
        stats = pdf_file.getStats()
        if isinstance(stats, dict):
            data["num_objects"] = _coerce_int(stats.get("Objects", 0))
            data["num_streams"] = _coerce_int(stats.get("Streams", 0))
            data["num_uris"] = _coerce_int(stats.get("URIs", 0))
    except Exception:  # noqa: BLE001
        pass

    # peepdf reports parse errors — some of them are meaningful.
    try:
        errors = pdf_file.getErrors()
        if errors:
            data["peepdf_errors"] = [str(e) for e in errors[:10]]
            nasty = {"bad pdf header", "%%eof not found", "missing endobj"}
            for e in errors:
                if any(n in str(e).lower() for n in nasty):
                    score_delta += 5
                    reasons.append("peepdf reports structural anomalies")
                    break
    except Exception:  # noqa: BLE001
        pass

    # JavaScript.
    try:
        js_versions = pdf_file.getJavascriptCode() or []
        js_items: list[str] = []
        for version_js in js_versions:
            if isinstance(version_js, (list, tuple)):
                for entry in version_js:
                    if isinstance(entry, tuple) and len(entry) >= 2:
                        js_items.append(str(entry[1]))
                    else:
                        js_items.append(str(entry))
            elif isinstance(version_js, str):
                js_items.append(version_js)
        js_items = [j for j in js_items if j and j != "[]"]
        if js_items:
            data["has_javascript"] = True
            data["javascript_count"] = len(js_items)
            data["javascript_code"] = [j[:500] for j in js_items[:10]]
            score_delta += 10
            reasons.append(f"peepdf extracted {len(js_items)} JavaScript block(s)")

            joined = " ".join(js_items).lower()
            matched_exploits = [label for pat, label in _JS_EXPLOIT_PATTERNS.items() if pat in joined]
            if matched_exploits:
                score_delta += 15
                reasons.append(f"JS exploit patterns: {', '.join(matched_exploits[:4])}")

            matched_social = [p for p in _SOCIAL_ENG_PATTERNS if p in joined]
            if matched_social:
                score_delta += 10
                reasons.append(f"Social-engineering JS alert: {', '.join(matched_social[:3])}")
    except Exception as exc:  # noqa: BLE001
        logger.debug("JavaScript extraction failed: %s", exc)

    # URIs.
    try:
        uri_versions = pdf_file.getURIs() or []
        flat_uris: list[str] = []
        for v in uri_versions:
            if isinstance(v, (list, tuple)):
                flat_uris.extend(str(u) for u in v if u)
            elif isinstance(v, str) and v:
                flat_uris.append(v)
        if flat_uris:
            data["uris"] = flat_uris[:50]
    except Exception as exc:  # noqa: BLE001
        logger.debug("URI extraction failed: %s", exc)

    # URLs (peepdf distinguishes URLs found inside stream content).
    try:
        url_versions = pdf_file.getURLs() or []
        flat_urls: list[str] = []
        for v in url_versions:
            if isinstance(v, (list, tuple)):
                flat_urls.extend(str(u) for u in v if u)
            elif isinstance(v, str) and v:
                flat_urls.append(v)
        if flat_urls:
            data["urls"] = flat_urls[:50]
    except Exception as exc:  # noqa: BLE001
        logger.debug("URL extraction failed: %s", exc)

    # Suspicious components as reported by peepdf's internal check.
    try:
        susp = pdf_file.getSuspiciousComponents()
        if susp:
            flat: list[str] = []
            for version_susp in susp if isinstance(susp, list) else [susp]:
                if isinstance(version_susp, dict):
                    for k, v in version_susp.items():
                        flat.append(f"{k}: {v}")
                elif isinstance(version_susp, list):
                    flat.extend(str(i) for i in version_susp)
                elif isinstance(version_susp, str):
                    flat.append(version_susp)
            if flat:
                data["suspicious_elements"] = flat[:20]
                score_delta += 5
                reasons.append(f"peepdf flagged: {', '.join(flat[:3])}")
    except Exception as exc:  # noqa: BLE001
        logger.debug("Suspicious component extraction failed: %s", exc)

    return score_delta, reasons


def _coerce_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _skipped(reason: str) -> dict:
    return {
        "module": "pdf_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    return {
        "module": "pdf_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
