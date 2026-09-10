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

Design notes
------------
The two passes are ordered the way they are because peepdf is the
unreliable one. It is an abandoned parser being fed deliberately
malformed input, and it fails in every direction: raising, returning a
non-zero status, returning a file object whose accessors raise, or
returning nested lists whose shape differs by PDF version. So the raw
byte sweep runs first and unconditionally, and everything peepdf
contributes is additive on top of a result that already stands alone.
That is also why every peepdf accessor below sits in its own try block
rather than one big one — a crash in JavaScript extraction must not cost
the URI list that would have been read after it.

peepdf is skipped entirely when the header does not say %PDF. Not for
safety of the process — the wrappers already cover that — but because a
"PDF" that is really HTML has already been fully explained by the header
mismatch, and peepdf's forceMode on non-PDF input produces error text
that reads like structural findings when it is really just confusion.

Scoring is additive-with-cap rather than combo-based (contrast
archive_analysis and lnk_analysis, which use frozenset rules). A PDF has
few enough dangerous markers that their sum is meaningful on its own, and
each marker is independently actionable: /OpenAction plus /JavaScript is
not a special combination, it is simply two bad things.

The keyword table is matched against raw bytes with no PDF tokenisation
at all. This is what lets the sweep work on encrypted, truncated and
object-stream-compressed files where no parser can reach the dictionary —
and equally why a marker inside a compressed stream is invisible to it.
Marker counts are therefore a floor, never a census.
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
#
# Every cap is 1 today, which makes the pair notation look redundant — it
# is kept because the weights are due a calibration sweep (docs/scoring.md)
# and "how many hits count" is the axis that sweep will move.
#
# Weights encode *automation*, not capability: /OpenAction and /Launch are
# 15 because they act without the user, while /XFA and /GoToE are 5 because
# they need a click or a second file. That is the reason /JavaScript (10)
# outscores /JS (5) despite naming the same feature — /JavaScript names a
# document-level action entry, /JS is the generic value key it also appears
# under in annotations.
#
# Matching is plain byte containment with no PDF tokenisation, so a keyword
# that is a prefix of another ("/EmbeddedFile" inside "/EmbeddedFiles") would
# be counted inside it. _raw_keyword_scan corrects for that generically —
# including for chains of three — so a new prefix-related keyword can be
# added here without further change.
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
    """Analyse a PDF file for suspicious structures and embedded code.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict. Not read — the size cap and
                   score cap are module constants, deliberately not tunable,
                   since a 100 MiB PDF is pathological at any profile.

    Returns:
        Standard module result dict. "skipped" when the file is not a PDF
        target or exceeds the size cap, "error" when it cannot be stat'd or
        an unexpected exception escapes the analysis, "success" otherwise.
    """
    # A non-PDF is a skip, not an error: every scan runs all thirteen
    # modules, so most files reach here having nothing to do with PDFs.
    if not _is_pdf_target(file_path):
        return _skipped("Not applicable — not a PDF file")

    # The size is taken once and threaded through, rather than re-stat'd in
    # the scan, so the cap decision and the scan agree even if the file is
    # replaced mid-scan.
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return _error(f"Could not stat file: {exc}")
    if size > _MAX_FILE_SIZE:
        return _skipped(f"File too large for pdf_analysis ({size} bytes > {_MAX_FILE_SIZE})")

    # The blanket catch is design rule 2 in its bluntest form. peepdf is a
    # third-party parser handling hostile input; anything it raises must
    # become this module's error result, never the pipeline's traceback.
    try:
        return _analyse(file_path, size)
    except Exception as exc:  # noqa: BLE001
        logger.error("pdf_analysis failed on %s: %s", file_path.name, exc)
        return _error(f"Analysis error: {exc}")


def _is_pdf_target(file_path: Path) -> bool:
    """The module runs on anything with a .pdf extension or %PDF header.

    A .pdf extension alone is enough — a header mismatch is itself a
    finding (HTML-smuggling PDFs rely on the extension).

    Args:
        file_path: Candidate file.

    Returns:
        True if the module should run. The extension test comes first
        because it needs no I/O, and because the extension-without-header
        case is the one this module most wants to catch.
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
    """Read the first *size* bytes, or b"" if the file cannot be opened.

    Args:
        file_path: File to read.
        size:      Byte count. Callers pass 512 for the header check.

    Returns:
        The leading bytes. An empty result is treated by the caller as a
        header mismatch, which is the correct reading: a file that cannot
        be opened cannot be shown to be a PDF.
    """
    try:
        with file_path.open("rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _analyse(file_path: Path, file_size: int) -> dict:
    """Run both passes and assemble the module result.

    Args:
        file_path:  The PDF (or claimed PDF) under analysis.
        file_size:  Size in bytes, already checked against the cap by run().

    Returns:
        Standard module result dict with status "success" — reaching here
        means the file was readable, and a file that yields no findings is
        a successful analysis, not a skip.

    Raises:
        Nothing by contract; run() wraps this call because peepdf's failure
        modes are not enumerable.
    """
    # data[] is fully pre-populated with typed empties so the reporters can
    # index it unconditionally. A key that only appears when a finding fires
    # would force every row builder to guess whether absence means "false"
    # or "not analysed".
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

    # ------------------------------------------------------------------
    # Pass 1: Header check — catch HTML-smuggling PDFs (gamaredon*.pdf).
    #
    # This runs first because its result gates peepdf below. lstrip() is
    # applied because leading whitespace before %PDF- is common and benign;
    # anything else in front of the signature is not, and the comparison
    # deliberately demands the signature at the (stripped) start rather
    # than anywhere in the first block, which is what makes a prepended
    # HTML document a mismatch instead of a PDF with an odd preamble.
    # ------------------------------------------------------------------
    header = _read_header(file_path, 512)
    if not header.lstrip().startswith(b"%PDF-"):
        data["header_mismatch"] = True
        head_preview = header.lstrip()[:40].decode("latin-1", errors="replace")
        # The preview is decoded latin-1 with replacement so that arbitrary
        # binary can be shown in the reason string without a decode error —
        # latin-1 maps every byte, which is exactly what is wanted here.
        lower_head = header.lower().lstrip()
        # Two tiers: HTML in a .pdf is an active delivery technique and
        # scores nearly triple. Any other wrong header is only evidence of
        # mislabelling, which has plenty of benign causes.
        if lower_head.startswith(b"<!doctype html") or lower_head.startswith(b"<html"):
            score_delta += 40
            reasons.append("File has .pdf extension but contains HTML — likely HTML smuggling")
        else:
            score_delta += 15
            reasons.append(f"Missing %PDF header — header begins: {head_preview!r}")
        # Still run raw keyword scan even on malformed PDFs — some flag anyway.

    # ------------------------------------------------------------------
    # Pass 2: Raw byte keyword sweep. Always runs, independent of peepdf
    # and of the header result — an encrypted or truncated PDF still shows
    # its dictionary markers, and that is often the only signal available.
    # ------------------------------------------------------------------
    raw_delta, raw_reasons, raw_hits = _raw_keyword_scan(file_path, file_size)
    data["raw_keyword_hits"] = raw_hits

    # The sweep scores +10 and states the file is encrypted, so the payload
    # has to agree — peepdf may be absent, skipped for a header mismatch, or
    # unable to read the encryption dictionary of a deliberately broken file.
    if "/Encrypt" in raw_hits:
        data["encrypted"] = True
    score_delta += raw_delta
    reasons.extend(raw_reasons)

    # ------------------------------------------------------------------
    # Pass 3: peepdf structural parse, best-effort and skippable.
    #
    # Skipped on a header mismatch by design (see the module docstring).
    # The missing-peepdf branch says so in the reason string rather than
    # silently degrading, because the same file scores differently with
    # and without the library and the report must admit that.
    # ------------------------------------------------------------------
    if _HAS_PEEPDF and not data["header_mismatch"]:
        pd_delta, pd_reasons = _peepdf_parse(file_path, data)
        score_delta += pd_delta
        reasons.extend(pd_reasons)
    elif not _HAS_PEEPDF:
        reasons.append("peepdf not available — raw keyword scan only")

    # One clamp at the end rather than per pass: the caps in the keyword
    # table bound individual markers, and this bounds the document.
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
    """Scan the raw bytes for PDF marker keywords without parsing.

    Args:
        file_path: File to read in full.
        file_size: Size in bytes. Currently unused — run() has already
                   enforced the cap — and kept so the signature does not
                   change when this grows a streaming path.

    Returns:
        (score_delta, reason_strings, {keyword: occurrence_count}). An
        unreadable file returns a zero triple rather than raising: the
        header pass may already have produced findings worth keeping.
    """
    score_delta = 0
    reasons: list[str] = []
    hits: dict = {}

    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        logger.debug("Could not read PDF bytes: %s", exc)
        return 0, [], {}

    # Counted once per keyword up front, so the prefix correction below
    # costs no extra passes over what may be 100 MiB of file.
    raw_counts = {kw: raw.count(kw) for kw in _KEYWORD_WEIGHTS}

    # Every occurrence of a longer keyword contains one occurrence of any
    # keyword that prefixes it, so a document carrying only the
    # /EmbeddedFiles name tree would also be scored for an /EmbeddedFile
    # attachment it does not have.
    #
    # Longest first, subtracting *corrected* counts rather than raw ones.
    # That distinction matters for a chain of three (A, AB, ABC), where
    # subtracting raw counts removes the same bytes twice and can drive a
    # genuine standalone match to zero. Processing longest first guarantees
    # every extension of a keyword is already corrected when it is used.
    adjusted: dict[bytes, int] = {}
    for kw in sorted(_KEYWORD_WEIGHTS, key=len, reverse=True):
        adjusted[kw] = raw_counts[kw] - sum(
            n for other, n in adjusted.items()
            if other != kw and other.startswith(kw)
        )

    # Occurrence counts are recorded in full even though scoring caps them,
    # because "/OpenAction x1" and "/OpenAction x40" mean different things
    # to a human reading the report even when they score identically.
    for kw, (weight, cap) in _KEYWORD_WEIGHTS.items():
        count = adjusted[kw]
        if count > 0:
            hits[kw.decode()] = count
            effective = min(count, cap)
            score_delta += weight * effective

    if hits:
        # "Highest-impact" is really insertion order — dict order follows
        # _KEYWORD_WEIGHTS, which is authored most-dangerous-first, so the
        # five shown are the five that matter. Reordering that table
        # therefore changes what the reason string leads with.
        summary = ", ".join(f"{k}({v})" for k, v in list(hits.items())[:5])
        reasons.append(f"Raw PDF markers: {summary}")

    # URI and action density are scored on thresholds rather than as
    # present/absent because both are ordinary in benign documents — a
    # report with a table of contents has dozens of each. Only the shape of
    # the distribution separates them, and these two tiers are the coarsest
    # split that does it. Counted on raw bytes, so a marker inside a
    # compressed object stream is missed; the counts are a lower bound.
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
    # Recorded as a hit, not only scored: _analyse() reads it back to set
    # data["encrypted"], so the payload cannot contradict the reason string
    # on a file peepdf never parsed.
    if b"/Encrypt" in raw:
        hits["/Encrypt"] = raw.count(b"/Encrypt")
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
    """Parse with peepdf and harvest whatever it manages to expose.

    Args:
        file_path: The PDF. Confirmed to carry a %PDF header by the caller.
        data:      The result payload, mutated in place. Written directly
                   rather than returned because each accessor below may
                   fail independently, and a partial harvest is still worth
                   reporting.

    Returns:
        (score_delta, reason_strings) for what peepdf added on top of the
        raw sweep. A parse that fails outright returns (0, [reason]) — the
        module still succeeds on its raw-sweep findings.

    Every accessor is individually wrapped. peepdf's return shapes vary by
    PDF version (a list per version, sometimes a bare value), so each site
    also normalises rather than trusting the documented type.
    """
    score_delta = 0
    reasons: list[str] = []

    # forceMode and looseMode together tell peepdf to keep going through
    # structural violations instead of aborting. Malware PDFs are malformed
    # far more often than not — frequently on purpose, to break parsers —
    # so strict parsing would refuse exactly the files worth reading.
    parser = PDFParser()
    try:
        ret, pdf_file = parser.parse(str(file_path), forceMode=True, looseMode=True)
    except Exception as exc:  # noqa: BLE001
        logger.info("peepdf parse crashed on %s: %s", file_path.name, exc)
        return 0, [f"peepdf parse failure: {exc}"]

    # Both halves are needed: peepdf signals failure through the status
    # code in some paths and through a None document in others.
    if ret != 0 or pdf_file is None:
        return 0, ["peepdf could not parse PDF structure"]

    # Set before any accessor runs, so the report can distinguish "peepdf
    # parsed this and found nothing" from "peepdf never got that far".
    data["parsed"] = True
    try:
        data["version"] = pdf_file.getVersion()
        # Never downgrades: the raw sweep may already have found an
        # /Encrypt dictionary that peepdf failed to reach.
        data["encrypted"] = data["encrypted"] or bool(pdf_file.isEncrypted())
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
    # Only the three in `nasty` score, and only once: peepdf emits dozens of
    # cosmetic complaints on ordinary files, so treating its error list as a
    # signal wholesale would score every PDF ever produced by a bad writer.
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

    # ------------------------------------------------------------------
    # JavaScript. The single most useful thing peepdf provides, and the
    # reason it is worth carrying an unmaintained dependency.
    #
    # getJavascriptCode() returns a list *per PDF version*, whose entries
    # may be (name, code) tuples or bare strings depending on where the
    # script was found. Both shapes are flattened here; "[]" is filtered
    # because peepdf stringifies an empty inner list into that literal.
    # ------------------------------------------------------------------
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

            # Patterns are matched against all blocks joined into one
            # lowercased haystack. Joining loses which block matched, which
            # the report does not show anyway, and gains detection of
            # scripts split across objects to defeat per-block matching.
            joined = " ".join(js_items).lower()
            matched_exploits = [label for pat, label in _JS_EXPLOIT_PATTERNS.items() if pat in joined]
            if matched_exploits:
                score_delta += 15
                reasons.append(f"JS exploit patterns: {', '.join(matched_exploits[:4])}")

            # Social-engineering strings score separately from exploit
            # patterns and lower. They prove intent, not capability: a PDF
            # telling the reader to "open in browser" is a lure, and the
            # payload is wherever it sends them.
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
    # Kept apart from URIs rather than merged: /URI annotation targets are
    # what a click reaches, while these are strings found in decompressed
    # content, and conflating them would hide which of the two a host came
    # from. Neither is scored here — ioc_extractor owns URL scoring, and
    # double-counting the same endpoint across two modules would inflate
    # every phishing PDF.
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
    # Scored only +5 despite covering serious findings, because it overlaps
    # heavily with the raw keyword sweep above — most of what it reports has
    # already been counted there, and this is the increment for peepdf
    # having reached it structurally rather than by byte match.
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
    """Best-effort int conversion for peepdf statistics.

    Args:
        value: Whatever getStats() put in the field — peepdf returns these
               as strings in some versions and ints in others.

    Returns:
        The integer value, or 0 for anything unconvertible. A statistic
        that cannot be read is reported as zero rather than omitted, so the
        report's shape stays constant across peepdf versions.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _skipped(reason: str) -> dict:
    """Build the standard "skipped" result (design rule 1).

    Args:
        reason: Human-readable explanation shown in the module strip.

    Returns:
        A zero-score result dict with empty data.
    """
    return {
        "module": "pdf_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    """Build the standard "error" result (design rule 1).

    Args:
        reason: Human-readable explanation shown in the module strip.

    Returns:
        A zero-score result dict with empty data. Distinct from _skipped()
        because an error means the file *should* have been analysed and was
        not — triage exits 3 on it, where a skip is silent.
    """
    return {
        "module": "pdf_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
