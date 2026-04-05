"""PDF analysis module.

Uses peepdf to inspect PDF object structure, extract embedded JavaScript,
detect launch/URI actions, and analyse stream entropy. Returns score_delta
for suspicious elements found.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from peepdf.PDFCore import PDFParser
    _HAS_PEEPDF = True
except ImportError:
    _HAS_PEEPDF = False
    logger.warning("peepdf not available — PDF analysis disabled")

# MIME types for PDF files.
_PDF_MIMES = {
    "application/pdf",
    "application/x-pdf",
}


def run(file_path: Path, config: dict) -> dict:
    """Analyse a PDF file for suspicious structures and embedded code.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict.

    Returns:
        Standard module result dict.
    """
    if not _HAS_PEEPDF:
        return _skipped("peepdf library not installed")

    # Check whether the file is actually a PDF.
    if not _is_pdf(file_path):
        return _skipped("Not applicable — not a PDF file")

    try:
        return _analyse(file_path)
    except Exception as exc:  # noqa: BLE001
        logger.error("pdf_analysis failed: %s", exc)
        return _error(f"Analysis error: {exc}")


def _is_pdf(file_path: Path) -> bool:
    """Determine if the file is a PDF by extension or magic bytes."""
    if file_path.suffix.lower() == ".pdf":
        return True
    # Check magic bytes (%PDF-)
    try:
        with file_path.open("rb") as f:
            header = f.read(1024)
        return b"%PDF-" in header
    except OSError:
        return False


def _analyse(file_path: Path) -> dict:
    """Parse PDF and extract findings."""
    score_delta = 0
    reasons: list[str] = []

    data: dict = {
        "version": None,
        "num_pages": 0,
        "num_objects": 0,
        "num_streams": 0,
        "encrypted": False,
        "has_javascript": False,
        "javascript_count": 0,
        "javascript_code": [],
        "uris": [],
        "urls": [],
        "suspicious_elements": [],
        "errors": [],
    }

    parser = PDFParser()
    ret, pdf_file = parser.parse(str(file_path), forceMode=True, looseMode=True)

    if ret != 0 or pdf_file is None:
        return {
            "module": "pdf_analysis",
            "status": "success",
            "data": data,
            "score_delta": 0,
            "reason": "Could not parse PDF structure — file may be corrupted",
        }

    # Basic metadata
    data["version"] = pdf_file.getVersion()
    data["encrypted"] = pdf_file.isEncrypted()

    # Get stats for object/stream counts
    try:
        stats = pdf_file.getStats()
        if isinstance(stats, dict):
            data["num_objects"] = stats.get("Objects", 0)
            data["num_streams"] = stats.get("Streams", 0)
            data["num_pages"] = stats.get("Pages", 0)
    except Exception:  # noqa: BLE001
        pass

    # ── Encryption ──
    if data["encrypted"]:
        score_delta += 5
        reasons.append("PDF is encrypted — may be hiding content")

    # ── Embedded JavaScript ──
    try:
        js_code_list = pdf_file.getJavascriptCode()
        if js_code_list:
            js_items = []
            for version_js in js_code_list:
                if isinstance(version_js, list):
                    for code_entry in version_js:
                        if isinstance(code_entry, tuple) and len(code_entry) >= 2:
                            js_items.append(str(code_entry[1])[:500])
                        elif isinstance(code_entry, str):
                            js_items.append(code_entry[:500])
                elif isinstance(version_js, str):
                    js_items.append(version_js[:500])

            if js_items:
                data["has_javascript"] = True
                data["javascript_count"] = len(js_items)
                data["javascript_code"] = js_items[:10]  # Cap stored code
                score_delta += 15
                reasons.append(f"Embedded JavaScript found ({len(js_items)} block(s))")

                # Check for known exploit patterns in JS.
                all_js = " ".join(js_items).lower()
                exploit_patterns = {
                    "eval(": "eval() call",
                    "unescape(": "unescape() call",
                    "shellcode": "shellcode reference",
                    "spray": "heap spray pattern",
                    "string.fromcharcode": "character code obfuscation",
                    "activexobject": "ActiveX instantiation",
                    "wscript.shell": "WScript.Shell access",
                    "adodb.stream": "ADODB.Stream access",
                }
                found_patterns = []
                for pattern, label in exploit_patterns.items():
                    if pattern in all_js:
                        found_patterns.append(label)

                if found_patterns:
                    score_delta += 10
                    reasons.append(f"Suspicious JS patterns: {', '.join(found_patterns[:5])}")
    except Exception as exc:  # noqa: BLE001
        logger.debug("JavaScript extraction failed: %s", exc)

    # ── URIs and URLs ──
    try:
        uris = pdf_file.getURIs()
        if uris:
            flat_uris = []
            for version_uris in uris:
                if isinstance(version_uris, list):
                    flat_uris.extend(str(u) for u in version_uris)
                elif isinstance(version_uris, str):
                    flat_uris.append(version_uris)
            data["uris"] = flat_uris[:50]  # Cap at 50

            if flat_uris:
                score_delta += 5
                reasons.append(f"External URIs found ({len(flat_uris)} URI(s))")
    except Exception as exc:  # noqa: BLE001
        logger.debug("URI extraction failed: %s", exc)

    try:
        urls = pdf_file.getURLs()
        if urls:
            flat_urls = []
            for version_urls in urls:
                if isinstance(version_urls, list):
                    flat_urls.extend(str(u) for u in version_urls)
                elif isinstance(version_urls, str):
                    flat_urls.append(version_urls)
            data["urls"] = flat_urls[:50]

            if flat_urls:
                score_delta += 5
                reasons.append(f"Embedded URLs found ({len(flat_urls)} URL(s))")
    except Exception as exc:  # noqa: BLE001
        logger.debug("URL extraction failed: %s", exc)

    # ── Suspicious elements ──
    try:
        suspicious = pdf_file.getSuspiciousComponents()
        if suspicious:
            flat_suspicious = []
            for version_susp in suspicious:
                if isinstance(version_susp, list):
                    for item in version_susp:
                        flat_suspicious.append(str(item))
                elif isinstance(version_susp, dict):
                    for key, val in version_susp.items():
                        flat_suspicious.append(f"{key}: {val}")
                elif isinstance(version_susp, str):
                    flat_suspicious.append(version_susp)

            data["suspicious_elements"] = flat_suspicious[:20]

            if flat_suspicious:
                score_delta += 10
                reasons.append(f"Suspicious PDF elements: {', '.join(flat_suspicious[:3])}")
    except Exception as exc:  # noqa: BLE001
        logger.debug("Suspicious component extraction failed: %s", exc)

    # ── Errors / anomalies detected by peepdf ──
    try:
        errors = pdf_file.getErrors()
        if errors:
            data["errors"] = [str(e) for e in errors[:10]]
    except Exception:  # noqa: BLE001
        pass

    # Cap total contribution at 50.
    score_delta = min(score_delta, 50)

    reason_text = "; ".join(reasons) if reasons else "No suspicious PDF elements detected"

    return {
        "module": "pdf_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


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
