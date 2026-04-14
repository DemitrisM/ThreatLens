"""Office document analysis module — production-grade static triage.

Covers ``.doc`` / ``.docx`` / ``.docm`` / ``.xls`` / ``.xlsx`` /
``.xlsm`` / ``.xlsb`` / ``.ppt`` / ``.pptx`` / ``.pptm`` / ``.rtf``,
routed by magic bytes (not extension) because samples like
``AgentTesla.doc`` are often RTF in disguise.

Passes:

1. **VBA macros** (``vba_macros.py``) — olevba keyword categories,
   MacroRaptor risk flags, and **VBA stomping detection** via pcodedmp
   (source/p-code divergence + EvilClippy MODULESTREAMNAME mismatch).
2. **XLM macros** (``xlm_macros.py``) — XLMMacroDeobfuscator with a
   hard wall-clock timeout; flags EXEC/CALL/URLs.
3. **Template injection** (``template_inject.py``) — OOXML ``.rels``
   parser with severity tiers + non-Microsoft-URL flag; RTF
   ``{\\*\\template}`` regex scan.
4. **OLE objects** (``ole_objects.py``) — rtfobj with Equation Editor
   CLSID matching (CVE-2017-11882 / CVE-2018-0802) and OLE Package
   exec-extension detection.
5. **oleid indicators** (``oleid_indicators.py``) — container-level
   risk flags including encryption-without-macros evasion.
6. **Scoring** (``scoring.py``) — weighted combo engine: co-firing
   indicators score as combinations, not sums. Cap 60.
"""

import logging
import time
from pathlib import Path

from .routing import (
    MAX_FILE_SIZE,
    detect_format,
    is_office_file,
    is_xlm_candidate,
)
from .vba_macros import analyse_vba
from .xlm_macros import analyse_xlm
from .template_inject import analyse_openxml_rels, analyse_rtf_template
from .ole_objects import analyse_rtf_objects
from .oleid_indicators import analyse_oleid
from .scoring import score_document

logger = logging.getLogger(__name__)


def run(file_path: Path, config: dict) -> dict:
    """Analyse an Office document. Returns the standard module result dict."""
    if not is_office_file(file_path):
        return _skipped("Not applicable — not an Office document")

    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return _error(f"Could not stat file: {exc}")

    if size > MAX_FILE_SIZE:
        return _skipped(
            f"File too large for doc_analysis ({size} bytes > {MAX_FILE_SIZE})"
        )

    try:
        return _analyse(file_path, config)
    except Exception as exc:  # noqa: BLE001
        logger.error("doc_analysis failed on %s: %s", file_path.name, exc)
        return _error(f"Analysis error: {exc}")


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def _analyse(file_path: Path, _config: dict) -> dict:
    fmt = detect_format(file_path)
    indicator_flags: set[str] = set()
    timings: dict[str, float] = {}

    # ── VBA (OLE + OpenXML) ────────────────────────────────────────────────
    vba: dict = {"present": False, "performed": False}
    if fmt in ("ole", "openxml"):
        t0 = time.perf_counter()
        vba = analyse_vba(file_path)
        timings["vba"] = time.perf_counter() - t0
        indicator_flags |= vba.get("indicator_flags", set())
        vba["performed"] = True

    # ── XLM (Excel only) ───────────────────────────────────────────────────
    xlm: dict = {"performed": False, "present": False}
    if is_xlm_candidate(file_path, fmt):
        t0 = time.perf_counter()
        xlm = analyse_xlm(file_path)
        timings["xlm"] = time.perf_counter() - t0
        indicator_flags |= xlm.get("indicator_flags", set())

    # ── Template injection ─────────────────────────────────────────────────
    ooxml: dict = {}
    rtf_template: dict = {"templates": []}
    if fmt == "openxml":
        t0 = time.perf_counter()
        ooxml = analyse_openxml_rels(file_path)
        timings["openxml_rels"] = time.perf_counter() - t0
        indicator_flags |= ooxml.get("indicator_flags", set())
    if fmt == "rtf":
        try:
            raw_rtf = file_path.read_bytes()
        except OSError as exc:
            logger.info("Could not read RTF %s: %s", file_path.name, exc)
            raw_rtf = b""
    else:
        raw_rtf = b""
    if raw_rtf:
        t0 = time.perf_counter()
        rtf_template = analyse_rtf_template(raw_rtf)
        timings["rtf_template"] = time.perf_counter() - t0
        indicator_flags |= rtf_template.get("indicator_flags", set())

    # ── OLE objects (RTF path) ─────────────────────────────────────────────
    rtf_objects: dict = {}
    if fmt == "rtf" and raw_rtf:
        t0 = time.perf_counter()
        rtf_objects = analyse_rtf_objects(raw_rtf)
        timings["rtf_objects"] = time.perf_counter() - t0
        indicator_flags |= rtf_objects.get("indicator_flags", set())

    # ── oleid (any non-RTF Office) ─────────────────────────────────────────
    oleid: dict = {"indicators": []}
    if fmt in ("ole", "openxml"):
        t0 = time.perf_counter()
        oleid = analyse_oleid(file_path)
        timings["oleid"] = time.perf_counter() - t0
        indicator_flags |= oleid.get("indicator_flags", set())

    # ── Scoring ────────────────────────────────────────────────────────────
    score_delta, reasons, classification = score_document(indicator_flags)

    data = _build_data(
        fmt=fmt,
        vba=vba,
        xlm=xlm,
        ooxml=ooxml,
        rtf_template=rtf_template,
        rtf_objects=rtf_objects,
        oleid=oleid,
        classification=classification,
        indicator_flags=indicator_flags,
        timings=timings,
    )

    if reasons:
        reason_text = "; ".join(reasons)
    else:
        reason_text = "No suspicious OLE/VBA content detected"

    return {
        "module": "doc_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


def _build_data(**parts) -> dict:
    """Assemble the JSON-serialisable data dict exposed to reporters."""
    vba = parts["vba"] or {}
    xlm = parts["xlm"] or {}
    ooxml = parts["ooxml"] or {}
    rtf_template = parts["rtf_template"] or {}
    rtf_objects = parts["rtf_objects"] or {}
    oleid = parts["oleid"] or {}

    return {
        "format": parts["fmt"],
        "classification": parts["classification"],
        "indicator_flags": sorted(parts["indicator_flags"]),
        "timings": parts["timings"],

        # Macro findings
        "macros": {
            "vba": {
                "present": vba.get("present", False),
                "count": vba.get("count", 0),
                "streams": vba.get("streams", []),
                "auto_exec_keywords": vba.get("auto_exec_keywords", []),
                "suspicious_keywords": vba.get("suspicious_keywords", []),
                "ioc_keywords": vba.get("ioc_keywords", []),
                "mraptor_flags": vba.get("mraptor_flags", {}),
                "stomping_detected": vba.get("stomping_detected", False),
                "stomping_check_performed": vba.get("stomping_check_performed", False),
                "modulestreamname_mismatch": vba.get("modulestreamname_mismatch", False),
                "heavy_obfuscation": vba.get("heavy_obfuscation", False),
            },
            "xlm": {
                "performed": xlm.get("performed", False),
                "present": xlm.get("present", False),
                "cell_count": xlm.get("cell_count", 0),
                "deobfuscated_cells": xlm.get("deobfuscated_cells", []),
                "exec_call_found": xlm.get("exec_call_found", False),
                "urls": xlm.get("urls", []),
            },
        },

        "template_injection": {
            "ooxml": ooxml.get("external_relationships", []),
            "alt_chunks": ooxml.get("alt_chunks", []),
            "rtf": rtf_template.get("templates", []),
        },

        "ole_objects": {
            "rtf_classes": rtf_objects.get("class_names", []),
            "high_risk_classes": rtf_objects.get("high_risk_classes", []),
            "equation_editor_candidates": rtf_objects.get(
                "equation_editor_candidates", []
            ),
            "package_objects": rtf_objects.get("package_objects", []),
            "ole_object_count": rtf_objects.get("ole_object_count", 0),
            "package_count": rtf_objects.get("package_count", 0),
            "raw_objupdate": rtf_objects.get("raw_objupdate", False),
        },

        "openxml_findings": {
            "alt_chunks": ooxml.get("alt_chunks", []),
            "external_relationships": ooxml.get("external_relationships", []),
            "embedded_files": ooxml.get("embedded_files", []),
            "dangerous_embedded": ooxml.get("dangerous_embedded", []),
            "ole_objects": ooxml.get("ole_objects", []),
            "decompression_bomb": ooxml.get("decompression_bomb", False),
        },

        "oleid_indicators": oleid.get("indicators", []),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skipped(reason: str) -> dict:
    return {
        "module": "doc_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    return {
        "module": "doc_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
