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

Design notes
------------
Format routing decides which passes run, and it is done on magic bytes
rather than the extension for a specific reason: RTF-in-a-.doc is one of
the commonest disguises in this corpus, and feeding such a file to olevba
produces a parse failure rather than the RTF findings that were there to
be had. ``detect_format`` is therefore the first thing ``_analyse`` calls,
and every pass below is gated on its answer.

Passes communicate with the scoring engine through one channel only: a
flat ``set[str]`` of indicator flags, unioned from every pass. That is
what lets the combo engine reason about *co-occurrence* across passes —
"AutoExec from olevba" plus "OLE Package with an .exe from rtfobj" is a
rule, even though the two facts come from different libraries. The dict
each pass returns beside its flags is presentation only; nothing scores
off it, so a reporter change can never move a score.

Every pass returns rather than raises. That is not merely design rule 2
politeness — it is what allows a document to be scored on the passes that
worked when olevba chokes on it, which for deliberately malformed samples
is most of them. ``run()`` still carries a blanket catch as a backstop,
but reaching it means a pass broke its own contract.

The wall-clock timing of each pass is recorded in ``data["timings"]``.
Not decoration: olevba and XLMMacroDeobfuscator are the two slowest things
in a standard scan, and this is the only place that says which one cost
the time on a given sample.
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
    """Analyse an Office document. Returns the standard module result dict.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict. Not read — the size cap and
                   the per-library timeouts are module constants, since a
                   document large enough to matter here is pathological at
                   any scan profile.

    Returns:
        Standard module result dict. "skipped" when the file is not an
        Office document or exceeds the size cap, "error" when it cannot be
        stat'd or a pass broke its no-raise contract, "success" otherwise.
    """
    # Gate on file type before touching anything: every scan runs all
    # thirteen modules, so most files that reach here are not documents.
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

    # Backstop only. Each pass is contracted never to raise, so reaching
    # this catch means one of them broke that contract — hence the error
    # log, where the per-pass failures below log at info or debug.
    try:
        return _analyse(file_path, config)
    except Exception as exc:  # noqa: BLE001
        logger.error("doc_analysis failed on %s: %s", file_path.name, exc)
        return _error(f"Analysis error: {exc}")


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def _analyse(file_path: Path, _config: dict) -> dict:
    """Run every applicable pass and score the union of their flags.

    Args:
        file_path: The document. Size and type already checked by run().
        _config:   Unused; kept so the signature matches the module seam.

    Returns:
        The standard module result dict with status "success".

    Passes are gated on the detected format, so a given document runs three
    or four of the six. A pass that does not run leaves its ``performed``
    field False rather than being omitted, which is what lets the report
    distinguish "checked, found nothing" from "never checked".
    """
    # Magic bytes, not the extension — see the module docstring.
    fmt = detect_format(file_path)

    # The one channel into scoring: every pass contributes to this set, and
    # nothing else a pass returns can affect the score.
    indicator_flags: set[str] = set()
    timings: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Pass 1: VBA macros. Runs for both container formats, since a .docm
    # is a ZIP and a .doc is an OLE compound file but olevba reads either.
    # RTF is excluded because RTF cannot carry a VBA project at all — its
    # macro-equivalent is the embedded OLE object handled in pass 4.
    # ------------------------------------------------------------------
    vba: dict = {"present": False, "performed": False}
    if fmt in ("ole", "openxml"):
        t0 = time.perf_counter()
        vba = analyse_vba(file_path)
        timings["vba"] = time.perf_counter() - t0
        indicator_flags |= vba.get("indicator_flags", set())
        vba["performed"] = True

    # ------------------------------------------------------------------
    # Pass 2: XLM (Excel 4.0) macros. Gated on extension as well as format
    # by is_xlm_candidate, because the deobfuscator is slow and the answer
    # for a Word document is always "none".
    # ------------------------------------------------------------------
    xlm: dict = {"performed": False, "present": False}
    if is_xlm_candidate(file_path, fmt):
        t0 = time.perf_counter()
        xlm = analyse_xlm(file_path)
        timings["xlm"] = time.perf_counter() - t0
        indicator_flags |= xlm.get("indicator_flags", set())

    # ------------------------------------------------------------------
    # Pass 3: Template injection, by two unrelated mechanisms.
    #
    # OOXML carries it in the relationship graph (an external
    # attachedTemplate target); RTF carries it as a {\*\template} control
    # word in the raw bytes. Nothing is shared between the two paths but
    # the flags they emit, which is exactly the point of the flag channel.
    # ------------------------------------------------------------------
    ooxml: dict = {}
    rtf_template: dict = {"templates": []}
    if fmt == "openxml":
        t0 = time.perf_counter()
        ooxml = analyse_openxml_rels(file_path)
        timings["openxml_rels"] = time.perf_counter() - t0
        indicator_flags |= ooxml.get("indicator_flags", set())
    # Read once, used by both RTF passes. Bounded by the caller's size cap,
    # and a read failure degrades to an empty buffer so the OOXML findings
    # already collected above survive.
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

    # ------------------------------------------------------------------
    # Pass 4: Embedded OLE objects, RTF only.
    #
    # The OOXML equivalent is covered inside pass 3, which sees embedded
    # streams while it is already walking the ZIP. Splitting them this way
    # avoids opening the container twice.
    # ------------------------------------------------------------------
    rtf_objects: dict = {}
    if fmt == "rtf" and raw_rtf:
        t0 = time.perf_counter()
        rtf_objects = analyse_rtf_objects(raw_rtf)
        timings["rtf_objects"] = time.perf_counter() - t0
        indicator_flags |= rtf_objects.get("indicator_flags", set())

    # ------------------------------------------------------------------
    # Pass 5: oleid container-level indicators. Not RTF, which has no
    # container for oleid to inspect. Its value is breadth rather than
    # depth — it answers "encrypted?", "signed?", "declared type versus
    # actual content?" in one call, and those overlap little with anything
    # the four passes above look at.
    # ------------------------------------------------------------------
    oleid: dict = {"indicators": []}
    if fmt in ("ole", "openxml"):
        t0 = time.perf_counter()
        oleid = analyse_oleid(file_path)
        timings["oleid"] = time.perf_counter() - t0
        indicator_flags |= oleid.get("indicator_flags", set())

    # ------------------------------------------------------------------
    # Pass 6: Score the union. The engine sees only the flag set, so the
    # order the passes ran in cannot affect the result.
    # ------------------------------------------------------------------
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
    """Assemble the JSON-serialisable data dict exposed to reporters.

    Args:
        **parts: The per-pass result dicts plus fmt, classification,
                 indicator_flags and timings. Passed by keyword because
                 there are ten of them and positional order would be a
                 standing invitation to transpose two.

    Returns:
        A dict of plain JSON types. ``indicator_flags`` is sorted here —
        it is a set everywhere upstream, and an unordered field would churn
        the golden report snapshots on every run.

    Each pass's dict is read through ``.get`` with an explicit default, so
    a pass that did not run (and returned its bare skeleton) yields the
    same shape as one that ran and found nothing. Reporters can therefore
    index this structure unconditionally.
    """
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
    """Build the standard "skipped" result (design rule 1).

    Args:
        reason: Human-readable explanation shown in the module strip.

    Returns:
        A zero-score result dict with empty data.
    """
    return {
        "module": "doc_analysis",
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
        because an error means the document should have been analysed and
        was not — triage exits 3 on it, where a skip is silent.
    """
    return {
        "module": "doc_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
