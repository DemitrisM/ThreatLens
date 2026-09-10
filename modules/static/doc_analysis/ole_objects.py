"""Embedded OLE object analysis for RTF files.

Extends the previous rtfobj pass with:

* **Equation Editor CLSID matching** — identifies CVE-2017-11882 and
  CVE-2018-0802 candidates by the object's reported CLSID rather than
  just class-name substring matching.
* **OLE Package inspection** — CLSID ``0003000C-0000-...`` is the
  Package container used to drop arbitrary files; we extract the
  embedded filename and flag executable extensions.

Falls back to a raw-byte scan for ``\\objupdate`` + ``\\objdata`` and the
classic ``Equation.3`` / ``Equation.2`` ProgID strings — catches
obfuscation that defeats rtfobj's stream parser.

Design notes
------------
Identification is attempted by CLSID first and class name second, and the
order matters. A class name is a string the document chose for itself and
can be misspelled, padded or hex-escaped past a substring match; the
CLSID is what Windows actually dispatches on. The name-based table is the
fallback for objects whose CLSID rtfobj could not surface, not the
primary check.

The raw byte scan runs *in addition* to a successful parse, never only as
a fallback. RTF obfuscation targets the parser specifically — nested
groups, junk control words, split hex — so a sample can parse cleanly
into objects that hide what a flat byte scan sees plainly. The scan is
guarded against re-flagging what the parser already found, so the two
paths do not double-count.

A parse failure is itself scored (``rtf_parse_failed``). Benign RTF from
Word parses; a document that defeats rtfobj is usually malformed on
purpose.

The CLSID prefix comparison uses the first eight hex digits only. That is
the component Microsoft varies per class within these families, and
matching the full GUID would miss the version-suffixed variants that
carry the same vulnerable code path.

Note ``.lnk`` reaches this module only as an OLE Package filename
extension, scored blind on its extension. Handing those bytes to
lnk_analysis is a planned follow-up recorded in CLAUDE.md; this is one of
the three detection sites it will change.
"""

import logging
from pathlib import Path

from ._quiet import quiet_stdout

logger = logging.getLogger(__name__)

try:
    with quiet_stdout(logger, "oletools.rtfobj"):
        from oletools.rtfobj import RtfObjParser
    _HAS_RTFOBJ = True
except ImportError:
    _HAS_RTFOBJ = False

# Equation Editor CLSIDs — matched case-insensitively and with or
# without braces / hyphens.
#
# Equation Editor is the reason RTF remained an attack format after the
# macro block: EQNEDT32.EXE is an out-of-process COM server compiled
# before modern mitigations, and CVE-2017-11882 / CVE-2018-0802 are stack
# overflows in its font-record parsing. A document embedding it is not
# necessarily an exploit, but it is one of the very few reasons to.
_EQUATION_EDITOR_CLSIDS = {
    "0002ce02",  # Equation.3 (CVE-2017-11882, CVE-2018-0802)
    "0002ce01",  # Equation.2
    "0003000b",  # older MathType / Equation.2 family
    "0004a6b0",  # MathType newer
}

# OLE Package CLSID — embedded arbitrary file dropper.
# The Package container carries an arbitrary file plus the name to write
# it under, which is why the extension inside it is what gets scored
# rather than the presence of the container.
_OLE_PACKAGE_CLSID = "0003000c"

# Executable / scriptable extensions that have no business being dropped
# out of an Office document.
_EXEC_EXTENSIONS = frozenset({
    ".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".wsf",
    ".ps1", ".hta", ".lnk", ".inf", ".dll", ".jar", ".msi",
})

# ProgIDs still flagged via class_name substring when no CLSID is emitted.
# Substring rather than exact match because the class name in an RTF is
# free text that samples pad and case-shift. Note these values are flag
# names: only "equation_editor_ole" and (indirectly) the package path
# currently appear in the scoring rules.
_HIGH_RISK_CLASS_SUBSTRINGS = {
    "equation.3": "equation_editor_ole",
    "equation.2": "equation_editor_ole",
    "equation native": "equation_editor_ole",
    "package": "ole_package",
    "packager shell": "packager_shell",
    "shell.explorer": "shell_explorer",
    "htmlfile": "htmlfile",
}


def analyse_rtf_objects(raw: bytes) -> dict:
    """Parse RTF raw bytes for embedded OLE objects.

    Args:
        raw: The document's bytes, read once by the orchestrator and shared
             with the template-injection pass.


    Returns a dict with:
      - ``object_count``, ``ole_object_count``, ``package_count``
      - ``class_names`` (all), ``high_risk_classes`` (matched substrings)
      - ``equation_editor_candidates`` (CVE tags)
      - ``package_objects`` [{filename, extension, exec_ext}]
      - ``indicator_flags`` — scoring flags

    Never raises. Without rtfobj, or when it fails, the raw byte scan
    still runs — so this pass always produces something for an RTF.
    """
    out: dict = {
        "object_count": 0,
        "ole_object_count": 0,
        "package_count": 0,
        "class_names": [],
        "high_risk_classes": [],
        "equation_editor_candidates": [],
        "package_objects": [],
        "raw_objupdate": False,
        "indicator_flags": set(),
    }

    # Degraded but not skipped: the byte scan alone still catches the two
    # highest-value RTF indicators, \objupdate and the Equation ProgIDs.
    if not _HAS_RTFOBJ:
        logger.info("rtfobj not available — raw scan only")
        _raw_byte_scan(raw, out)
        return out

    try:
        parser = RtfObjParser(raw)
        parser.parse()
    # A parse failure is a finding, not just a degradation — see the
    # module docstring — and the byte scan then carries the pass.
    except Exception as exc:  # noqa: BLE001
        logger.info("rtfobj parse failed: %s", exc)
        out["indicator_flags"].add("rtf_parse_failed")
        _raw_byte_scan(raw, out)
        return out

    out["object_count"] = len(parser.objects)
    for obj in parser.objects:
        class_name = _safe_class_name(obj)
        clsid = _safe_clsid(obj)
        if class_name:
            out["class_names"].append(class_name)
            lowered = class_name.lower()
            # First match wins: the table is ordered most specific first,
            # and "package" would otherwise also match "packager shell".
            for needle, flag in _HIGH_RISK_CLASS_SUBSTRINGS.items():
                if needle in lowered:
                    out["high_risk_classes"].append(class_name)
                    out["indicator_flags"].add(flag)
                    break

        # Normalised because the CLSID reaches us in whatever form rtfobj
        # recovered it — braced, hyphenated, upper or lower case.
        if clsid:
            clsid_norm = clsid.lower().replace("-", "").replace("{", "").replace("}", "")
            clsid_prefix = clsid_norm[:8]
            if clsid_prefix in _EQUATION_EDITOR_CLSIDS:
                tag = {
                    "0002ce02": "CVE-2017-11882 / CVE-2018-0802 (Equation.3)",
                    "0002ce01": "Equation.2",
                    "0003000b": "Equation family (MathType)",
                    "0004a6b0": "MathType",
                }[clsid_prefix]
                out["equation_editor_candidates"].append(tag)
                out["indicator_flags"].add("equation_editor_ole")
            if clsid_prefix == _OLE_PACKAGE_CLSID:
                pkg = _extract_package_info(obj)
                out["package_objects"].append(pkg)
                if pkg.get("exec_ext"):
                    out["indicator_flags"].add("ole_package_exec_ext")

        # rtfobj's own classification, kept separate from the CLSID work
        # above: is_package can be true for an object whose CLSID was not
        # recovered, which is why the package is re-extracted here and
        # de-duplicated on filename rather than simply appended.
        if getattr(obj, "is_ole", False):
            out["ole_object_count"] += 1
        if getattr(obj, "is_package", False):
            out["package_count"] += 1
            if not any(
                p.get("filename") == _extract_package_info(obj).get("filename")
                for p in out["package_objects"]
            ):
                pkg = _extract_package_info(obj)
                out["package_objects"].append(pkg)
                if pkg.get("exec_ext"):
                    out["indicator_flags"].add("ole_package_exec_ext")

    _raw_byte_scan(raw, out)
    return out


def _safe_class_name(obj) -> str:  # noqa: ANN001
    """Decode an object's class name defensively.

    Args:
        obj: One rtfobj object. Attributes are read through getattr because
             the shape differs across oletools versions.

    Returns:
        The class name as text, or "" when absent. latin-1 with
        replacement never fails, and the trailing NUL is stripped because
        the field is a C string in the original structure.
    """
    name = getattr(obj, "class_name", None)
    if not name:
        return ""
    try:
        return name.decode("latin-1", errors="replace").strip("\x00").strip()
    except Exception:  # noqa: BLE001
        return repr(name)


def _safe_clsid(obj) -> str:  # noqa: ANN001
    """Recover an object's CLSID from whichever attribute holds it.

    Args:
        obj: One rtfobj object.

    Returns:
        The CLSID as text, or "" if no attribute carried one.

    Four attribute names and two nested parser objects are tried because
    oletools moved this field across versions and exposes it as bytes on
    some paths and as an already-formatted string on others. Returning ""
    simply falls the caller back to class-name matching.
    """
    # Ordered by reliability: the raw .clsid field first, the human
    # description variants after, and the nested OLE parser last.
    for attr in ("clsid", "clsid_desc", "clsid_text"):
        val = getattr(obj, attr, None)
        if val:
            try:
                return val.decode("ascii", errors="replace") if isinstance(val, bytes) else str(val)
            except Exception:  # noqa: BLE001
                continue
    ole = getattr(obj, "oleobj", None) or getattr(obj, "ole", None)
    if ole is not None:
        clsid = getattr(ole, "clsid", None)
        if clsid:
            return str(clsid)
    return ""


def _extract_package_info(obj) -> dict:  # noqa: ANN001
    """Pull the embedded filename + extension out of a Package OLE object.

    Args:
        obj: An rtfobj object whose CLSID or is_package flag identified it
             as a Package container.

    Returns:
        ``{"filename", "extension", "exec_ext"}``, all empty/False when no
        filename could be recovered.

    The extension is the scored signal, not the container: a Package
    holding a .txt is a legitimate attachment, one holding a .exe or .hta
    is a dropper with the payload already inside the document.
    """
    info: dict = {"filename": "", "extension": "", "exec_ext": False}
    # Three attribute names for the same idea — the name declared inside
    # the Package, and the two paths rtfobj may have written it to.
    filename = (
        getattr(obj, "filename", None)
        or getattr(obj, "src_path", None)
        or getattr(obj, "temp_path", None)
    )
    if isinstance(filename, bytes):
        try:
            filename = filename.decode("latin-1", errors="replace")
        except Exception:  # noqa: BLE001
            filename = ""
    if filename:
        info["filename"] = filename
        ext = Path(filename).suffix.lower()
        info["extension"] = ext
        if ext in _EXEC_EXTENSIONS:
            info["exec_ext"] = True
    return info


def _raw_byte_scan(raw: bytes, out: dict) -> None:
    """Fallback markers picked up from raw RTF bytes.

    Args:
        raw: The document's bytes; only the first 2 MiB are lowercased and
             searched, which is where RTF keeps its object data.
        out: Result dict, mutated in place.

    Returns:
        None.

    Runs after a successful parse as well as after a failed one — see the
    module docstring. The Equation check is suppressed when the parser
    already flagged it, so the two paths agree instead of double-counting;
    ``\\objupdate`` has no parser equivalent, so it needs no such guard.
    """
    lowered = raw[: 2 * 1024 * 1024].lower()
    # Both control words are required. \objupdate alone is a rendering
    # hint; paired with \objdata it forces the embedded object to load
    # when the document opens, with no click.
    if b"\\objupdate" in lowered and b"\\objdata" in lowered:
        out["raw_objupdate"] = True
        out["indicator_flags"].add("rtf_objupdate")
    if (b"equation.3" in lowered or b"equation.2" in lowered) \
            and "equation_editor_ole" not in out["indicator_flags"]:
        out["equation_editor_candidates"].append(
            "Equation Editor ProgID in raw bytes"
        )
        out["indicator_flags"].add("equation_editor_ole")
