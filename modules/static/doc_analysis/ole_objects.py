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
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from oletools.rtfobj import RtfObjParser
    _HAS_RTFOBJ = True
except ImportError:
    _HAS_RTFOBJ = False

# Equation Editor CLSIDs — matched case-insensitively and with or
# without braces / hyphens.
_EQUATION_EDITOR_CLSIDS = {
    "0002ce02",  # Equation.3 (CVE-2017-11882, CVE-2018-0802)
    "0002ce01",  # Equation.2
    "0003000b",  # older MathType / Equation.2 family
    "0004a6b0",  # MathType newer
}

# OLE Package CLSID — embedded arbitrary file dropper.
_OLE_PACKAGE_CLSID = "0003000c"

# Executable / scriptable extensions that have no business being dropped
# out of an Office document.
_EXEC_EXTENSIONS = frozenset({
    ".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".wsf",
    ".ps1", ".hta", ".lnk", ".inf", ".dll", ".jar", ".msi",
})

# ProgIDs still flagged via class_name substring when no CLSID is emitted.
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

    Returns a dict with:
      - ``object_count``, ``ole_object_count``, ``package_count``
      - ``class_names`` (all), ``high_risk_classes`` (matched substrings)
      - ``equation_editor_candidates`` (CVE tags)
      - ``package_objects`` [{filename, extension, exec_ext}]
      - ``indicator_flags`` — scoring flags
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

    if not _HAS_RTFOBJ:
        logger.info("rtfobj not available — raw scan only")
        _raw_byte_scan(raw, out)
        return out

    try:
        parser = RtfObjParser(raw)
        parser.parse()
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
            for needle, flag in _HIGH_RISK_CLASS_SUBSTRINGS.items():
                if needle in lowered:
                    out["high_risk_classes"].append(class_name)
                    out["indicator_flags"].add(flag)
                    break

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
    name = getattr(obj, "class_name", None)
    if not name:
        return ""
    try:
        return name.decode("latin-1", errors="replace").strip("\x00").strip()
    except Exception:  # noqa: BLE001
        return repr(name)


def _safe_clsid(obj) -> str:  # noqa: ANN001
    # rtfobj exposes the CLSID as bytes via .clsid or via the OLE parser
    # when is_ole is true.
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
    """Pull the embedded filename + extension out of a Package OLE object."""
    info: dict = {"filename": "", "extension": "", "exec_ext": False}
    # rtfobj decodes the Package automatically when is_package is True.
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
    """Fallback markers picked up from raw RTF bytes."""
    lowered = raw[: 2 * 1024 * 1024].lower()
    if b"\\objupdate" in lowered and b"\\objdata" in lowered:
        out["raw_objupdate"] = True
        out["indicator_flags"].add("rtf_objupdate")
    if (b"equation.3" in lowered or b"equation.2" in lowered) \
            and "equation_editor_ole" not in out["indicator_flags"]:
        out["equation_editor_candidates"].append(
            "Equation Editor ProgID in raw bytes"
        )
        out["indicator_flags"].add("equation_editor_ole")
