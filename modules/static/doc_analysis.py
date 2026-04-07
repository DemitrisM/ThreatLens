"""Office document analysis module.

Uses oletools (olevba, mraptor, oleid, rtfobj) plus manual OpenXML
inspection to detect VBA macros, auto-execution triggers, altChunk /
template injection, embedded RTF objects, external template references,
and CVE-2017-11882-style Equation Editor abuse across .doc, .docx,
.xls, .xlsx, .ppt, .pptx and .rtf files.
"""

import logging
import re
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from oletools.olevba import VBA_Parser
    _HAS_OLEVBA = True
except ImportError:
    _HAS_OLEVBA = False
    logger.warning("oletools.olevba not available — VBA analysis disabled")

try:
    from oletools.mraptor import MacroRaptor
    _HAS_MRAPTOR = True
except ImportError:
    _HAS_MRAPTOR = False

try:
    from oletools.oleid import OleID
    _HAS_OLEID = True
except ImportError:
    _HAS_OLEID = False

try:
    from oletools.rtfobj import RtfObjParser
    _HAS_RTFOBJ = True
except ImportError:
    _HAS_RTFOBJ = False
    logger.warning("oletools.rtfobj not available — RTF analysis disabled")

# MIME types that indicate Office documents.
_OFFICE_MIMES = {
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-word.document.macroEnabled.12",
    "text/rtf",
    "application/rtf",
}

# File extensions recognised as Office documents.
_OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm", ".xlsb",
    ".ppt", ".pptx", ".pptm",
    ".rtf",
}

# Safety: refuse to analyse very large documents or zip entries to avoid
# memory exhaustion from decompression bombs or oversized embedded objects.
_MAX_FILE_SIZE = 100 * 1024 * 1024          # 100 MiB hard cap
_MAX_ZIP_UNCOMPRESSED = 300 * 1024 * 1024   # 300 MiB cumulative cap for docx contents
_MAX_ZIP_RATIO = 200                        # per-entry compression ratio limit
_DOC_SCORE_CAP = 60

# Known-dangerous OLE class names that appear inside RTF-embedded objects.
_HIGH_RISK_CLASSES = {
    "equation.3": 25,                    # CVE-2017-11882, CVE-2018-0802
    "equation.2": 25,
    "equation native": 20,
    "package": 15,                       # arbitrary file drop
    "package16": 15,
    "packager shell": 20,
    "shell.explorer": 20,
    "htmlfile": 15,
}

# Extensions treated as hostile when found embedded inside a docx.
_DANGEROUS_EMBEDDED_EXTS = {
    ".rtf": 15,
    ".exe": 25,
    ".dll": 20,
    ".scr": 25,
    ".bat": 15,
    ".cmd": 15,
    ".ps1": 15,
    ".vbs": 15,
    ".js": 10,
    ".hta": 20,
    ".lnk": 15,
    ".jar": 10,
}


def run(file_path: Path, config: dict) -> dict:
    """Analyse an Office document for macros, embedded objects, and
    template-injection indicators.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict.

    Returns:
        Standard module result dict.
    """
    if not (_HAS_OLEVBA or _HAS_RTFOBJ):
        return _skipped("oletools library not installed")

    if not _is_office_file(file_path, config):
        return _skipped("Not applicable — not an Office document")

    # Safety: refuse to process anything over the hard cap.
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return _error(f"Could not stat file: {exc}")
    if size > _MAX_FILE_SIZE:
        return _skipped(f"File too large for doc_analysis ({size} bytes > {_MAX_FILE_SIZE})")

    try:
        return _analyse(file_path)
    except Exception as exc:  # noqa: BLE001
        logger.error("doc_analysis failed on %s: %s", file_path.name, exc)
        return _error(f"Analysis error: {exc}")


def _is_office_file(file_path: Path, _config: dict) -> bool:
    """Determine if the file is an Office document by extension or MIME."""
    if file_path.suffix.lower() in _OFFICE_EXTENSIONS:
        return True
    try:
        import magic  # noqa: PLC0415
        mime = magic.from_file(str(file_path), mime=True)
        return mime in _OFFICE_MIMES
    except Exception:  # noqa: BLE001
        return False


def _detect_format(file_path: Path) -> str:
    """Classify a document by its magic bytes rather than extension.

    Returns one of: 'rtf', 'ole', 'openxml', 'unknown'.
    """
    try:
        with file_path.open("rb") as fh:
            head = fh.read(16)
    except OSError:
        return "unknown"
    if head[:5] == b"{\\rtf" or head[:4] == b"{\\rt":
        return "rtf"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "openxml"
    return "unknown"


def _analyse(file_path: Path) -> dict:
    """Route to the correct analyser based on detected format."""
    fmt = _detect_format(file_path)
    data: dict = {
        "format": fmt,
        "has_macros": False,
        "macro_count": 0,
        "suspicious_keywords": [],
        "auto_exec_keywords": [],
        "ioc_keywords": [],
        "macro_source_code": [],
        "mraptor_flags": {},
        "ole_indicators": [],
        "openxml_findings": {},
        "rtf_findings": {},
    }
    score_delta = 0
    reasons: list[str] = []

    # ── VBA macro analysis (OLE + OpenXML only — RTF would raise) ──
    if fmt in ("ole", "openxml") and _HAS_OLEVBA:
        vba_delta, vba_reasons = _run_vba_analysis(file_path, data)
        score_delta += vba_delta
        reasons.extend(vba_reasons)

    # ── OpenXML structural inspection (altChunk / embedded RTF / external refs) ──
    if fmt == "openxml":
        oxml_delta, oxml_reasons = _inspect_openxml(file_path, data)
        score_delta += oxml_delta
        reasons.extend(oxml_reasons)

    # ── RTF object inspection ──
    if fmt == "rtf" and _HAS_RTFOBJ:
        rtf_delta, rtf_reasons = _inspect_rtf(file_path, data)
        score_delta += rtf_delta
        reasons.extend(rtf_reasons)

    # ── oleid: high-level OLE indicator analysis (safe to run on any supported type) ──
    if _HAS_OLEID and fmt in ("ole", "openxml"):
        oleid_delta, oleid_reasons = _run_oleid(file_path, data)
        score_delta += oleid_delta
        reasons.extend(oleid_reasons)

    score_delta = min(score_delta, _DOC_SCORE_CAP)
    reason_text = "; ".join(reasons) if reasons else "No suspicious OLE/VBA content detected"

    return {
        "module": "doc_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


# ────────────────────────────── VBA path ──────────────────────────────

def _run_vba_analysis(file_path: Path, data: dict) -> tuple[int, list[str]]:
    score_delta = 0
    reasons: list[str] = []

    try:
        vba_parser = VBA_Parser(str(file_path))
    except Exception as exc:  # noqa: BLE001
        logger.info("olevba could not parse %s: %s", file_path.name, exc)
        return 0, []

    try:
        if not vba_parser.detect_vba_macros():
            return 0, []

        data["has_macros"] = True
        macros = []
        for _, _, vba_filename, vba_code in vba_parser.extract_macros():
            macros.append({
                "filename": vba_filename,
                "code_preview": vba_code[:500] if vba_code else "",
            })
        data["macro_count"] = len(macros)
        data["macro_source_code"] = macros
        score_delta += 10
        reasons.append(f"VBA macros found ({len(macros)} stream(s))")

        suspicious: list[dict] = []
        auto_exec: list[dict] = []
        iocs: list[dict] = []
        for kw_type, keyword, description in vba_parser.analyze_macros():
            entry = {"type": kw_type, "keyword": keyword, "description": description}
            if kw_type == "Suspicious":
                suspicious.append(entry)
            elif kw_type == "AutoExec":
                auto_exec.append(entry)
            elif kw_type == "IOC":
                iocs.append(entry)

        data["suspicious_keywords"] = suspicious
        data["auto_exec_keywords"] = auto_exec
        data["ioc_keywords"] = iocs

        if auto_exec:
            score_delta += 10
            triggers = list({kw["keyword"] for kw in auto_exec})[:5]
            reasons.append(f"Auto-execution triggers: {', '.join(triggers)}")
        if suspicious:
            score_delta += 10
            kws = list({kw["keyword"] for kw in suspicious})[:5]
            suffix = f" (+{len(suspicious) - 5} more)" if len(suspicious) > 5 else ""
            reasons.append(f"Suspicious VBA keywords: {', '.join(kws)}{suffix}")
        if iocs:
            score_delta += 5
            reasons.append(f"VBA IOC patterns found ({len(iocs)} indicator(s))")
    finally:
        vba_parser.close()

    # MacroRaptor risk classification.
    if _HAS_MRAPTOR and data["has_macros"]:
        try:
            vba2 = VBA_Parser(str(file_path))
            try:
                all_code = ""
                if vba2.detect_vba_macros():
                    for _, _, _, vba_code in vba2.extract_macros():
                        if vba_code:
                            all_code += vba_code + "\n"
                if all_code:
                    raptor = MacroRaptor(all_code)
                    raptor.scan()
                    data["mraptor_flags"] = {
                        "auto_exec": raptor.autoexec,
                        "write_file": raptor.write,
                        "execute_command": raptor.execute,
                        "suspicious": raptor.suspicious,
                    }
                    if raptor.suspicious:
                        score_delta += 15
                        flags = []
                        if raptor.autoexec:
                            flags.append("auto-execute")
                        if raptor.write:
                            flags.append("file-write")
                        if raptor.execute:
                            flags.append("command-execute")
                        reasons.append(f"MacroRaptor: suspicious ({', '.join(flags)})")
            finally:
                vba2.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("mraptor analysis failed: %s", exc)

    return score_delta, reasons


# ──────────────────────────── OpenXML path ────────────────────────────

def _inspect_openxml(file_path: Path, data: dict) -> tuple[int, list[str]]:
    """Scan a docx/xlsx/pptx zip for altChunk, embedded RTFs, external templates."""
    score_delta = 0
    reasons: list[str] = []
    findings: dict = {
        "alt_chunks": [],
        "external_relationships": [],
        "embedded_files": [],
        "dangerous_embedded": [],
        "ole_objects": [],
    }

    try:
        with zipfile.ZipFile(str(file_path)) as zf:
            infos = zf.infolist()
            # Decompression bomb guard.
            total_uncompressed = 0
            for info in infos:
                total_uncompressed += info.file_size
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > _MAX_ZIP_RATIO and info.file_size > 1024 * 1024:
                        logger.warning(
                            "doc_analysis: suspicious compression ratio %.1f for %s — skipping content inspection",
                            ratio, info.filename)
                        findings["decompression_bomb"] = True
                        data["openxml_findings"] = findings
                        return score_delta, ["Suspicious decompression ratio inside container"]
            if total_uncompressed > _MAX_ZIP_UNCOMPRESSED:
                logger.warning("doc_analysis: cumulative zip size %d over cap", total_uncompressed)
                findings["decompression_bomb"] = True
                data["openxml_findings"] = findings
                return score_delta, ["OpenXML container exceeds safe size cap"]

            # Enumerate embedded files (anything that isn't the usual OpenXML skeleton).
            for info in infos:
                name_lower = info.filename.lower()
                ext = Path(name_lower).suffix
                if ext in _DANGEROUS_EMBEDDED_EXTS:
                    findings["embedded_files"].append(info.filename)
                    weight = _DANGEROUS_EMBEDDED_EXTS[ext]
                    findings["dangerous_embedded"].append({"name": info.filename, "ext": ext, "weight": weight})
                    score_delta += weight
                    reasons.append(f"Embedded {ext} inside container: {Path(info.filename).name}")
                if "embeddings/" in name_lower or name_lower.endswith(".bin"):
                    findings["ole_objects"].append(info.filename)

            if findings["ole_objects"]:
                score_delta += 10
                reasons.append(f"OLE object streams embedded ({len(findings['ole_objects'])})")

            # Parse relationship files for altChunk / external targets / attachedTemplate.
            for info in infos:
                if not info.filename.endswith(".rels"):
                    continue
                if info.file_size > 512 * 1024:
                    # A rels file this large is already abnormal — skip.
                    continue
                try:
                    content = zf.read(info.filename).decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    continue

                for m in re.finditer(r"<Relationship[^>]+>", content):
                    rel = m.group()
                    rel_lower = rel.lower()
                    # altChunk / aFChunk — a classic template injection vector.
                    if "/afchunk" in rel_lower or "/altchunk" in rel_lower:
                        target = _extract_attr(rel, "Target")
                        findings["alt_chunks"].append(target)
                        score_delta += 30
                        reasons.append(f"altChunk relationship (template injection vector): {target}")
                        # Absolute paths or missing targets strongly imply exploit abuse
                        # rather than a legitimate document-assembly use of altChunk.
                        if target.startswith("/") or target.startswith("\\"):
                            score_delta += 5
                            reasons.append("altChunk target uses absolute path (exploit marker)")
                    # External TargetMode — remote template / content.
                    if 'targetmode="external"' in rel_lower:
                        target = _extract_attr(rel, "Target")
                        findings["external_relationships"].append(target)
                        rtype = _extract_attr(rel, "Type")
                        if "attachedtemplate" in (rtype or "").lower() or "frame" in (rtype or "").lower() or "subdocument" in (rtype or "").lower():
                            score_delta += 20
                            reasons.append(f"External attachedTemplate/subDocument: {target}")
                        else:
                            score_delta += 10
                            reasons.append(f"External resource reference: {target}")
                    # oleObject relationships.
                    if "/oleobject" in rel_lower:
                        target = _extract_attr(rel, "Target")
                        findings["ole_objects"].append(target or "<inline>")
    except zipfile.BadZipFile:
        reasons.append("Container claims OpenXML but ZIP is malformed")
        score_delta += 10
    except Exception as exc:  # noqa: BLE001
        logger.debug("OpenXML inspection failed: %s", exc)

    data["openxml_findings"] = findings
    return score_delta, reasons


def _extract_attr(xml_tag: str, name: str) -> str:
    m = re.search(rf'{name}="([^"]*)"', xml_tag)
    return m.group(1) if m else ""


# ───────────────────────────── RTF path ─────────────────────────────

def _inspect_rtf(file_path: Path, data: dict) -> tuple[int, list[str]]:
    score_delta = 0
    reasons: list[str] = []
    findings: dict = {
        "object_count": 0,
        "ole_object_count": 0,
        "package_count": 0,
        "class_names": [],
        "high_risk_classes": [],
    }

    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        logger.debug("Could not read RTF: %s", exc)
        return 0, []

    try:
        parser = RtfObjParser(raw)
        parser.parse()
    except Exception as exc:  # noqa: BLE001
        logger.info("rtfobj parse failed: %s", exc)
        data["rtf_findings"] = findings
        # A parse failure on a file with rtf magic is itself slightly suspicious.
        return 5, ["RTF failed to parse cleanly (possible exploit attempt)"]

    findings["object_count"] = len(parser.objects)
    for obj in parser.objects:
        class_name_raw = getattr(obj, "class_name", None)
        if class_name_raw:
            try:
                class_name = class_name_raw.decode("latin-1", errors="replace").strip("\x00").strip()
            except Exception:  # noqa: BLE001
                class_name = repr(class_name_raw)
        else:
            class_name = ""
        if class_name:
            findings["class_names"].append(class_name)
            lowered = class_name.lower()
            for needle, weight in _HIGH_RISK_CLASSES.items():
                if needle in lowered:
                    findings["high_risk_classes"].append(class_name)
                    score_delta += weight
                    reasons.append(f"RTF embeds high-risk OLE class: {class_name} (+{weight})")
                    break
        if getattr(obj, "is_ole", False):
            findings["ole_object_count"] += 1
        if getattr(obj, "is_package", False):
            findings["package_count"] += 1

    if findings["ole_object_count"]:
        per_obj = min(findings["ole_object_count"] * 5, 20)
        score_delta += per_obj
        reasons.append(
            f"RTF contains {findings['ole_object_count']} embedded OLE object(s)")

    if findings["package_count"]:
        score_delta += 15
        reasons.append(
            f"RTF contains {findings['package_count']} packaged file drop(s)")

    # Heuristic keyword scan over raw bytes — catches control-word obfuscation that
    # trips up object parsers. Use tight markers to keep false positives down.
    lowered = raw[: 2 * 1024 * 1024].lower()  # first 2 MiB is enough for headers
    if b"\\objupdate" in lowered and b"\\objdata" in lowered:
        # objupdate forces the OLE object to load on open — a classic abuse pattern.
        score_delta += 10
        reasons.append("RTF uses \\objupdate to force object load on open")
    if b"equation.3" in lowered or b"equation.2" in lowered:
        if "CVE-2017-11882 Equation Editor abuse" not in reasons:
            score_delta += 20
            reasons.append("CVE-2017-11882 Equation Editor abuse indicator")

    data["rtf_findings"] = findings
    return score_delta, reasons


# ───────────────────────────── oleid path ─────────────────────────────

def _run_oleid(file_path: Path, data: dict) -> tuple[int, list[str]]:
    score_delta = 0
    reasons: list[str] = []
    try:
        oid = OleID(str(file_path))
        indicators = oid.check()
        results = []
        for indicator in indicators:
            results.append({
                "id": indicator.id,
                "name": indicator.name,
                "value": str(indicator.value),
                "risk": indicator.risk,
            })
            if indicator.risk == "HIGH":
                score_delta += 5
                reasons.append(f"OLE indicator: {indicator.name} = {indicator.value}")
        data["ole_indicators"] = results
    except Exception as exc:  # noqa: BLE001
        logger.debug("oleid analysis failed: %s", exc)
    return score_delta, reasons


# ───────────────────────────── helpers ─────────────────────────────

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
