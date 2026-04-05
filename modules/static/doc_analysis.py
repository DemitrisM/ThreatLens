"""Office document analysis module.

Uses oletools (olevba, mraptor, oleid) to extract and analyse VBA macros,
detect auto-execution triggers, shell calls, and suspicious OLE structures
in .doc, .docx, .xls, .xlsx, .ppt, .pptx, and .rtf files.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
    _HAS_OLEVBA = True
except ImportError:
    _HAS_OLEVBA = False
    logger.warning("oletools not available — Office document analysis disabled")

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


def run(file_path: Path, config: dict) -> dict:
    """Analyse an Office document for VBA macros and suspicious OLE structures.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict.

    Returns:
        Standard module result dict.
    """
    if not _HAS_OLEVBA:
        return _skipped("oletools library not installed")

    # Check whether the file is actually an Office document.
    if not _is_office_file(file_path, config):
        return _skipped("Not applicable — not an Office document")

    try:
        return _analyse(file_path)
    except Exception as exc:  # noqa: BLE001
        logger.error("doc_analysis failed: %s", exc)
        return _error(f"Analysis error: {exc}")


def _is_office_file(file_path: Path, config: dict) -> bool:
    """Determine if the file is an Office document by extension or MIME."""
    if file_path.suffix.lower() in _OFFICE_EXTENSIONS:
        return True
    # Fall back to MIME detection from file_intake (not available here,
    # so we also try python-magic if cheap).
    try:
        import magic  # noqa: PLC0415
        mime = magic.from_file(str(file_path), mime=True)
        return mime in _OFFICE_MIMES
    except Exception:  # noqa: BLE001
        return False


def _analyse(file_path: Path) -> dict:
    """Run olevba + mraptor + oleid and aggregate findings."""
    score_delta = 0
    reasons: list[str] = []
    data: dict = {
        "has_macros": False,
        "macro_count": 0,
        "suspicious_keywords": [],
        "auto_exec_keywords": [],
        "ioc_keywords": [],
        "macro_source_code": [],
        "mraptor_flags": {},
        "ole_indicators": [],
    }

    # ── olevba: VBA macro extraction and keyword analysis ──
    try:
        vba_parser = VBA_Parser(str(file_path))
    except Exception as exc:  # noqa: BLE001
        logger.info("olevba could not parse %s: %s", file_path.name, exc)
        return {
            "module": "doc_analysis",
            "status": "success",
            "data": data,
            "score_delta": 0,
            "reason": "No OLE/VBA content detected",
        }

    try:
        if vba_parser.detect_vba_macros():
            data["has_macros"] = True
            macros = []

            for _, _, vba_filename, vba_code in vba_parser.extract_macros():
                macros.append({
                    "filename": vba_filename,
                    "code_preview": vba_code[:500] if vba_code else "",
                })

            data["macro_count"] = len(macros)
            data["macro_source_code"] = macros

            # Presence of macros is suspicious.
            score_delta += 10
            reasons.append(f"VBA macros found ({len(macros)} macro stream(s))")

            # Keyword analysis — detect suspicious patterns.
            suspicious = []
            auto_exec = []
            iocs = []

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

    # ── mraptor: macro risk classification ──
    if _HAS_MRAPTOR and data["has_macros"]:
        try:
            # Re-parse for mraptor (it needs its own parse).
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
                        reasons.append(f"MacroRaptor: suspicious macro ({', '.join(flags)})")
            finally:
                vba2.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("mraptor analysis failed: %s", exc)

    # ── oleid: OLE indicator analysis ──
    if _HAS_OLEID:
        try:
            oid = OleID(str(file_path))
            indicators = oid.check()
            ole_results = []
            for indicator in indicators:
                ole_results.append({
                    "id": indicator.id,
                    "name": indicator.name,
                    "value": str(indicator.value),
                    "risk": indicator.risk,
                })
                # High-risk OLE indicators add score.
                if indicator.risk == "HIGH":
                    score_delta += 5
                    reasons.append(f"OLE indicator: {indicator.name} = {indicator.value}")

            data["ole_indicators"] = ole_results
        except Exception as exc:  # noqa: BLE001
            logger.debug("oleid analysis failed: %s", exc)

    # Cap doc_analysis contribution at 50.
    score_delta = min(score_delta, 50)

    reason_text = "; ".join(reasons) if reasons else "No suspicious OLE/VBA content detected"

    return {
        "module": "doc_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


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
