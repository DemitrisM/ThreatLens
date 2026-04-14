"""VBA macro extraction, keyword analysis, MacroRaptor risk flags, and
stomping detection via pcodedmp.

VBA stomping (popularised by EvilClippy) leaves the original VBA source
text empty or decoy-filled while the real malicious logic lives in the
compiled p-code. olevba reads the source stream only, so we additionally
run pcodedmp — which dumps the p-code — and diff the two. A module that
has p-code opcodes but no corresponding source is stomped.
"""

import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from oletools.olevba import VBA_Parser
    _HAS_OLEVBA = True
except ImportError:
    _HAS_OLEVBA = False

try:
    from oletools.mraptor import MacroRaptor
    _HAS_MRAPTOR = True
except ImportError:
    _HAS_MRAPTOR = False

_PCODEDMP_TIMEOUT_SECONDS = 15

# Heuristic for "heavy obfuscation" — lots of Chr() / Asc() arithmetic or
# hex-encoded string concatenations rather than normal VBA.
_CHR_CALL_RE = re.compile(r"\bChr[\$BW]?\s*\(", re.IGNORECASE)
_HEX_STRING_RE = re.compile(r"&H[0-9A-F]{2,}", re.IGNORECASE)


def analyse_vba(file_path: Path) -> dict:
    """Extract macros and compute indicator flags.

    Returns a dict with the vba data payload plus ``indicator_flags`` — a
    set of keys consumed by the scoring engine. Never raises.
    """
    result: dict = {
        "present": False,
        "count": 0,
        "streams": [],
        "auto_exec_keywords": [],
        "suspicious_keywords": [],
        "ioc_keywords": [],
        "mraptor_flags": {},
        "stomping_detected": False,
        "stomping_check_performed": False,
        "modulestreamname_mismatch": False,
        "heavy_obfuscation": False,
        "indicator_flags": set(),
    }

    if not _HAS_OLEVBA:
        return result

    try:
        parser = VBA_Parser(str(file_path))
    except Exception as exc:  # noqa: BLE001
        logger.info("olevba could not parse %s: %s", file_path.name, exc)
        return result

    try:
        if not parser.detect_vba_macros():
            return result

        result["present"] = True
        result["indicator_flags"].add("vba_present")

        streams: list[dict] = []
        all_source = ""
        for _, _, vba_filename, vba_code in parser.extract_macros():
            streams.append({
                "filename": vba_filename,
                "code_preview": vba_code[:500] if vba_code else "",
            })
            if vba_code:
                all_source += vba_code + "\n"
        result["count"] = len(streams)
        result["streams"] = streams

        suspicious: list[dict] = []
        auto_exec: list[dict] = []
        iocs: list[dict] = []
        for kw_type, keyword, description in parser.analyze_macros():
            entry = {"type": kw_type, "keyword": keyword, "description": description}
            if kw_type == "Suspicious":
                suspicious.append(entry)
            elif kw_type == "AutoExec":
                auto_exec.append(entry)
            elif kw_type == "IOC":
                iocs.append(entry)
        result["auto_exec_keywords"] = auto_exec
        result["suspicious_keywords"] = suspicious
        result["ioc_keywords"] = iocs

        if auto_exec:
            result["indicator_flags"].add("auto_exec")
        # Map specific suspicious keyword families to combo-engine flags.
        kw_names = {kw["keyword"].lower() for kw in suspicious}
        if kw_names & {"shell", "wscript.shell", "createobject", "run"}:
            result["indicator_flags"].add("shell_keyword")
        if kw_names & {"urldownloadtofile", "xmlhttp", "msxml2.xmlhttp",
                       "winhttprequest", "xmlhttprequest", "microsoft.xmlhttp"}:
            result["indicator_flags"].add("url_downloader_keyword")

        # Heavy-obfuscation heuristic: count Chr() calls and hex literals.
        chr_hits = len(_CHR_CALL_RE.findall(all_source))
        hex_hits = len(_HEX_STRING_RE.findall(all_source))
        if chr_hits >= 25 or hex_hits >= 40:
            result["heavy_obfuscation"] = True
            result["indicator_flags"].add("heavy_vba_obfuscation")

        # MacroRaptor risk flags (re-parse because mraptor consumes source directly).
        if _HAS_MRAPTOR and all_source:
            try:
                raptor = MacroRaptor(all_source)
                raptor.scan()
                result["mraptor_flags"] = {
                    "auto_exec": raptor.autoexec,
                    "write_file": raptor.write,
                    "execute_command": raptor.execute,
                    "suspicious": raptor.suspicious,
                }
                if raptor.execute:
                    result["indicator_flags"].add("shell_keyword")
                if raptor.autoexec:
                    result["indicator_flags"].add("auto_exec")
            except Exception as exc:  # noqa: BLE001
                logger.debug("mraptor failed: %s", exc)
    finally:
        parser.close()

    # VBA stomping — requires a file on disk, which we already have.
    stomp = _detect_stomping(file_path, result["streams"])
    result["stomping_check_performed"] = stomp["performed"]
    result["stomping_detected"] = stomp["detected"]
    result["modulestreamname_mismatch"] = stomp["modulestreamname_mismatch"]
    if stomp["detected"]:
        result["indicator_flags"].add("vba_stomping")

    return result


def _detect_stomping(file_path: Path, source_streams: list[dict]) -> dict:
    """Run pcodedmp and diff p-code against olevba-extracted source.

    Returns ``{"performed": bool, "detected": bool,
               "modulestreamname_mismatch": bool}``.
    """
    out = {"performed": False, "detected": False, "modulestreamname_mismatch": False}
    try:
        proc = subprocess.run(
            ["pcodedmp", "-d", str(file_path)],
            capture_output=True,
            text=True,
            timeout=_PCODEDMP_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        logger.info("pcodedmp not on PATH — stomping check skipped")
        return out
    except subprocess.TimeoutExpired:
        logger.warning("pcodedmp timed out on %s", file_path.name)
        return out
    except Exception as exc:  # noqa: BLE001
        logger.info("pcodedmp invocation failed: %s", exc)
        return out

    out["performed"] = True
    pcode_text = (proc.stdout or "") + (proc.stderr or "")

    # EvilClippy signature: ASCII/Unicode MODULESTREAMNAME mismatch recorded
    # by pcodedmp when the dir stream's two MODULESTREAMNAME records disagree.
    if "MODULESTREAMNAME" in pcode_text and (
        "MODULESTREAMNAMEUNICODE" in pcode_text or "mismatch" in pcode_text.lower()
    ):
        # pcodedmp reports the names; cross-check by extracting the two variants.
        ascii_names = re.findall(r"MODULESTREAMNAME:\s*'([^']+)'", pcode_text)
        unicode_names = re.findall(
            r"MODULESTREAMNAMEUNICODE:\s*'([^']+)'", pcode_text
        )
        for a, u in zip(ascii_names, unicode_names):
            if a and u and a != u:
                out["modulestreamname_mismatch"] = True
                out["detected"] = True
                break

    # Classic stomping: p-code dump contains opcode lines (the ones with
    # "Line #" markers + real instructions) but the corresponding source
    # stream extracted by olevba is empty or trivial.
    has_pcode_opcodes = bool(
        re.search(r"Line #\d+:\s*\w", pcode_text)
        or "FuncDefn" in pcode_text
        or "LitStr" in pcode_text
    )
    if has_pcode_opcodes:
        total_source_len = sum(
            len((s.get("code_preview") or "").strip()) for s in source_streams
        )
        # If we clearly have p-code but essentially no source, it's stomped.
        if total_source_len < 50 and source_streams:
            out["detected"] = True

    return out
