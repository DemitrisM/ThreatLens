"""VBA macro extraction, keyword analysis, MacroRaptor risk flags, and
stomping detection via pcodedmp.

VBA stomping (popularised by EvilClippy) leaves the original VBA source
text empty or decoy-filled while the real malicious logic lives in the
compiled p-code. olevba reads the source stream only, so we additionally
run pcodedmp — which dumps the p-code — and diff the two. A module that
has p-code opcodes but no corresponding source is stomped.

Design notes
------------
Three independent sources feed the flag set, and the overlap between them
is intentional. olevba's keyword analysis names what the source *says*;
MacroRaptor judges what it *does*, on its own much narrower rules; and
pcodedmp reports what the compiled p-code contains, which is the only one
of the three that survives stomping. Both olevba and MacroRaptor can set
``auto_exec`` and ``shell_keyword``, and that is fine — flags are a set,
so agreement costs nothing and either one alone is enough.

The stomping check runs outside the olevba try/finally, after the parser
is closed, because it is a subprocess against the file on disk and must
not hold the parser open across a 15-second wait. It also runs whether or
not olevba found anything worth reporting — a stomped document is one
whose source stream looks empty, which is precisely the case where the
earlier passes have least to say.

pcodedmp is invoked as a *binary on PATH*, not imported, even though it
is a Python package: its module-level API prints to stdout and is not
reentrant, and a subprocess is the only place a hard timeout can be
enforced. Its absence is a skip, not an error — the rest of the pass is
unaffected.

Both obfuscation thresholds are counted over the concatenated source of
every module rather than per module, because a stealer routinely splits
one obfuscated blob across several small modules to stay under exactly
this kind of per-module threshold.
"""

import logging
import re
import subprocess
from pathlib import Path

from ._quiet import quiet_stdout

logger = logging.getLogger(__name__)

# olevba pulls in XLMMacroDeobfuscator, which prints to stdout on import.
try:
    with quiet_stdout(logger, "oletools.olevba"):
        from oletools.olevba import VBA_Parser
    _HAS_OLEVBA = True
except ImportError:
    _HAS_OLEVBA = False

try:
    with quiet_stdout(logger, "oletools.mraptor"):
        from oletools.mraptor import MacroRaptor
    _HAS_MRAPTOR = True
except ImportError:
    _HAS_MRAPTOR = False

# pcodedmp walks compiled p-code and is fast on real documents; a sample
# that takes longer than this is pathological, and the pass is optional
# enough that waiting is worse than losing it (design rule 5).
_PCODEDMP_TIMEOUT_SECONDS = 15

# Heuristic for "heavy obfuscation" — lots of Chr() / Asc() arithmetic or
# hex-encoded string concatenations rather than normal VBA.
#
# Both patterns accept the type-suffixed spellings (Chr$, ChrB, ChrW),
# which obfuscators alternate between precisely because naive detection
# looks for the bare name. The thresholds below are counts, not ratios:
# a long legitimate macro may use Chr() a dozen times for line endings,
# but twenty-five of them is a character-by-character string builder.
_CHR_CALL_RE = re.compile(r"\bChr[\$BW]?\s*\(", re.IGNORECASE)
_HEX_STRING_RE = re.compile(r"&H[0-9A-F]{2,}", re.IGNORECASE)


def analyse_vba(file_path: Path) -> dict:
    """Extract macros and compute indicator flags.

    Returns a dict with the vba data payload plus ``indicator_flags`` — a
    set of keys consumed by the scoring engine. Never raises.

    Args:
        file_path: Document to parse. Must exist on disk, since the
                   stomping check shells out to pcodedmp against the path.

    Returns:
        The payload dict. Every field is pre-populated, so a caller can
        read any key whether or not olevba was installed, parsed, or found
        macros — "no macros" and "olevba absent" differ in the flags, not
        in the shape.
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

    # A missing olevba is a silent degradation, not a flag: absence of the
    # library says nothing about the document, and emitting a flag would
    # let an install problem move a score.
    if not _HAS_OLEVBA:
        return result

    # Construction is where olevba rejects a malformed container, so it is
    # wrapped separately from the analysis below — and the failure is
    # logged at info rather than flagged, because RTF-in-a-.doc reaches
    # here routinely and is already reported by the format router.
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

        # Two accumulations from one walk: the per-stream preview shown in
        # the report, and the concatenated source that MacroRaptor and the
        # obfuscation heuristics need whole.
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
        # Only these two families are mapped, because only they appear in
        # the combination rules; the rest of olevba's keyword output is
        # carried for the reader rather than scored. Matching is on
        # lowercased keyword names, since olevba's casing follows the
        # source text.
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

        # MacroRaptor is a second opinion on the same source, with rules
        # tuned for precision rather than coverage — it deliberately flags
        # far less than olevba's keyword list. Its verdicts feed the same
        # two flags, so either tool alone is enough to fire a combination.
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

    # Outside the try/finally above: the parser is closed first so the
    # subprocess below cannot hold a handle open across its timeout.
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

    Args:
        file_path:      Document on disk, passed to pcodedmp as a path.
        source_streams: The stream dicts olevba produced, read for their
                        ``code_preview`` length only.

    Returns:
        The three-key verdict. ``performed`` False means pcodedmp was
        absent, timed out, or failed to launch — the report distinguishes
        that from a check that ran and found nothing, because "not stomped"
        and "not checked" are very different statements about a sample.

    Two independent signatures are tested. The MODULESTREAMNAME mismatch is
    EvilClippy's fingerprint specifically; the source-versus-p-code volume
    comparison catches stomping however it was produced. Either sets the
    verdict.
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

    # Reaching here means pcodedmp ran, whatever its exit code — it
    # returns non-zero for documents it partially understood, and the
    # partial dump is still worth diffing.
    out["performed"] = True

    # stderr is concatenated because pcodedmp splits its output across both
    # streams depending on version and on which record it is describing.
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
        # Paired by position: pcodedmp emits the two records in module
        # order, so index i of each list describes the same module. The
        # first disagreement is enough — one stomped module stomps the
        # document.
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
    # The volume comparison, and the reason the constant is so low: a
    # module with real p-code but under fifty characters of recoverable
    # source is not a small macro, it is an emptied one. Using
    # code_preview (capped at 500 chars upstream) is safe precisely
    # because the threshold sits so far below that cap.
    if has_pcode_opcodes:
        total_source_len = sum(
            len((s.get("code_preview") or "").strip()) for s in source_streams
        )
        # If we clearly have p-code but essentially no source, it's stomped.
        if total_source_len < 50 and source_streams:
            out["detected"] = True

    return out
