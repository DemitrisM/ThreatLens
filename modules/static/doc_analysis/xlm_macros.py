"""Excel 4.0 (XLM) macro deobfuscation via XLMMacroDeobfuscator.

XLM is the pre-VBA macro language used in older Excel files and still
weaponised by loaders that want to sidestep VBA-focused detection.
XLMMacroDeobfuscator walks the formula graph and emits the
deobfuscated cell sequence; we then scan for the high-risk calls
``EXEC``, ``CALL``, ``FORMULA.FILL``, and HTTP URLs.

The library is in low-maintenance mode and has been observed to hang
on adversarial samples, so every invocation has a hard outer timeout.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from XLMMacroDeobfuscator.deobfuscator import process_file as _xlm_process_file
    _HAS_XLM = True
except Exception:  # noqa: BLE001
    _HAS_XLM = False

_XLM_TIMEOUT_SECONDS = 30
_EXEC_CALL_RE = re.compile(r"\b(EXEC|CALL|FORMULA(?:\.FILL)?)\s*\(", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)


def analyse_xlm(file_path: Path) -> dict:
    """Deobfuscate XLM macros and flag EXEC/CALL/URL usage.

    Returns a dict with:
      - ``performed``  — True iff the library was available and ran
      - ``present``    — True iff any cells were extracted
      - ``cell_count``
      - ``deobfuscated_cells`` — list of cell strings (truncated)
      - ``exec_call_found`` — EXEC/CALL/FORMULA.FILL observed
      - ``urls`` — URLs extracted from the cell stream
      - ``indicator_flags`` — set of scoring flags
    """
    out: dict = {
        "performed": False,
        "present": False,
        "cell_count": 0,
        "deobfuscated_cells": [],
        "exec_call_found": False,
        "urls": [],
        "indicator_flags": set(),
    }

    if not _HAS_XLM:
        return out

    try:
        cells = _run_with_timeout(file_path, _XLM_TIMEOUT_SECONDS)
    except TimeoutError:
        logger.warning("XLMMacroDeobfuscator timed out on %s", file_path.name)
        out["performed"] = True
        return out
    except Exception as exc:  # noqa: BLE001
        logger.info("XLM deobfuscation failed on %s: %s", file_path.name, exc)
        return out

    out["performed"] = True
    if not cells:
        return out

    out["present"] = True
    out["cell_count"] = len(cells)
    out["deobfuscated_cells"] = [c[:300] for c in cells[:50]]

    joined = "\n".join(cells)
    if _EXEC_CALL_RE.search(joined):
        out["exec_call_found"] = True
        out["indicator_flags"].add("xlm_exec_call")
    urls = _URL_RE.findall(joined)
    if urls:
        out["urls"] = list(dict.fromkeys(urls))[:20]
        out["indicator_flags"].add("xlm_url")

    return out


def _run_with_timeout(file_path: Path, timeout: int) -> list[str]:
    """Invoke XLMMacroDeobfuscator in noninteractive mode with a hard wall-clock limit.

    The library's own ``timeout`` kwarg is cooperative and has been seen to
    overshoot on samples with pathological formula chains. We additionally
    enforce SIGALRM as a second line of defence where the platform supports it.
    """
    import signal
    use_alarm = hasattr(signal, "SIGALRM")

    def _handler(_signum, _frame):
        raise TimeoutError(f"XLMMacroDeobfuscator exceeded {timeout}s")

    prev = None
    if use_alarm:
        prev = signal.signal(signal.SIGALRM, _handler)
        signal.alarm(timeout)
    try:
        result = _xlm_process_file(
            file=str(file_path),
            noninteractive=True,
            return_deobfuscated=True,
            timeout=timeout,
            silent_mode=True,
        )
    finally:
        if use_alarm:
            signal.alarm(0)
            if prev is not None:
                signal.signal(signal.SIGALRM, prev)

    # process_file returns a list of strings (one per deobfuscated cell).
    if isinstance(result, list):
        return [str(x) for x in result if x]
    return []
