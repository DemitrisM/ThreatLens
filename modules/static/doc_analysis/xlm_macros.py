"""Excel 4.0 (XLM) macro deobfuscation via XLMMacroDeobfuscator.

XLM is the pre-VBA macro language used in older Excel files and still
weaponised by loaders that want to sidestep VBA-focused detection.
XLMMacroDeobfuscator walks the formula graph and emits the
deobfuscated cell sequence; we then scan for the high-risk calls
``EXEC``, ``CALL``, ``FORMULA.FILL``, and HTTP URLs.

The library is in low-maintenance mode and has been observed to hang
on adversarial samples, so every invocation has a hard outer timeout.

Design notes
------------
Two timeouts, deliberately. The library takes a ``timeout`` kwarg, but it
is cooperative — it is checked between formula evaluations, so a single
pathological chain runs past it. SIGALRM is therefore layered underneath
as a hard stop that interrupts wherever execution happens to be.

That layering carries one contract worth knowing: ``signal.signal`` only
works on the main thread of a process. The pipeline is single-threaded
today so it holds. If module execution is ever parallelised (Phase 4),
a *process* pool keeps this working — each worker runs its task on its
own main thread — while a *thread* pool does not: the ValueError would
be swallowed by the caller's except clause and XLM analysis would quietly
stop running everywhere. Recorded here because the failure is silent.

The import is guarded with a bare ``except Exception`` rather than
``ImportError``, unlike its siblings in this package. XLMMacroDeobfuscator
does real work at import — including probing for pywin32 — and has been
seen to raise things other than ImportError on a partial install.
"""

import logging
import re
from pathlib import Path

from ._quiet import quiet_stdout

logger = logging.getLogger(__name__)

# This module prints a pywin32 notice to stdout at import time.
try:
    with quiet_stdout(logger, "XLMMacroDeobfuscator.deobfuscator"):
        from XLMMacroDeobfuscator.deobfuscator import process_file as _xlm_process_file
    _HAS_XLM = True
except Exception:  # noqa: BLE001
    _HAS_XLM = False

# Thirty seconds is the whole budget for this pass, and it is the largest
# single timeout in a document scan. XLM deobfuscation is an interpreter
# walking a formula graph; on a real sample it finishes in under a second,
# and anything approaching this bound is a graph built to be walked
# forever.
_XLM_TIMEOUT_SECONDS = 30
_EXEC_CALL_RE = re.compile(r"\b(EXEC|CALL|FORMULA(?:\.FILL)?)\s*\(", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)


def analyse_xlm(file_path: Path) -> dict:
    """Deobfuscate XLM macros and flag EXEC/CALL/URL usage.

    Args:
        file_path: An Excel document, already screened by is_xlm_candidate.


    Returns a dict with:
      - ``performed``  — True iff the library was available and ran
      - ``present``    — True iff any cells were extracted
      - ``cell_count``
      - ``deobfuscated_cells`` — list of cell strings (truncated)
      - ``exec_call_found`` — EXEC/CALL/FORMULA.FILL observed
      - ``urls`` — URLs extracted from the cell stream
      - ``indicator_flags`` — set of scoring flags

    Never raises. Note the difference between ``performed`` and
    ``present``: a timeout sets performed True and present False, because
    the library did run and simply did not finish — whereas an absent
    library leaves both False. The report needs to tell "no XLM macros"
    from "we could not look".
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

    # A timeout is reported as performed, since the deobfuscator ran and
    # was cut off; any other failure is not, since it never got going.
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

    # Matched against all cells joined rather than cell by cell: XLM's
    # whole obfuscation model is splitting one call across a chain of
    # cells, and the deobfuscated sequence is the reconstruction of that
    # chain. Per-cell matching would miss exactly what was deobfuscated.
    joined = "\n".join(cells)
    if _EXEC_CALL_RE.search(joined):
        out["exec_call_found"] = True
        out["indicator_flags"].add("xlm_exec_call")
    # dict.fromkeys preserves first-seen order while deduplicating — the
    # same download URL typically appears in several reconstructed cells,
    # and the order it was built in is the order worth showing.
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

    Args:
        file_path: The Excel document.
        timeout:   Seconds, passed to the library *and* armed as an alarm.

    Returns:
        One string per deobfuscated cell. An unexpected return type from
        the library yields an empty list rather than a crash — its API has
        changed shape across versions.

    Raises:
        TimeoutError: When the alarm fires before the library returns.
        Anything the library itself raises, which the caller handles.
    """
    # Imported here rather than at module scope: signal is only needed on
    # this path, and the local import keeps the platform check adjacent to
    # the use.
    import signal
    use_alarm = hasattr(signal, "SIGALRM")

    def _handler(_signum, _frame):
        raise TimeoutError(f"XLMMacroDeobfuscator exceeded {timeout}s")

    # The previous handler is saved and restored rather than left
    # replaced. This runs inside a long-lived CLI process, and leaving a
    # SIGALRM handler installed would have any later alarm — anywhere in
    # the process — raise a TimeoutError attributed to XLM parsing.
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
    # Disarm before restoring, and do both on every path: an alarm left
    # armed after a fast return would fire during whichever module runs
    # next.
    finally:
        if use_alarm:
            signal.alarm(0)
            if prev is not None:
                signal.signal(signal.SIGALRM, prev)

    # process_file returns a list of strings (one per deobfuscated cell).
    if isinstance(result, list):
        return [str(x) for x in result if x]
    return []
