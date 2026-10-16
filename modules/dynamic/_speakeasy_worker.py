"""Speakeasy emulation worker — runs in its own process, by design.

Invoked as::

    python -m modules.dynamic._speakeasy_worker \\
            --timeout 60 --max-api-count 20000 -- <sample_path>

Writes exactly one JSON document to stdout and exits 0. Everything else —
diagnostics, library chatter, output from the emulated sample itself — goes
to stderr.

Design notes
------------
**Why this is a separate process at all.** Speakeasy pins
``unicorn==1.0.2``, which is below 2.0.0rc5 and carries a published sandbox
escape; the pin is a hard equality so the patched version cannot be
installed alongside it. This module parses and emulates attacker-controlled
instructions and is the most likely exploitable component in the tool, so it
runs where an escape costs a short-lived worker rather than the analyser.
The process boundary also gives the parent a hard timeout (``run_contained``
kills the group) and makes D-6's whitelist structural — the parent can only
receive what is serialised here.

**stdout is protected structurally, not by discipline.** ``speakeasy``,
``pefile``, ``unicorn`` and Speakeasy's emulated CRT can all write to file
descriptor 1, and an emulated sample calling ``printf`` is normal behaviour
rather than an edge case. One stray line would corrupt the JSON and turn a
successful emulation into a parse failure upstream. So fd 1 is duplicated
and then redirected to stderr before Speakeasy is imported; the result is
written to the saved descriptor.

**This process always exits 0 when it produced a document.** Re-raising
after writing would exit non-zero, and the parent maps a non-zero exit to
``failed`` regardless of what reached stdout — discarding the very trace the
harvest exists to preserve.

**The budgets are Speakeasy's own, and they are PER ENTRY POINT — this is
a known limitation, not a solved problem.** ``run_module(all_entrypoints=
True)`` queues every entry point and runs them inside one blocking call,
reading its limits from the config given at construction. There is no
parameter, hook or callback here that can halt it part-way, so the
cumulative checks below run only *after* it returns: they label the result
honestly but cannot stop the work.

The consequence, stated plainly: a binary with many entry points can spend
up to ``entry_points x timeout`` seconds, and the parent's hard kill may
fire on a sample that never tripped Speakeasy's own bound — losing the
trace. Measured against the corpus this is currently theoretical: all six
sampled binaries finished in under 2 seconds against a 15-20s budget, and
the widest (``Aotera.exe``, 13 entry points) took 1.9s in total. Closing it
properly needs a Speakeasy-side hook; until then the outer kill is the only
real bound and a timed-out emulation is reported as the failure it is.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time

# ----------------------------------------------------------------------
# Caps on what crosses the pipe.
#
# Capping only the API list does not bound the document: Speakeasy appends
# to file_access and registry_access on every emulated file or registry
# call, including up to a kilobyte of hex data per write, so a 20,000
# iteration RegEnumKeyEx loop produces megabytes with the API list well
# inside its own cap. Every list is capped, and every one keeps a *_total
# so nothing reads as quieter than it was.
# ----------------------------------------------------------------------
MAX_APIS = 2000
MAX_ARG_CHARS = 200
MAX_EVENTS = 500
MAX_DROPPED = 100
MAX_ENTRY_POINTS = 200

#: Runtime-resolved imports. Measured max on the corpus is 41
#: (Amadey2.exe), so this is headroom rather than a real constraint.
MAX_DYN_IMPORTS = 500

#: Speakeasy error['type'] values that mean a graceful stop, not a fault.
_GRACEFUL = {"max_api_count": "api_cap", "timeout": "timeout"}



def _protect_stdout() -> int:
    """Move the real stdout out of reach before any library can write to it.

    Returns:
        A file descriptor that is the original stdout. Nothing else in the
        process can reach it, because fd 1 now points at stderr.
    """
    saved = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return saved


def _emit(saved_fd: int, payload: dict) -> None:
    """Write the one JSON document to the saved descriptor and exit cleanly.

    Args:
        saved_fd: Descriptor returned by :func:`_protect_stdout`.
        payload:  The envelope to serialise.
    """
    raw = json.dumps(payload, default=str).encode()
    with os.fdopen(saved_fd, "wb") as out:
        out.write(raw)


def _stop_reason(error: object) -> str:
    """Map Speakeasy's per-entry-point error onto this worker's vocabulary.

    Speakeasy does not store our words. A clean entry point has no error at
    all — so indexing ``error["type"]`` would raise on exactly the common
    case — and a fault carries its own specific category
    (``invalid_read``, ``unsupported_api``, ...) rather than the literal
    "fault". Hitting the API ceiling or the timeout *also* populates this
    field, which is why truthiness cannot be used to detect a fault.

    Args:
        error: ``entry_point["error"]``, which may be None, {}, or a dict.

    Returns:
        One of ``clean``, ``api_cap``, ``timeout``, ``fault``.
    """
    if not error:
        return "clean"
    if not isinstance(error, dict):
        return "fault"
    return _GRACEFUL.get(error.get("type"), "fault")


def _is_pe(data: bytes) -> bool:
    """Whether *data* begins with a real PE, not merely the letters ``MZ``.

    An ``MZ`` check alone would award the dropped-executable weight to any
    file whose first two bytes happen to read that way, so the PE signature
    is followed to where the header claims it is.

    Args:
        data: The leading bytes of a dropped file.

    Returns:
        True if both the DOS and NT signatures are present.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    return len(data) >= offset + 4 and data[offset : offset + 4] == b"PE\0\0"


def _as_list(value: object) -> list:
    """Coerce a Speakeasy activity field to a list without destroying it.

    ``registry_access`` and ``process_events`` are lists, but ``network``
    was never observed in the corpus and may well be a dict of sub-lists
    (``{traffic, dns}``). Extending a list with a dict would silently
    aggregate its *key names* and discard the data, so the shape is checked
    rather than assumed.

    Args:
        value: Whatever the field held, including None.

    Returns:
        A list. A dict's values are flattened; a scalar is wrapped.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        flat: list = []
        for sub in value.values():
            flat.extend(sub if isinstance(sub, list) else [sub])
        return flat
    return [value]


def _collect_dyn_imports(se) -> tuple[list, int]:
    """Read the imports the sample resolved at runtime, not from its table.

    This is the one part of Speakeasy's surface that measurably pays off on
    this corpus: 13 of 21 native PEs resolved at least one function through
    ``GetProcAddress`` or equivalent, and ``Amadey2.exe`` resolved 41.
    Packers hide their real imports exactly this way, so ``pe_analysis``
    sees a hollow import table and can only say the binary *looks* packed —
    this says what it actually reached for.

    Args:
        se: The Speakeasy instance, which may have no engine at all.

    Returns:
        ``(names, total)``, the list capped at :data:`MAX_DYN_IMPORTS`.
    """
    try:
        resolved = se.get_dyn_imports() or []
    except Exception:
        # Raises on a None engine when load_module failed.
        return [], 0

    names = []
    for item in resolved:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            names.append(item.get("name") or item.get("api_name") or str(item))
        else:
            names.append(str(item))
    return names[:MAX_DYN_IMPORTS], len(names)


def _collect_dropped(se) -> tuple[list, int, bool]:
    """Read dropped files from the live emulator before it is discarded.

    They are not in ``get_report()`` at all, and the bytes are needed here
    because the parent never sees them — the PE check has to happen on this
    side of the pipe.

    Args:
        se: The Speakeasy instance, which may not have an engine at all.

    Returns:
        ``(entries, total, saw_pe)``. ``entries`` is capped at
        :data:`MAX_DROPPED`; ``saw_pe`` is true if ANY dropped file was a
        PE, including one past the cap.
    """
    try:
        files = se.get_dropped_files() or []
    except Exception:
        # Raises AttributeError on a None engine when load_module failed.
        return [], 0, False

    # Every dropped file is inspected; only the emitted list is capped.
    # Slicing first would let a sample write 100 decoys before its payload
    # and carry the PE past the cap, evading the dropped-executable weight.
    out = []
    saw_pe = False
    for handle in files:
        entry = {"path": None, "sha256": None, "is_pe": False, "magic": None}
        for attr, key in (("get_path", "path"), ("get_hash", "sha256")):
            try:
                entry[key] = getattr(handle, attr)()
            except Exception:
                pass
        try:
            data = handle.get_data() or b""
            entry["is_pe"] = _is_pe(data)
            # Hex, never raw bytes: json.dumps raises TypeError on bytes,
            # which would crash the worker on precisely the samples that
            # are most interesting.
            entry["magic"] = data[:4].hex() or None
        except Exception:
            pass
        if entry["is_pe"]:
            saw_pe = True
        # Strictly capped. An earlier version kept every PE past the cap so
        # decoys could not hide one, but that made the list unbounded — a
        # sample writing PE buffers in a loop would blow the pipe budget
        # the cap exists to protect. The fact that a PE was dropped is
        # carried out separately instead, the same way features are taken
        # from the uncapped API list.
        if len(out) < MAX_DROPPED:
            out.append(entry)
    return out, len(files), saw_pe


# ----------------------------------------------------------------------
# Behavioural features, as EXACT API names.
#
# Substring matching was tried and is wrong, in a way that is invisible
# until it is measured: "lsa" is a substring of TlsAlloc and FlsAlloc,
# which the MSVC C runtime calls before main() in nearly every native PE.
# Every emulated sample therefore scored +10 for credential access, benign
# or not. Matching is exact, and a Windows API name is matched with its
# A/W suffix stripped so one entry covers both.
# ----------------------------------------------------------------------
_FEATURE_APIS: dict[str, frozenset[str]] = {
    "process_injection": frozenset({
        "writeprocessmemory", "createremotethread", "createremotethreadex",
        "virtualallocex", "virtualprotectex", "ntunmapviewofsection",
        "queueuserapc", "setthreadcontext", "ntwritevirtualmemory",
        "ntcreatethreadex", "rtlcreateuserthread",
    }),
    # No "schtasks": this table is matched against Win32 export names, and
    # schtasks.exe is a process a sample launches, not an API it calls, so
    # the entry could never fire. Scheduled-task persistence shows up as
    # CreateProcess with that command line, which belongs in a future
    # process_events rule rather than here.
    "persistence": frozenset({
        "regsetvalueex", "regsetvalue", "regcreatekeyex", "createservice",
        "startservice", "createprocessasuser",
    }),
    "self_deletion": frozenset({"deletefile", "movefileex", "ntdeletefile"}),
    # No "gettickcount": every Windows binary calls it, benign or not, so
    # it is the same false-positive shape as matching "lsa" inside
    # TlsAlloc. Timing-based evasion needs the INTERVAL between two calls,
    # which the post-emulation report does not preserve.
    "anti_analysis": frozenset({
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstring",
        "getadaptersinfo",
    }),
    "credential_access": frozenset({
        "cryptunprotectdata", "credenumerate", "credread",
        "lsaopenpolicy", "lsaretrieveprivatedata", "netuserenum",
    }),
}


#: Flattened once so _normalise_api can test membership cheaply.
_ALL_FEATURE_NAMES: frozenset[str] = frozenset().union(*_FEATURE_APIS.values())


def _normalise_api(name: str) -> str:
    """Reduce a Windows API name to the form the feature table keys on.

    Strips any module prefix and the trailing A/W character-set suffix, so
    ``kernel32.CreateFileW`` and ``CreateFileA`` both key as ``createfile``.

    Args:
        name: The API name as Speakeasy recorded it.

    Returns:
        The lowercased bare name without its A/W suffix.
    """
    bare = name.rsplit(".", 1)[-1].lower()
    if len(bare) > 2 and bare[-1] in ("a", "w") and bare[:-1].isalnum():
        trimmed = bare[:-1]
        # Only trim when trimming actually reaches a known name; otherwise
        # "createremotethreada" would be fine but "lsa" would become "ls".
        if trimmed in _ALL_FEATURE_NAMES:
            return trimmed
    return bare


def _extract_features(apis: list) -> dict:
    """Derive the behavioural features D-7 scores, from the UNCAPPED trace.

    This runs before any cap is applied. If features were read from the
    capped list, a noisy startup loop could fill the cap and push a later
    injection sequence out of the document — meaning a sample would score
    lower *because it was noisy first*, which an attacker controls.

    Args:
        apis: Every API name observed, in order, across all entry points.

    Returns:
        A dict of boolean features. Weights live in the provider.
    """
    seen = {_normalise_api(a) for a in apis if a}
    return {
        feature: bool(seen & names) for feature, names in _FEATURE_APIS.items()
    }


def _summarise(ep_reasons: list[str], interrupted: bool) -> tuple[bool, str | None, str]:
    """Decide how the file as a whole ended, from the per-entry reasons.

    Extracted so it can be tested without Speakeasy installed: the rules
    here are the ones review kept finding defects in, and testing them
    through ``_run`` would need a working emulator.

    Truncation is claimed **only** from per-entry stop reasons. The
    cumulative totals are deliberately not consulted — Speakeasy's budgets
    are per entry point and this worker cannot halt it part-way, so a total
    crossing a single-entry budget means nothing was cut short.

    Args:
        ep_reasons:  Each entry point's stop reason, in order.
        interrupted: Whether a Python exception ended the run.

    Returns:
        ``(truncated, truncation_reason, ended)``.
    """
    # An unhandled Python exception out of run_module ends the queue: the
    # entry point then running was cut off and everything still queued
    # never ran. That is a truncated picture whatever the entry points
    # that DID complete say, and it is a fault however many of them
    # succeeded — so it outranks them rather than being consulted only
    # when nothing ran.
    if interrupted:
        return True, "interrupted", "fault"

    stopped_early = [r for r in ep_reasons if r in ("api_cap", "timeout")]
    truncated = bool(stopped_early)
    truncation_reason = stopped_early[0] if stopped_early else None

    if truncation_reason:
        ended = truncation_reason
    elif not ep_reasons:
        # No entry points in the report at all. Speakeasy ran something —
        # load_module succeeded or we would have returned already — so an
        # empty list means the report did not describe it. "clean" would
        # be a claim about a run we cannot see; the provider turns an
        # empty trace into a failed detonation anyway, and this keeps the
        # two consistent.
        ended = "fault"
    elif "clean" in ep_reasons:
        # "Some faulted" is not a failure: exports are invoked with
        # synthesised arguments, so a fault on one says nothing about the
        # sample. Every attempted entry point must have faulted.
        ended = "clean"
    else:
        ended = "fault"
    return truncated, truncation_reason, ended


def _run(sample: str, budget: float, api_budget: int) -> dict:
    """Emulate *sample*, enforcing both budgets cumulatively across entries.

    Args:
        sample:     Path to the PE.
        budget:     Total wall-clock seconds across every entry point.
        api_budget: Total API calls across every entry point.

    Returns:
        The trace dict described in the plan's section 4.2.
    """
    import speakeasy  # noqa: PLC0415 — deliberately late, see module docstring

    started = time.monotonic()

    # ------------------------------------------------------------------
    # Phase 1: Construct with the budget.
    #
    # Speakeasy reads its limits once, here, and applies them PER ENTRY
    # POINT — see the module docstring for why that cannot be made
    # cumulative from this side. The checks after run_module() describe
    # what happened; they cannot interrupt it.
    # ------------------------------------------------------------------
    config = speakeasy.Speakeasy().config
    config["timeout"] = max(1, math.ceil(budget))
    config["max_api_count"] = api_budget
    se = speakeasy.Speakeasy(config=config)

    interrupted = False

    try:
        module = se.load_module(sample)
    except Exception as exc:
        # Not a usable PE. The engine does not exist, so nothing can be
        # harvested — get_report() itself raises past this point.
        return {
            "unloadable": f"{type(exc).__name__}: {exc}",
            "entry_points": [],
            "apis": [],
            "api_total": 0,
        }

    try:
        se.run_module(module, all_entrypoints=True)
    except Exception as exc:
        # A bug in a Speakeasy Python API hook bypasses its own handler, so
        # the entry point will look clean in the report. Record that it did
        # not, then harvest anyway: the trace up to the raise is still real
        # and may hold the only interesting thing the sample did.
        interrupted = f"{type(exc).__name__}: {exc}"

    # NOTE: no cumulative truncation is claimed here. The budgets are
    # Speakeasy's own and apply per entry point (see the module docstring),
    # so this function cannot halt the work part-way — and a check that
    # cannot stop anything must not pretend it did. Asserting truncation
    # from cumulative totals produced three wrong answers: a clean
    # multi-entry binary whose totals crossed a single-entry budget was
    # reported truncated although nothing was cut short; a real per-entry
    # timeout was relabelled "api_cap" because the cumulative API total
    # also happened to cross; and a sub-second budget rounded up to 1s
    # reported a timeout from interpreter start-up alone. The per-entry
    # stop reasons below are the only truthful source.

    # ------------------------------------------------------------------
    # Phase 2: Harvest. Guarded because an engine that failed to start
    # raises rather than returning an empty report.
    # ------------------------------------------------------------------
    try:
        report = se.get_report() or {}
    except Exception as exc:
        # The module loaded and ran, so this is not "nothing happened" —
        # the harvest itself broke. Swallowing it silently let the run
        # reach _summarise with no entry points and report `ended: clean`,
        # and if dropped files or runtime imports still came back off the
        # live instance the provider would call that an observed, clean,
        # un-truncated emulation of zero API calls. Record it as the fault
        # it is.
        report = {}
        interrupted = interrupted or f"report harvest failed: {type(exc).__name__}: {exc}"

    entries = report.get("entry_points") or []
    apis_all: list[str] = []
    apis_out: list[dict] = []
    events: dict[str, list] = {"network": [], "files": [], "registry": [], "processes": []}
    eps_out: list[dict] = []
    ep_reasons: list[str] = []

    # Iterate EVERY entry point. Only the emitted list is capped below:
    # slicing here would drop later entry points out of api_total, out of
    # the event totals and out of feature extraction, so a binary with many
    # exports could push its malicious one past the cap and out of scoring.
    for ep in entries:
        # No rewriting here. Which entry point an unhandled Python
        # exception aborted is not recoverable from the report — it may
        # have raised between entry points, in which case the last one
        # really did finish cleanly — so guessing produced wrong answers
        # in both directions. The interruption is recorded once, for the
        # whole file, by _summarise.
        reason = _stop_reason(ep.get("error"))
        ep_reasons.append(reason)
        if len(eps_out) < MAX_ENTRY_POINTS:
            eps_out.append({
                "ep_type": ep.get("ep_type"),
                "start_addr": ep.get("start_addr"),
                "ret_val": ep.get("ret_val"),
                "stop_reason": reason,
            })
        for call in ep.get("apis") or []:
            name = call.get("api_name") or ""
            apis_all.append(name)
            if len(apis_out) < MAX_APIS:
                apis_out.append({
                    "name": name,
                    "args": str(call.get("args"))[:MAX_ARG_CHARS],
                    "ret": str(call.get("ret_val"))[:MAX_ARG_CHARS],
                })
        for src, dst in (("network", "network"), ("file_access", "files"),
                         ("registry_access", "registry"), ("process_events", "processes")):
            events[dst].extend(_as_list(ep.get(src)))


    dropped, dropped_total, dropped_pe = _collect_dropped(se)
    dyn_imports, dyn_import_total = _collect_dyn_imports(se)

    # ------------------------------------------------------------------
    # Phase 3: Decide how the file as a whole ended.
    #
    # Precedence matters: a cumulative stop outranks any per-entry verdict,
    # because none of the entries that DID run will carry a cap or timeout
    # error when the worker itself called a halt. "Some faulted" is not a
    # failure — exports are invoked with synthesised arguments, so a fault
    # on one says nothing about the sample.
    # ------------------------------------------------------------------
    # A per-entry graceful stop also truncates the picture, so fold those in
    # BEFORE deciding `ended`. truncation_reason is only ever a reason for
    # truncation — an earlier version could leave it holding "clean", which
    # rendered as the nonsense "truncated (clean)".
    truncated, truncation_reason, ended = _summarise(ep_reasons, bool(interrupted))

    return {
        "apis": apis_out,
        "api_total": len(apis_all),
        "network": events["network"][:MAX_EVENTS],
        "network_total": len(events["network"]),
        "files": events["files"][:MAX_EVENTS],
        "files_total": len(events["files"]),
        "registry": events["registry"][:MAX_EVENTS],
        "registry_total": len(events["registry"]),
        "processes": events["processes"][:MAX_EVENTS],
        "processes_total": len(events["processes"]),
        "dropped": dropped,
        "dropped_total": dropped_total,
        "dyn_imports": dyn_imports,
        "dyn_import_total": dyn_import_total,
        "entry_points": eps_out,
        "entry_point_total": len(entries),
        "features": {**_extract_features(apis_all), "dropped_pe": dropped_pe},
        "truncated": truncated,
        "truncation_reason": truncation_reason,
        "ended": ended,
        "interrupted": interrupted or None,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, emulate, emit one JSON envelope, exit 0.

    Args:
        argv: Argument list for testing; defaults to the real one.

    Returns:
        0 whenever a document was produced, which is every path that is not
        a crash of this function itself.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--max-api-count", type=int, required=True)
    parser.add_argument("sample")
    args = parser.parse_args(argv)

    saved = _protect_stdout()

    try:
        trace = _run(args.sample, args.timeout, args.max_api_count)
    except ImportError as exc:
        # The only state the trace schema cannot express, which is why the
        # document is an envelope. The text matters: a missing setuptools<81
        # (unicorn 1.0.2 imports distutils, removed in Python 3.12) must be
        # distinguishable from the extra simply not being installed.
        _emit(saved, {"status": "unavailable", "reason": f"{type(exc).__name__}: {exc}"})
        return 0
    except Exception as exc:  # noqa: BLE001 — design rule 2 applies here too
        _emit(saved, {"status": "error", "reason": f"{type(exc).__name__}: {exc}"})
        return 0

    _emit(saved, {"status": "ok", "trace": trace})
    return 0


if __name__ == "__main__":
    sys.exit(main())
