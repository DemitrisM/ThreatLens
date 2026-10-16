"""Speakeasy dynamic analysis provider — emulates native Windows PEs.

Runs the emulation in a separate process (``_speakeasy_worker``) and maps
what comes back onto the D-2 three-valued detonation state.

Design notes
------------
**The one rule the state mapping follows: ``observed`` requires
observations.** How the emulation ended — clean return, fault, inner
timeout, API ceiling — is a *reason* attached to the state, never the thing
that decides it. Measured on the corpus: ``ArkeiStealer.exe`` emulates to
zero API calls *and* a fault, and four of six sampled binaries faulted at
all. A mapping keyed on the ending would report that sample as
"dynamically observed, nothing malicious" — a clean dynamic verdict on live
malware, which is exactly what D-2 exists to prevent. The inverse collapse
is equally wrong: ``Amadey2.exe`` faulted while recording 235 API calls, and
treating any fault as failure would throw that trace away.

**Applicability is decided here, not in ``is_available``.**
``_run_dynamic_provider`` calls ``is_available(config)`` before ``run()``,
passes it only the config — never the sample — and discards a False with a
bare ``None`` that carries no reason. So ``is_available`` answers only
whether the provider is selected at all, and every per-sample decision is
made here where a reason can be attached.

**The checks are ordered by cost.** 93.3% of the corpus is not a native PE,
and those answers come from a header read. Nothing is spawned for them.

**Why ``pefile`` rather than hand-read offsets.** The CLR directory entry
sits at a different file offset for PE32 than for PE32+; reading the 32-bit
offset on a 64-bit binary lands on the import-address-table entry, which is
non-zero in nearly every native 64-bit PE — so a hand-rolled check would
classify most candidates as .NET and skip them silently.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from core import detonation
from core.process import run_contained

logger = logging.getLogger(__name__)

PROVIDER_NAME = "speakeasy"

#: Added to the inner budget to get the hard kill. Not user-settable: if a
#: caller could set the outer bound below the inner one, the graceful path
#: would be unreachable and every sample would report failed — the tool
#: would look like a broken emulator rather than a misconfiguration.
_SUBPROCESS_MARGIN_SECONDS = 30

_DEFAULT_TIMEOUT = 60
_DEFAULT_MAX_APIS = 20000

#: Machine types Speakeasy emulates. An ARM64 PE otherwise passes the PE and
#: .NET checks, spawns a worker, and dies in load_module — reporting failed
#: when the honest answer is "we do not emulate this architecture".
_SUPPORTED_MACHINES = {0x014C, 0x8664}

#: What each observed feature contributes. D-7: weight the finding, never
#: the fact that emulation ran. "We emulated it" is worth zero.
_WEIGHTS = {
    "process_injection": 20,
    "persistence": 15,
    "self_deletion": 10,
    "anti_analysis": 10,
    "credential_access": 10,
}
_DROPPED_PE_WEIGHT = 15

# Runtime-resolved imports are reported and deliberately NOT scored.
#
# Measured on the 21 native PE candidates: 13 resolved at least one import
# at runtime, Amadey2.exe resolved 41. That is real evidence and it fills a
# gap pe_analysis cannot — a hollow import table tells you a binary looks
# packed, this tells you what it actually reached for.
#
# It is not weighted because its false-positive rate is unmeasured and the
# shape is suspicious: legitimate packed and licensed software resolves
# imports the same way, and this project has no benign corpus to measure
# against. Adding a weight now would move every packed sample's score on an
# untested assumption. It is surfaced for the analyst and left for the
# calibration sweep, once benign controls exist.


def is_available(config: dict) -> bool:
    """Whether this provider is selected at all.

    Deliberately does not probe for Speakeasy: the import check costs a
    subprocess, and the worker reports its own unavailability with a reason
    that this function has no way to return.

    Args:
        config: The validated configuration dict.

    Returns:
        True whenever the provider has been chosen.
    """
    return str(config.get("dynamic_provider", "none")).lower() == PROVIDER_NAME


def _not_attempted(reason: str) -> dict:
    """Build a result for a sample this provider will not emulate.

    Args:
        reason: Why, in terms a report reader can act on.

    Returns:
        A standard module result with the D-2 block set.
    """
    return {
        "module": PROVIDER_NAME,
        "status": "skipped",
        "data": {detonation.DATA_KEY: detonation.build(detonation.NOT_ATTEMPTED, reason)},
        "score_delta": 0,
        "reason": reason,
    }


def _failed(reason: str, data: dict | None = None) -> dict:
    """Build a result for an emulation that was attempted and did not work.

    A failed detonation is itself a finding — D-3 renders it deliberately —
    so this is distinct from never having tried.

    Args:
        reason: What went wrong.
        data:   Any partial data worth keeping beside the state.

    Returns:
        A standard module result with the D-2 block set and no score.
    """
    payload = dict(data or {})
    payload[detonation.DATA_KEY] = detonation.build(detonation.FAILED, reason)
    return {
        "module": PROVIDER_NAME,
        "status": "error",
        "data": payload,
        "score_delta": 0,
        "reason": reason,
    }


def _applicability(file_path: Path) -> str | None:
    """Why this sample cannot be emulated, or None if it can.

    Args:
        file_path: The sample.

    Returns:
        A reason string, or None when the sample is a supported native PE.
    """
    try:
        import pefile
    except ImportError:
        return "pefile is not installed"

    try:
        # fast_load: header fields only. Parsing every directory here would
        # repeat work pe_analysis already does, to answer a yes/no question.
        pe = pefile.PE(str(file_path), fast_load=True)
    except Exception:
        return "Not a PE file — Speakeasy emulates Windows executables"

    try:
        machine = pe.FILE_HEADER.Machine
        if machine not in _SUPPORTED_MACHINES:
            return f"Unsupported architecture (machine 0x{machine:04x})"

        # pefile populates only NumberOfRvaAndSizes entries and does not pad
        # to 16, so a malformed or heavily packed header can be short here.
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) > 14 and directories[14].VirtualAddress:
            return ".NET assembly — Speakeasy emulates native code only"
    except AttributeError:
        # A COFF-like file with SizeOfOptionalHeader == 0 loads without
        # raising but never gets an OPTIONAL_HEADER. Design rule 2: this
        # cannot be allowed to escape into the pipeline.
        return "PE header is incomplete — cannot determine whether it is native"
    except Exception as exc:  # noqa: BLE001 — same rule, anything else too
        return f"PE header could not be read: {type(exc).__name__}"
    finally:
        pe.close()

    return None


def _child_env() -> dict:
    """The environment the worker gets: ours, minus anything credential-shaped.

    The worker makes no network calls, and it is the process most likely to
    be exploited — it emulates attacker-controlled instructions under a
    unicorn with a published escape. There is no reason for a key to be
    reachable from inside it.

    Returns:
        A copy of the environment with credential variables removed.
    """
    env = dict(os.environ)
    for key in list(env):
        upper = key.upper()
        if "KEY" in upper or "TOKEN" in upper or "SECRET" in upper or "PASSWORD" in upper:
            env.pop(key, None)
    return env


def _score(trace: dict) -> tuple[int, list[str]]:
    """Score what was observed. Never the fact that emulation happened.

    Args:
        trace: The worker's trace dict.

    Returns:
        ``(delta, findings)``. The delta is never negative — D-1 clamps in
        the pipeline too, but a provider that relies on that is already
        wrong.
    """
    delta = 0
    findings: list[str] = []

    for feature, weight in _WEIGHTS.items():
        if trace.get("features", {}).get(feature):
            delta += weight
            findings.append(feature.replace("_", " "))

    # Read the FEATURE, not the capped list: a sample that drops a hundred
    # decoys before its payload would otherwise carry the PE past the cap
    # and evade this weight entirely.
    if trace.get("features", {}).get("dropped_pe"):
        delta += _DROPPED_PE_WEIGHT
        findings.append("executable written to disk")

    return max(0, delta), findings


def run(file_path: Path, config: dict) -> dict:
    """Emulate *file_path* and report what was observed.

    Never raises: every failure path returns a result dict with a reason,
    per design rule 2.

    Args:
        file_path: The sample under analysis.
        config:    The validated configuration dict.

    Returns:
        A standard module result dict carrying a D-2 detonation block.
    """
    # --- Applicability, cheapest first, nothing spawned ----------------
    reason = _applicability(Path(file_path))
    if reason:
        return _not_attempted(reason)

    inner = config.get("speakeasy_timeout_seconds", _DEFAULT_TIMEOUT) or _DEFAULT_TIMEOUT
    max_apis = config.get("speakeasy_max_api_count", _DEFAULT_MAX_APIS) or _DEFAULT_MAX_APIS

    argv = [
        sys.executable, "-m", "modules.dynamic._speakeasy_worker",
        "--timeout", str(inner),
        "--max-api-count", str(int(max_apis)),
        # Separator, so a path beginning with "-" is never parsed as a flag.
        # argparse would exit 2 before the worker could emit anything, and
        # the provider would report a failed detonation for a filename.
        "--",
        # ABSOLUTE, because run_contained below overrides the worker's cwd
        # to the repo root so `-m modules.dynamic...` resolves. A relative
        # path would be checked here against the caller's directory and
        # then reopened in the worker against a different one — so a scan
        # run from anywhere but the repo root would report a perfectly good
        # PE as "could not load".
        str(Path(file_path).resolve()),
    ]

    # --- Emulate, bounded from outside ---------------------------------
    try:
        completed = run_contained(
            argv,
            timeout=float(inner) + _SUBPROCESS_MARGIN_SECONDS,
            capture_output=True,
            text=True,
            env=_child_env(),
            cwd=str(Path(__file__).resolve().parents[2]),
        )
    except subprocess.TimeoutExpired:
        # The inner bound should have won. That it did not means the
        # emulator wedged somewhere Python could not interrupt.
        return _failed(
            f"Emulation timed out after {inner + _SUBPROCESS_MARGIN_SECONDS}s "
            "and was killed"
        )
    except OSError as exc:
        return _failed(f"Could not start the emulation worker: {exc}")

    if completed.stderr:
        logger.debug("speakeasy worker stderr: %s", completed.stderr[:2000])

    try:
        envelope = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        return _failed(
            f"Emulation worker produced no usable output (exit {completed.returncode})"
        )

    status = envelope.get("status")
    if status == "unavailable":
        return _not_attempted(f"Speakeasy is not installed: {envelope.get('reason')}")
    if status != "ok":
        return _failed(f"Emulation failed: {envelope.get('reason')}")

    trace = envelope.get("trace") or {}

    if trace.get("unloadable"):
        # FAILED, not not_attempted. Applicability already established this
        # is a supported native PE, so a worker that got this far did
        # attempt a detonation — load_module does the full directory parse,
        # section mapping and import resolution, and a packed or
        # header-tampered sample is exactly what breaks it. D-3 renders a
        # failed detonation deliberately, because that IS the finding;
        # reporting "never attempted" would hide it.
        return _failed(f"Speakeasy could not load the PE: {trace['unloadable']}")

    # --- The one rule: observed requires observations ------------------
    observations = sum(
        len(trace.get(k) or [])
        for k in ("apis", "network", "files", "registry", "processes", "dropped",
                  "dyn_imports")
    )
    if not observations:
        return _failed(
            f"Emulation produced no observations (ended: {trace.get('ended')})",
            {"trace": trace},
        )

    delta, findings = _score(trace)

    ended = trace.get("ended")
    detail = f"{trace.get('api_total', 0)} API calls"
    resolved = trace.get("dyn_import_total") or 0
    if resolved:
        detail += f", {resolved} imports resolved at runtime"
    if trace.get("truncated"):
        detail += f", truncated ({trace.get('truncation_reason')})"
    reason = (
        f"Emulated: {', '.join(findings)} — {detail}"
        if findings
        else f"Emulated ({detail}); no scored behaviour observed, ended {ended}"
    )

    return {
        "module": PROVIDER_NAME,
        "status": "success",
        "data": {
            "trace": trace,
            detonation.DATA_KEY: detonation.build(
                detonation.OBSERVED, f"Speakeasy emulation, ended {ended}"
            ),
            # Speakeasy is an offline emulator with synthetic network hooks:
            # nothing the sample sends leaves this machine. Stating that is
            # D-4's job, and "unknown" would be a lie in both directions.
            detonation.EGRESS_KEY: detonation.egress(detonation.EGRESS_DENIED),
        },
        "score_delta": delta,
        "reason": reason,
    }
