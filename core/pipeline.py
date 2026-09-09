"""Analysis pipeline orchestrator.

Discovers and runs enabled analysis modules in sequence, collects their
standardised result dicts, feeds them to the scoring engine, and
returns a complete report dict ready for any reporter.

Design notes
------------
Modules are imported lazily by dotted path rather than at module scope. That
is what lets a machine missing ``pefile`` or ``yara-python`` still run every
other module: the failed import becomes a skipped result, not an ImportError
at startup (design rule 2).

The orchestrator is deliberately ignorant of what any module does. It knows
only the result-dict contract, and it repairs partial results with
``setdefault`` rather than validating them, so a module author cannot break
the reporters by omitting a key.

Ordering is significant. ``enabled_modules`` is executed in sequence and each
module sees its predecessors' results through
``config["_module_results_so_far"]`` — ``virustotal`` relies on running after
``archive_analysis`` to look up hashes that archive extraction surfaced.
"""

import logging
import time
from pathlib import Path
from typing import Callable

from core.scoring import compute_score

logger = logging.getLogger(__name__)

# Type for optional progress callback: (module_index, total_modules, module_name, event)
# event is "start" or "done"
ProgressCallback = Callable[[int, int, str, str], None] | None

# ----------------------------------------------------------------------
# Static and enrichment module registry.
#
# Maps config module names → dotted import path. This table is the single
# authority on what a "module" is: the CLI validates --modules against it,
# config_loader's DEFAULTS list mirrors its keys, and the tests assert the
# three stay in step. file_intake lives in core/ because the pipeline
# cannot function without it; everything else is optional and lives under
# modules/.
# ----------------------------------------------------------------------
# Maps config module names → (import_path, callable_name).
# file_intake lives in core/, everything else under modules/.
_MODULE_REGISTRY: dict[str, str] = {
    "file_intake": "core.file_intake",
    "pe_analysis": "modules.static.pe_analysis",
    "string_analysis": "modules.static.string_analysis",
    "ioc_extractor": "modules.static.ioc_extractor",
    "capa_analysis": "modules.static.capa_analysis",
    "yara_scanner": "modules.static.yara_scanner",
    "doc_analysis": "modules.static.doc_analysis",
    "pdf_analysis": "modules.static.pdf_analysis",
    "html_analysis": "modules.static.html_analysis",
    "archive_analysis": "modules.static.archive_analysis",
    "onenote_analysis": "modules.static.onenote_analysis",
    "lnk_analysis": "modules.static.lnk_analysis",
    "virustotal": "modules.enrichment.virustotal",
}

# ----------------------------------------------------------------------
# User-facing short names.
#
# Typing `--modules pe,capa,vt` is the common case; the registry keys are
# the precise ones. Several aliases map to the same target on purpose
# (zip/archive, doc/office) because analysts reach for different words for
# the same format.
# ----------------------------------------------------------------------
# Short names accepted by --modules / --skip, mapped to registry keys.
# Lives here rather than in cli/ so the CLI and any config validation
# resolve names through one table.
MODULE_ALIASES: dict[str, str] = {
    "intake": "file_intake",
    "file": "file_intake",
    "pe": "pe_analysis",
    "exe": "pe_analysis",
    "strings": "string_analysis",
    "string": "string_analysis",
    "ioc": "ioc_extractor",
    "iocs": "ioc_extractor",
    "capa": "capa_analysis",
    "yara": "yara_scanner",
    "doc": "doc_analysis",
    "office": "doc_analysis",
    "pdf": "pdf_analysis",
    "html": "html_analysis",
    "archive": "archive_analysis",
    "zip": "archive_analysis",
    "onenote": "onenote_analysis",
    "lnk": "lnk_analysis",
    "shortcut": "lnk_analysis",
    "vt": "virustotal",
}


def resolve_module_name(name: str) -> str | None:
    """Canonical module name for a user-supplied token, or None if unknown.

    Accepts a registry key verbatim or any alias above, case-insensitively.
    Returning None rather than raising keeps the policy decision with the
    caller: the CLI treats an unknown name as a usage error, while
    ``enabled_modules`` in config.yaml only warns and skips, so a stale
    config file cannot make the tool unrunnable.

    Args:
        name: A registry key or alias, in any case, possibly padded.

    Returns:
        The canonical registry key, or None if the token matches neither.
    """
    # Registry keys win over aliases so a future alias colliding with a
    # real module name can never shadow that module.
    token = name.strip().lower()
    if token in _MODULE_REGISTRY:
        return token
    return MODULE_ALIASES.get(token)


def module_names() -> list[str]:
    """Every canonical module name, sorted — for error messages and help.

    Returns:
        Sorted list of registry keys. Sorted rather than in registry
        order so the CLI's error text is stable across edits to the
        registry, which the surface tests depend on.
    """
    return sorted(_MODULE_REGISTRY)


# ----------------------------------------------------------------------
# Dynamic provider registry — kept separate from the static modules.
#
# Providers detonate the sample rather than reading it, so they have a
# different contract (an is_available() gate) and a different risk
# profile. At most one runs per scan, chosen by config, and there is
# deliberately no --dynamic flag: arming a sandbox is a config decision,
# not something to trip over on the command line. All three are Phase 5
# stubs today.
# ----------------------------------------------------------------------
_DYNAMIC_REGISTRY: dict[str, str] = {
    "speakeasy": "modules.dynamic.speakeasy_provider",
    "vm_worker": "modules.dynamic.vm_worker_provider",
    "cape": "modules.dynamic.cape_provider",
}


def _load_module(import_path: str) -> object | None:
    """Dynamically import a module by dotted path.

    Args:
        import_path: Dotted path from one of the two registries.

    Returns:
        The imported module object, or None if the import failed
        (graceful degradation — a missing optional dependency must never
        crash the pipeline).
    """
    try:
        # Imported inside the function, not at module scope: this is the
        # one call site, and a top-level import here would run at CLI
        # startup for a tool that may never load a single module.
        from importlib import import_module  # noqa: PLC0415

        return import_module(import_path)
    except ImportError as exc:
        # The expected failure: an optional third-party dependency is not
        # installed. Warn and let the caller record a skip.
        logger.warning("Could not import %s: %s — module will be skipped", import_path, exc)
        return None
    except Exception as exc:  # noqa: BLE001
        # Anything else means the module raised during import — a syntax
        # error or a bad module-level constant. Still non-fatal, but it
        # is a bug rather than a missing package.
        logger.warning("Unexpected error importing %s: %s", import_path, exc)
        return None


def _run_module(mod: object, name: str, file_path: Path, config: dict) -> dict:
    """Invoke a module's ``run()`` function and return its result dict.

    Guarantees a well-formed result to the caller under all conditions: a
    module with no ``run()`` yields a skip, a module that raises or returns
    a non-dict yields an error result, and a partial dict is completed with
    ``setdefault``.

    Args:
        mod:       Imported module object from ``_load_module``.
        name:      Canonical module name, used for the result and logs.
        file_path: Path to the file under analysis.
        config:    Configuration dict, forwarded to the module unchanged.

    Returns:
        A standard module result dict. Never raises.
    """
    # NOTE: this function does NOT impose the ``module_timeout_seconds``
    # timeout. Timeouts are enforced inside the modules that shell out or
    # can loop (capa's subprocess, XLM deobfuscation's 30s cap), because
    # only they can be interrupted safely; there is no watchdog at the
    # orchestrator level. See the note raised against design rule 5.
    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        logger.debug("Module %s has no run() — skipped (not yet implemented)", name)
        return _skipped_result(name, "Module not yet implemented")

    try:
        result = run_fn(file_path, config)

        if not isinstance(result, dict):
            logger.warning("Module %s returned non-dict — treating as error", name)
            return _error_result(name, "Module returned non-dict result")

        # Repair rather than reject: setdefault fills any key the module
        # omitted so every reporter can index the result dict blindly.
        # Ensure all required keys are present.
        result.setdefault("module", name)
        result.setdefault("status", "success")
        result.setdefault("data", {})
        result.setdefault("score_delta", 0)
        result.setdefault("reason", "")
        return result

    except Exception as exc:  # noqa: BLE001
        # Deliberately broad. This is the boundary that makes design rule
        # 2 true: whatever a third-party parser throws on malformed input,
        # the other twelve modules still run and the user still gets a
        # report.
        logger.error("Module %s raised an exception: %s", name, exc)
        return _error_result(name, str(exc))


def _run_dynamic_provider(
    provider_path: str, provider_name: str, file_path: Path, config: dict
) -> dict | None:
    """Load and run a dynamic analysis provider.

    Args:
        provider_path: Dotted import path from ``_DYNAMIC_REGISTRY``.
        provider_name: Provider key, used to label the result.
        file_path:     Path to the file under analysis.
        config:        Configuration dict, forwarded unchanged.

    Returns:
        The provider result dict, or None if the provider is unavailable
        or failed. None is distinct from an error result: an unarmed
        sandbox is a normal state, not a fault to report.
    """
    mod = _load_module(provider_path)
    if mod is None:
        return None

    # ------------------------------------------------------------------
    # Step 1: Ask the provider whether it can actually run.
    #
    # Detonation needs a live backend — a reachable CAPE instance, a
    # configured VM. is_available() lets the provider check that itself
    # rather than have the orchestrator encode each backend's
    # preconditions.
    # ------------------------------------------------------------------
    # Providers expose is_available() and run(sample_path).
    is_available = getattr(mod, "is_available", None)
    if callable(is_available) and not is_available(config):
        logger.info("Dynamic provider %s is not available — skipping", provider_name)
        return None

    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        logger.warning("Dynamic provider %s has no run() function", provider_name)
        return None

    # ------------------------------------------------------------------
    # Step 2: Run it, normalising the result to the same contract the
    # static modules obey so the reporters need no special case. The
    # "dynamic_" prefix keeps the provider distinguishable in the score
    # breakdown.
    # ------------------------------------------------------------------
    try:
        result = run_fn(file_path, config)
        if isinstance(result, dict):
            result.setdefault("module", f"dynamic_{provider_name}")
            result.setdefault("status", "success")
            result.setdefault("data", {})
            result.setdefault("score_delta", 0)
            result.setdefault("reason", "")
            return result
        logger.warning("Dynamic provider %s returned non-dict", provider_name)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error("Dynamic provider %s failed: %s", provider_name, exc)
        return None


def _error_result(module_name: str, message: str) -> dict:
    """Build a safe error-state module result.

    Args:
        module_name: Canonical module name.
        message:     Human-readable failure description, surfaced as the
                     result's ``reason``.

    Returns:
        A standard result dict with ``status: "error"`` and a zero score.
        The zero matters: a module that failed must not be able to move
        the verdict in either direction.
    """
    return {
        "module": module_name,
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": message,
    }


def _skipped_result(module_name: str, reason: str) -> dict:
    """Build a skipped-state module result.

    Args:
        module_name: Canonical module name.
        reason:      Why the module did not run — an absent dependency,
                     an inapplicable file type.

    Returns:
        A standard result dict with ``status: "skipped"``. Distinct from
        an error so the report can say "did not apply" rather than
        "went wrong"; ``-v`` shows these, level 0 hides them.
    """
    return {
        "module": module_name,
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def run_pipeline(
    file_path: Path,
    config: dict,
    progress_cb: ProgressCallback = None,
) -> dict:
    """Execute the full analysis pipeline on *file_path*.

    Runs every enabled module listed in ``config["enabled_modules"]``,
    optionally runs the configured dynamic provider, computes the
    aggregate confidence score, and returns a report dict.

    Args:
        file_path:   Path to the file under analysis.
        config:      Validated configuration dict from config_loader.
        progress_cb: Optional callback(index, total, name, event) for
                     progress updates.  *event* is ``"start"`` or ``"done"``.

    Returns:
        Report dict with keys:
            file          — str, original file path
            module_results — list of per-module result dicts
            scoring       — output of scoring.compute_score()
            timing        — dict with start/end/elapsed
            dynamic       — dynamic provider result (or None)
    """
    start_time = time.time()
    enabled = config.get("enabled_modules", [])
    total_modules = len(enabled)
    module_results: list[dict] = []

    logger.info(
        "Pipeline starting — %d modules enabled, file: %s",
        total_modules,
        file_path.name,
    )

    # ------------------------------------------------------------------
    # Step 1: Run the static and enrichment modules, in the order
    # enabled_modules lists them.
    #
    # Order is load-bearing, not cosmetic: each module is handed the
    # results of everything before it, so virustotal must follow
    # archive_analysis to see the embedded hashes it extracted. Every
    # failure path here appends a result and continues — a scan that runs
    # twelve of thirteen modules is still a useful scan.
    # ------------------------------------------------------------------
    # --- Static / enrichment modules ---
    for idx, name in enumerate(enabled):
        # An unknown name reaching this point came from a stale config
        # file, not the CLI (which rejects unknown names with exit 2).
        # Warn and skip so an old config cannot make the tool unrunnable.
        import_path = _MODULE_REGISTRY.get(name)
        if import_path is None:
            logger.warning("Unknown module %r in enabled_modules — skipping", name)
            module_results.append(_skipped_result(name, f"Unknown module: {name}"))
            continue

        mod = _load_module(import_path)
        if mod is None:
            module_results.append(
                _skipped_result(name, f"Could not import {import_path}")
            )
            continue

        logger.debug("Running module: %s", name)
        if progress_cb is not None:
            progress_cb(idx, total_modules, name, "start")
        # A copy, not the live list: a module that mutated the pipeline's
        # own accumulator could corrupt the report for every module after
        # it.
        # Expose prior results so downstream modules (e.g. virustotal) can
        # read embedded hashes surfaced by archive_analysis.
        config["_module_results_so_far"] = list(module_results)
        t0 = time.time()
        result = _run_module(mod, name, file_path, config)
        elapsed = time.time() - t0
        # Timing is attached here rather than inside the module so it is
        # measured uniformly and no module can misreport its own cost.
        result["elapsed_seconds"] = round(elapsed, 3)
        logger.debug("Module %s finished in %.2fs — status: %s", name, elapsed, result["status"])
        module_results.append(result)
        if progress_cb is not None:
            progress_cb(idx, total_modules, name, "done")

    # ------------------------------------------------------------------
    # Step 2: Run the dynamic provider, if one is configured.
    #
    # Config-driven only, and at most one. Its result joins
    # module_results so it scores through exactly the same path as a
    # static module.
    # ------------------------------------------------------------------
    # --- Dynamic provider (if configured) ---
    dynamic_result = None
    provider_name = config.get("dynamic_provider", "none").lower()
    if provider_name != "none":
        provider_path = _DYNAMIC_REGISTRY.get(provider_name)
        if provider_path is None:
            logger.warning("Unknown dynamic provider %r — skipping", provider_name)
        else:
            logger.info("Running dynamic provider: %s", provider_name)
            dynamic_result = _run_dynamic_provider(
                provider_path, provider_name, file_path, config
            )
            if dynamic_result is not None:
                module_results.append(dynamic_result)

    # ------------------------------------------------------------------
    # Step 3: Score once, over everything that ran, and assemble the
    # report. This dict is the pipeline's entire public output — every
    # reporter (JSON, terminal, HTML, triage) consumes this shape and
    # nothing else.
    # ------------------------------------------------------------------
    # --- Scoring ---
    scoring = compute_score(module_results)

    end_time = time.time()

    report = {
        "file": str(file_path),
        "module_results": module_results,
        "scoring": scoring,
        "timing": {
            "start": start_time,
            "end": end_time,
            "elapsed_seconds": round(end_time - start_time, 3),
        },
        "dynamic": dynamic_result,
    }

    logger.info(
        "Pipeline complete — score: %d / 100 [%s] in %.2fs",
        scoring["total_score"],
        scoring["risk_band"],
        report["timing"]["elapsed_seconds"],
    )

    return report
