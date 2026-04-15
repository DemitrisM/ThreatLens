"""Analysis pipeline orchestrator.

Discovers and runs enabled analysis modules in sequence, collects their
standardised result dicts, feeds them to the scoring engine, and
returns a complete report dict ready for any reporter.
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
    "virustotal": "modules.enrichment.virustotal",
}

# Dynamic provider registry — separate from static modules.
_DYNAMIC_REGISTRY: dict[str, str] = {
    "speakeasy": "modules.dynamic.speakeasy_provider",
    "vm_worker": "modules.dynamic.vm_worker_provider",
    "cape": "modules.dynamic.cape_provider",
}


def _load_module(import_path: str) -> object | None:
    """Dynamically import a module by dotted path.

    Returns the module object, or None if the import fails (graceful
    degradation — a missing optional dependency must never crash the
    pipeline).
    """
    try:
        from importlib import import_module  # noqa: PLC0415

        return import_module(import_path)
    except ImportError as exc:
        logger.warning("Could not import %s: %s — module will be skipped", import_path, exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected error importing %s: %s", import_path, exc)
        return None


def _run_module(mod: object, name: str, file_path: Path, config: dict) -> dict:
    """Invoke a module's ``run()`` function and return its result dict.

    Enforces the per-module timeout from config.  If the module raises
    or returns a non-dict, a safe ``status: "error"`` result is
    returned instead.
    """
    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        logger.debug("Module %s has no run() — skipped (not yet implemented)", name)
        return _skipped_result(name, "Module not yet implemented")

    try:
        result = run_fn(file_path, config)

        if not isinstance(result, dict):
            logger.warning("Module %s returned non-dict — treating as error", name)
            return _error_result(name, "Module returned non-dict result")

        # Ensure all required keys are present.
        result.setdefault("module", name)
        result.setdefault("status", "success")
        result.setdefault("data", {})
        result.setdefault("score_delta", 0)
        result.setdefault("reason", "")
        return result

    except Exception as exc:  # noqa: BLE001
        logger.error("Module %s raised an exception: %s", name, exc)
        return _error_result(name, str(exc))


def _run_dynamic_provider(
    provider_path: str, provider_name: str, file_path: Path, config: dict
) -> dict | None:
    """Load and run a dynamic analysis provider.

    Returns the provider result dict, or None if the provider is
    unavailable or fails.
    """
    mod = _load_module(provider_path)
    if mod is None:
        return None

    # Providers expose is_available() and run(sample_path).
    is_available = getattr(mod, "is_available", None)
    if callable(is_available) and not is_available(config):
        logger.info("Dynamic provider %s is not available — skipping", provider_name)
        return None

    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        logger.warning("Dynamic provider %s has no run() function", provider_name)
        return None

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
    """Build a safe error-state module result."""
    return {
        "module": module_name,
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": message,
    }


def _skipped_result(module_name: str, reason: str) -> dict:
    """Build a skipped-state module result."""
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

    # --- Static / enrichment modules ---
    for idx, name in enumerate(enabled):
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
        # Expose prior results so downstream modules (e.g. virustotal) can
        # read embedded hashes surfaced by archive_analysis.
        config["_module_results_so_far"] = list(module_results)
        t0 = time.time()
        result = _run_module(mod, name, file_path, config)
        elapsed = time.time() - t0
        result["elapsed_seconds"] = round(elapsed, 3)
        logger.debug("Module %s finished in %.2fs — status: %s", name, elapsed, result["status"])
        module_results.append(result)
        if progress_cb is not None:
            progress_cb(idx, total_modules, name, "done")

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
