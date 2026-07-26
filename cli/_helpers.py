"""Scan-profile presets, module overrides, and logging setup.

ThreatLens separates two axes that other tools keep confused:

- ``--profile`` decides *what runs* — a cost decision.
- ``-v`` / ``-vv`` decide *what prints* — a display decision.

Nothing in this module touches the second axis; verbosity is a plain count
passed straight to the reporter.
"""

import copy
import logging

from core.config_loader import DEFAULTS

# ── Scan profile presets ────────────────────────────────────────────

PROFILES = ("quick", "standard", "deep")

_QUICK_MODULES = ["file_intake", "pe_analysis"]

_DEEP_OVERRIDES = {
    "capa_timeout_seconds": 180,
}


def _apply_scan_profile(config: dict, profile: str) -> dict:
    """Override config values based on the selected scan profile.

    ``standard`` means "whatever ``enabled_modules`` says", so it only fills
    in the built-in list when the config supplied none — overwriting from
    ``DEFAULTS`` would silently drop modules a user enabled in config.yaml.
    """
    if profile == "quick":
        config["enabled_modules"] = list(_QUICK_MODULES)
    elif profile == "standard":
        if not config.get("enabled_modules"):
            config["enabled_modules"] = copy.deepcopy(DEFAULTS["enabled_modules"])
    elif profile == "deep":
        config.update(_DEEP_OVERRIDES)
    return config


def _apply_module_overrides(
    config: dict, modules: str | None, skip: str | None
) -> dict:
    """Apply ``--modules`` and ``--skip`` overrides to ``enabled_modules``.

    Names are still matched verbatim against the pipeline registry here;
    Pass 3 of the CLI redesign adds alias resolution and rejects unknown
    names with a usage error.
    """
    if modules is not None:
        names = [m.strip() for m in modules.split(",") if m.strip()]
        # Every module reads file_intake's metadata, so it is never optional.
        if "file_intake" not in names:
            names.insert(0, "file_intake")
        config["enabled_modules"] = names

    if skip is not None:
        to_skip = {m.strip() for m in skip.split(",") if m.strip()}
        config["enabled_modules"] = [
            m for m in config["enabled_modules"] if m not in to_skip
        ]

    return config


def _setup_logging(log_level: str | None = None, verbosity: int = 0) -> None:
    """Configure the root logger.

    Args:
        log_level: Level name from config, used when no flag overrides it.
        verbosity: ``-v`` count. 1 → INFO, 2+ → DEBUG.

    Called twice per invocation: once before the config is read (so that
    config-loading warnings reach a configured handler) and once after (to
    honour ``log_level``). ``force=True`` makes the second call effective —
    ``logging.basicConfig`` is otherwise a no-op once handlers exist.
    """
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = getattr(logging, (log_level or "WARNING").upper(), logging.WARNING)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        force=True,
    )


def _detail_level(verbosity: int) -> int:
    """Clamp a ``-v`` count to the reporter's 0/1/2 detail levels."""
    return min(max(verbosity, 0), 2)
