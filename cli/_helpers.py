"""Scan-profile presets, module overrides, and logging setup.

ThreatLens separates two axes that other tools keep confused:

- ``--profile`` decides *what runs* — a cost decision.
- ``-v`` / ``-vv`` decide *what prints* — a display decision.

Nothing in this module touches the second axis; verbosity is a plain count
passed straight to the reporter.
"""

import copy
import logging

import click

from core.config_loader import DEFAULTS
from core.pipeline import module_names, resolve_module_name

logger = logging.getLogger(__name__)

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


#: Every module reads this one's metadata (hashes, type), so it is never
#: optional — it is force-added to --modules and ignored in --skip.
_MANDATORY_MODULE = "file_intake"


def _resolve_list(raw: str, flag: str) -> list[str]:
    """Split a comma-separated flag value into canonical module names.

    Raises:
        click.UsageError: on an unknown name or an empty selection. Both
            are exit 2. Silently accepting either is how ``--modules
            pe,capa,yara`` used to produce ``total_score: 0`` and a
            confident LOW verdict on a scan that never ran.
    """
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    if not tokens:
        raise click.UsageError(
            f"{flag} was given no module names. "
            f"Valid names: {', '.join(module_names())}"
        )

    unknown = [t for t in tokens if resolve_module_name(t) is None]
    if unknown:
        raise click.UsageError(
            f"{flag}: unknown module(s): {', '.join(unknown)}. "
            f"Valid names: {', '.join(module_names())}"
        )

    resolved: list[str] = []
    for token in tokens:
        name = resolve_module_name(token)
        # Aliases can collide (pe and exe both mean pe_analysis), so
        # de-duplicate while keeping the order the user typed.
        if name not in resolved:
            resolved.append(name)
    return resolved


def _apply_module_overrides(
    config: dict, modules: str | None, skip: str | None
) -> dict:
    """Apply ``--modules`` and ``--skip`` overrides to ``enabled_modules``.

    Both accept registry names and short aliases (``pe``, ``capa``, ``vt``).
    ``--skip`` is applied after ``--modules``, so ``-p deep --skip
    capa_analysis`` behaves as documented.

    Unknown names are a usage error rather than a silent no-op — the CLI is
    explicit intent, so a typo must not quietly change what ran.
    ``enabled_modules`` in config.yaml stays permissive (the pipeline warns
    and skips) so a stale config file cannot make the tool unrunnable.
    """
    if modules is not None:
        names = _resolve_list(modules, "--modules")
        if _MANDATORY_MODULE not in names:
            names.insert(0, _MANDATORY_MODULE)
        config["enabled_modules"] = names

    if skip is not None:
        to_skip = set(_resolve_list(skip, "--skip"))
        if _MANDATORY_MODULE in to_skip:
            logger.warning(
                "%s cannot be skipped — every module reads its metadata",
                _MANDATORY_MODULE,
            )
            to_skip.discard(_MANDATORY_MODULE)
        config["enabled_modules"] = [
            m for m in config["enabled_modules"] if m not in to_skip
        ]

    remaining = [m for m in config["enabled_modules"] if m != _MANDATORY_MODULE]
    if not remaining:
        raise click.UsageError(
            "No analysis modules left to run — every module was skipped or "
            "deselected. A scan that runs nothing cannot report a verdict."
        )

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
