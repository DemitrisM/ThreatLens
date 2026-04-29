"""Scan-profile presets, module overrides, logging setup, and verbosity helpers."""

import logging

import click


# ── Scan profile presets ────────────────────────────────────────────

_QUICK_MODULES = ["file_intake", "pe_analysis"]

_STANDARD_MODULES = [
    "file_intake",
    "pe_analysis",
    "string_analysis",
    "ioc_extractor",
    "capa_analysis",
    "yara_scanner",
    "doc_analysis",
    "pdf_analysis",
    "html_analysis",
    "archive_analysis",
    "virustotal",
]

_DEEP_OVERRIDES = {
    "capa_timeout_seconds": 180,
}


def _apply_scan_profile(config: dict, profile: str) -> dict:
    """Override config values based on the selected scan profile."""
    if profile == "quick":
        config["enabled_modules"] = list(_QUICK_MODULES)
    elif profile == "deep":
        for k, v in _DEEP_OVERRIDES.items():
            config[k] = v
    elif profile == "full":
        for k, v in _DEEP_OVERRIDES.items():
            config[k] = v
    return config


def _apply_module_overrides(
    config: dict, modules: str | None, skip: str | None
) -> dict:
    """Apply --modules and --skip overrides to enabled_modules."""
    if modules is not None:
        names = [m.strip() for m in modules.split(",") if m.strip()]
        if "file_intake" not in names:
            names.insert(0, "file_intake")
        config["enabled_modules"] = names

    if skip is not None:
        to_skip = {m.strip() for m in skip.split(",") if m.strip()}
        config["enabled_modules"] = [
            m for m in config["enabled_modules"] if m not in to_skip
        ]

    return config


def _setup_logging(log_level: str, verbose: bool, debug: bool) -> None:
    """Configure the root logger based on CLI flags and config."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = getattr(logging, log_level, logging.WARNING)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _resolve_profile(quick: bool, deep: bool, full: bool) -> str:
    """Return the active scan profile name, enforcing mutual exclusion."""
    selected = [p for p, flag in [("quick", quick), ("deep", deep), ("full", full)] if flag]
    if len(selected) > 1:
        raise click.UsageError(
            f"Scan profiles are mutually exclusive — got: {', '.join(selected)}"
        )
    return selected[0] if selected else "standard"


def _detail_level(verbose: bool, debug: bool) -> int:
    """Map verbosity flags to a detail level for the terminal reporter.

    0 = default summary, 1 = expanded (-v), 2 = full (--debug / -vv).
    """
    if debug:
        return 2
    if verbose:
        return 1
    return 0
