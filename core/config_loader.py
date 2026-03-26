"""Configuration loader — reads and validates config.yaml.

Provides a single get_config() entry point that returns a validated
configuration dict with sensible defaults for any missing keys.
"""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

DEFAULTS = {
    "virustotal_api_key": "",
    "yara_rules_dir": "./rules/yara",
    "floss_binary": "./bin/floss",
    "capa_binary": "./bin/capa",
    "output_dir": "./reports",
    "log_level": "INFO",
    "module_timeout_seconds": 60,
    "enabled_modules": [
        "file_intake",
        "pe_analysis",
        "string_analysis",
        "ioc_extractor",
        "capa_analysis",
        "yara_scanner",
        "doc_analysis",
        "pdf_analysis",
        "virustotal",
    ],
    "dynamic_provider": "none",
}

VALID_DYNAMIC_PROVIDERS = {"none", "speakeasy", "vm_worker", "cape"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def get_config(config_path: Path | None = None) -> dict:
    """Load config.yaml and return a validated dict with defaults applied.

    Args:
        config_path: Path to config.yaml. Defaults to ./config.yaml relative
                     to the current working directory.

    Returns:
        Validated configuration dict.

    Raises:
        SystemExit: If the config file exists but cannot be parsed.
    """
    if config_path is None:
        config_path = Path("config.yaml")

    config = dict(DEFAULTS)

    if not config_path.exists():
        logger.warning(
            "Config file not found at %s — using defaults", config_path
        )
        return config

    try:
        with config_path.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse config file %s: %s", config_path, exc)
        raise SystemExit(1) from exc

    if loaded and isinstance(loaded, dict):
        config.update(loaded)

    _validate(config)
    return config


def _validate(config: dict) -> None:
    """Apply sanity checks and normalise values in-place."""
    provider = config.get("dynamic_provider", "none")
    if provider not in VALID_DYNAMIC_PROVIDERS:
        logger.warning(
            "Unknown dynamic_provider %r — falling back to 'none'", provider
        )
        config["dynamic_provider"] = "none"

    log_level = str(config.get("log_level", "INFO")).upper()
    if log_level not in VALID_LOG_LEVELS:
        logger.warning(
            "Unknown log_level %r — falling back to 'INFO'", log_level
        )
        log_level = "INFO"
    config["log_level"] = log_level

    timeout = config.get("module_timeout_seconds", 60)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        logger.warning(
            "Invalid module_timeout_seconds %r — falling back to 60", timeout
        )
        config["module_timeout_seconds"] = 60
