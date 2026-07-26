"""Configuration loader — reads and validates config.yaml.

Provides a single get_config() entry point that returns a validated
configuration dict with sensible defaults for any missing keys.
"""

import copy
import logging
import os
import stat
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

#: Environment variable naming an alternate config file.
CONFIG_ENV_VAR = "THREATLENS_CONFIG"

#: Environment variable supplying the VirusTotal API key.
#:
#: Deliberately the only non-file mechanism. There is no ``--vt-key`` flag:
#: an argv secret is world-readable via ``ps`` and ``/proc/PID/cmdline`` for
#: the life of the process and lands in shell history, and it helps with
#: neither container path (a read-only mounted config, or ``--env-file``).
VT_KEY_ENV_VAR = "THREATLENS_VT_KEY"

#: Config keys whose value is a credential — used for the permission check.
_SECRET_CONFIG_KEYS = ("virustotal_api_key",)


class ConfigNotFound(Exception):
    """An explicitly requested config file does not exist.

    Raised rather than ``click.UsageError`` so ``core/`` stays free of the
    CLI framework; ``cli/`` translates this into exit 2.
    """


class ConfigError(Exception):
    """A config file exists but could not be parsed."""

DEFAULTS = {
    "virustotal_api_key": "",
    "yara_rules_dir": "./rules/yara",
    "floss_binary": "./bin/floss",
    "capa_binary": "./bin/capa",
    "output_dir": "./reports",
    "log_level": "INFO",
    "module_timeout_seconds": 60,
    "capa_timeout_seconds": 120,
    "enabled_modules": [
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
        "onenote_analysis",
        "virustotal",
    ],
    "dynamic_provider": "none",
    # archive_analysis tuning — these live in config.yaml and are read by
    # the module at runtime. Without them here they vanish on the
    # no-config path and each module falls back to its own literal.
    "archive_full_recursion": False,
    "max_archive_recursion_depth": 3,
    "max_archive_extracted_size_mb": 500,
    "archive_bomb_ratio_threshold": 100,
    "archive_bomb_member_count_threshold": 1000,
    "archive_member_mime_check_max_mb": 10,
    # onenote_analysis tuning
    "max_onenote_size_mb": 50,
    "max_onenote_blobs": 200,
    "onenote_full_recursion": False,
    "max_onenote_recursion_depth": 2,
    "rule_sources": [
        {
            "name": "signature-base",
            "type": "git",
            "url": "https://github.com/Neo23x0/signature-base.git",
            "directory": "signature-base",
            "branch": "master",
            "enabled": True,
        },
    ],
}

VALID_DYNAMIC_PROVIDERS = {"none", "speakeasy", "vm_worker", "cape"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _search_paths() -> list[Path]:
    """Config locations to try, in clig.dev precedence order."""
    paths = []
    env_value = os.environ.get(CONFIG_ENV_VAR)
    if env_value:
        paths.append(Path(env_value))
    paths.append(Path("config.yaml"))
    paths.append(Path.home() / ".config" / "threatlens" / "config.yaml")
    return paths


def get_config(config_path: Path | None = None, *, required: bool = True) -> dict:
    """Load config and return a validated dict with defaults applied.

    Search order when *config_path* is None: ``$THREATLENS_CONFIG``, then
    ``./config.yaml``, then ``~/.config/threatlens/config.yaml``.

    Args:
        config_path: Explicit path, usually from ``--config``.
        required:    When True (the default) an explicit *config_path* that
                     does not exist raises. A user who names a file expects
                     its settings applied; silently falling back to
                     defaults means believing settings took effect when
                     they did not.

    Returns:
        Validated configuration dict, fully independent of DEFAULTS.

    Raises:
        ConfigNotFound: *config_path* was given, required, and is missing.
        SystemExit:     the file exists but is not parseable.
    """
    # deepcopy, not dict(): a shallow copy shares enabled_modules and
    # rule_sources with the module-level constant, so both _validate's
    # setdefault calls and any caller mutation would corrupt DEFAULTS for
    # the rest of the process.
    config = copy.deepcopy(DEFAULTS)

    if config_path is not None:
        if not config_path.exists():
            if required:
                raise ConfigNotFound(str(config_path))
            logger.warning("Config file not found at %s — using defaults", config_path)
            _apply_env_overrides(config)
            _validate(config)
            return config
        chosen = config_path
    else:
        chosen = next((p for p in _search_paths() if p.exists()), None)
        if chosen is None:
            logger.warning("No config file found — using defaults")
            _apply_env_overrides(config)
            _validate(config)
            return config

    logger.debug("Loading config from %s", chosen)

    try:
        with chosen.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse config file %s: %s", chosen, exc)
        raise SystemExit(1) from exc
    except OSError as exc:
        logger.error("Could not read config file %s: %s", chosen, exc)
        raise SystemExit(1) from exc

    if loaded and isinstance(loaded, dict):
        config.update(loaded)

    _warn_if_world_readable(chosen, config)
    _apply_env_overrides(config)
    _validate(config)
    return config


def _apply_env_overrides(config: dict) -> None:
    """Overlay environment-supplied secrets on top of the file values.

    The environment wins so a container or CI job can inject a key without
    a writable config file. An exported-but-empty variable is ignored — it
    is a common shell accident and must not silently disable VirusTotal.
    """
    env_key = (os.environ.get(VT_KEY_ENV_VAR) or "").strip()
    if env_key:
        config["virustotal_api_key"] = env_key
        logger.debug("VirusTotal key taken from %s", VT_KEY_ENV_VAR)


def _warn_if_world_readable(path: Path, config: dict) -> None:
    """Warn when a config file holding a credential is readable by others.

    Only fires for files that actually carry a secret — nagging about a
    keyless config would train users to ignore the warning. The value is
    never included in the message.
    """
    if os.name != "posix":
        return
    if not any(str(config.get(k, "")).strip() for k in _SECRET_CONFIG_KEYS):
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return
    if mode & 0o077:
        logger.warning(
            "%s holds an API key but is readable by other users (mode %o). "
            "Restrict it with: chmod 600 %s",
            path,
            mode,
            path,
        )


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
    # bool is a subclass of int, so `module_timeout_seconds: true` would
    # otherwise be accepted as a one-second timeout.
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        logger.warning(
            "Invalid module_timeout_seconds %r — falling back to 60", timeout
        )
        config["module_timeout_seconds"] = 60

    capa_timeout = config.get("capa_timeout_seconds", 120)
    if not isinstance(capa_timeout, (int, float)) or isinstance(
        capa_timeout, bool
    ) or capa_timeout <= 0:
        logger.warning(
            "Invalid capa_timeout_seconds %r — falling back to 120", capa_timeout
        )
        config["capa_timeout_seconds"] = 120

    sources = config.get("rule_sources")
    if sources is not None:
        if not isinstance(sources, list):
            logger.warning("rule_sources must be a list — falling back to defaults")
            config["rule_sources"] = DEFAULTS["rule_sources"]
        else:
            for src in sources:
                if not isinstance(src, dict):
                    continue
                src.setdefault("type", "git")
                src.setdefault("branch", "master")
                src.setdefault("enabled", True)
                src.setdefault("directory", src.get("name", "unknown"))
