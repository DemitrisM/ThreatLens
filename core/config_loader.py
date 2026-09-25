"""Configuration loader — reads and validates config.yaml.

Provides a single get_config() entry point that returns a validated
configuration dict with sensible defaults for any missing keys.

Design notes
------------
Every key the tool reads is present in ``DEFAULTS``, so the no-config path
behaves identically to a config file that happens to match the defaults. A
key that exists only in the shipped ``config.yaml`` would vanish for users
without one, and each module would silently fall back to its own literal.

Validation never rejects. A bad value is logged and replaced with the
default, because a typo in one tuning key must not stop an analyst scanning
a sample. The one exception is an unparseable file, which is a mistake the
user needs to see immediately.

This module raises its own exception types rather than ``click`` ones so
``core/`` carries no dependency on the CLI framework.
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

# ----------------------------------------------------------------------
# Default configuration.
#
# This is the complete set of keys the tool reads — see the module
# docstring for why partial defaults are not acceptable. Never mutate this
# dict; get_config() hands out deep copies precisely so callers cannot.
# ----------------------------------------------------------------------
DEFAULTS = {
    "virustotal_api_key": "",
    "yara_rules_dir": "./rules/yara",
    "floss_binary": "./bin/floss",
    "capa_binary": "./bin/capa",
    "output_dir": "./reports",
    # WARNING, not INFO: the shipped config.yaml and every doc say WARNING,
    # and only the no-config path ever saw INFO — so a user without a
    # config file got a chattier tool than the documentation promised.
    "log_level": "WARNING",
    "module_timeout_seconds": 60,
    "capa_timeout_seconds": 120,
    # FLOSS gets its own budget rather than the generic one. 300s is
    # measured, not copied: the slowest of the 30 corpus PEs emulated in
    # 271.1s, so 300 covers all of them. It is also harmless on the
    # standard profile, where `--only static` finishes in about a second —
    # which is why there is no per-profile override and no floor logic
    # fighting a value the user set deliberately.
    "floss_timeout_seconds": 300,
    # Emulation off by default. Measured over those 30 samples it costs
    # 26x wall clock and produced zero suspicious-category matches; what it
    # does buy is the +10 structural bonus on 13 of them. That is a cost
    # decision, so it lives on the -p axis and `deep` turns it on.
    "floss_emulation": False,
    # Mirrors _MODULE_REGISTRY in core/pipeline.py, in execution order.
    # Order matters: virustotal trails archive_analysis so it can look up
    # the hashes archive extraction surfaced.
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
        "lnk_analysis",
        "virustotal",
    ],
    "dynamic_provider": "none",
    # archive_analysis tuning — these live in config.yaml and are read by
    # the module at runtime. Without them here they vanish on the
    # no-config path and each module falls back to its own literal.
    "archive_full_recursion": False,
    "max_archive_recursion_depth": 3,
    # A whole-tree budget, not per-archive: the cap is what stops a nested
    # zip bomb from filling the disk one small archive at a time.
    "max_archive_extracted_size_mb": 500,
    "archive_bomb_ratio_threshold": 100,
    "archive_bomb_member_count_threshold": 1000,
    "archive_member_mime_check_max_mb": 10,
    # onenote_analysis tuning
    "max_onenote_size_mb": 50,
    "max_onenote_blobs": 200,
    "onenote_full_recursion": False,
    "max_onenote_recursion_depth": 2,
    # file_intake tuning. Ceiling for the pure-Python ppdeep fallback
    # only; the C ssdeep extension is ~100x faster and stays uncapped.
    # Past this size the fuzzy hash is skipped with a warning rather than
    # stalling the scan — ppdeep costs 0.78-4.4 s/MB depending on how
    # often ssdeep has to halve its blocksize and rescan.
    "max_ppdeep_size_mb": 8,
    # lnk_analysis tuning. The size cap is deliberately tight — a shell
    # link past a few hundred KiB is carrying a payload, and the overlay
    # carve records it without parsing megabytes.
    "max_lnk_size_mb": 10,
    # StringData is UTF-16LE when LinkFlags.IsUnicode is set; otherwise it
    # is the *system default codepage* of the machine that built the file,
    # which is not recoverable from the file itself.
    "lnk_ansi_codepage": "cp1252",
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

# Allow-lists for the two enumerated settings. Anything outside these is
# replaced with the default rather than rejected — see _validate().
VALID_DYNAMIC_PROVIDERS = {"none", "speakeasy", "vm_worker", "cape"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _search_paths() -> list[Path]:
    """Config locations to try, in clig.dev precedence order.

    Returns:
        Paths to try in order, most specific first: the environment
        variable, then the working directory, then the per-user config
        directory. ``--config`` is not represented here because an
        explicit path bypasses the search entirely.
    """
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
    # ------------------------------------------------------------------
    # Step 1: Start from an independent copy of the defaults.
    # ------------------------------------------------------------------
    # deepcopy, not dict(): a shallow copy shares enabled_modules and
    # rule_sources with the module-level constant, so both _validate's
    # setdefault calls and any caller mutation would corrupt DEFAULTS for
    # the rest of the process.
    config = copy.deepcopy(DEFAULTS)

    # ------------------------------------------------------------------
    # Step 2: Decide which file to read, if any.
    #
    # Three outcomes: an explicit path (honoured or raised on), a search
    # hit, or nothing at all. The two no-file paths still run the env
    # overlay and validation before returning, so every exit from this
    # function yields a config that has been through the same treatment.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 3: Parse it.
    #
    # safe_load, never load: a config file is untrusted input as far as
    # arbitrary object construction is concerned. Unlike a bad *value*, an
    # unparseable *file* is fatal — the user asked for settings that
    # cannot be applied, and continuing would hide that.
    # ------------------------------------------------------------------
    try:
        with chosen.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse config file %s: %s", chosen, exc)
        raise SystemExit(1) from exc
    except OSError as exc:
        logger.error("Could not read config file %s: %s", chosen, exc)
        raise SystemExit(1) from exc

    # An empty file parses to None, which is a legitimate "use defaults".
    if loaded and isinstance(loaded, dict):
        config.update(loaded)

    # ------------------------------------------------------------------
    # Step 4: Post-process, in a fixed order that matters.
    #
    # The permission check runs before the env overlay so it judges the
    # file's own contents — a key supplied by the environment says nothing
    # about whether the file on disk is safe.
    # ------------------------------------------------------------------
    _warn_if_world_readable(chosen, config)
    _apply_env_overrides(config)
    _validate(config)
    return config


def _apply_env_overrides(config: dict) -> None:
    """Overlay environment-supplied secrets on top of the file values.

    The environment wins so a container or CI job can inject a key without
    a writable config file. An exported-but-empty variable is ignored — it
    is a common shell accident and must not silently disable VirusTotal.

    Args:
        config: The config dict, mutated in place.
    """
    env_key = (os.environ.get(VT_KEY_ENV_VAR) or "").strip()
    if env_key:
        config["virustotal_api_key"] = env_key
        # Logs that the key was *sourced*, never the key itself.
        logger.debug("VirusTotal key taken from %s", VT_KEY_ENV_VAR)


def _warn_if_world_readable(path: Path, config: dict) -> None:
    """Warn when a config file holding a credential is readable by others.

    Only fires for files that actually carry a secret — nagging about a
    keyless config would train users to ignore the warning. The value is
    never included in the message.

    Args:
        path:   The config file that was read.
        config: The parsed config, inspected for credential keys.
    """
    # POSIX mode bits are meaningless on Windows, where the equivalent
    # check is an ACL query this tool does not attempt.
    if os.name != "posix":
        return
    if not any(str(config.get(k, "")).strip() for k in _SECRET_CONFIG_KEYS):
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        # A permission check that cannot run is not worth failing over.
        return
    # 0o077 covers every group and other bit: any access at all by anyone
    # but the owner is too much for a file holding an API key.
    if mode & 0o077:
        logger.warning(
            "%s holds an API key but is readable by other users (mode %o). "
            "Restrict it with: chmod 600 %s",
            path,
            mode,
            path,
        )


def _validate(config: dict) -> None:
    """Apply sanity checks and normalise values in-place.

    Every check follows the same shape: detect a bad value, warn naming
    both the value and its replacement, then substitute the default. No
    check raises — a typo in one tuning key must not stop a scan.

    Args:
        config: The config dict, mutated in place.
    """
    # ------------------------------------------------------------------
    # Step 1: Enumerated values, checked against their allow-lists.
    # ------------------------------------------------------------------
    provider = config.get("dynamic_provider", "none")
    if provider not in VALID_DYNAMIC_PROVIDERS:
        logger.warning(
            "Unknown dynamic_provider %r — falling back to 'none'", provider
        )
        config["dynamic_provider"] = "none"

    # Normalised to upper case unconditionally so `log_level: debug` in a
    # hand-written config reaches the logging module in the form it wants.
    log_level = str(config.get("log_level", "INFO")).upper()
    if log_level not in VALID_LOG_LEVELS:
        logger.warning(
            "Unknown log_level %r — falling back to 'INFO'", log_level
        )
        log_level = "INFO"
    config["log_level"] = log_level

    # ------------------------------------------------------------------
    # Step 2: Numeric timeouts.
    # ------------------------------------------------------------------
    timeout = config.get("module_timeout_seconds", 60)
    # bool is a subclass of int, so `module_timeout_seconds: true` would
    # otherwise be accepted as a one-second timeout.
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        logger.warning(
            "Invalid module_timeout_seconds %r — falling back to 60", timeout
        )
        config["module_timeout_seconds"] = 60

    # Same three-part guard as above: right type, not a bool, positive.
    capa_timeout = config.get("capa_timeout_seconds", 120)
    if not isinstance(capa_timeout, (int, float)) or isinstance(
        capa_timeout, bool
    ) or capa_timeout <= 0:
        logger.warning(
            "Invalid capa_timeout_seconds %r — falling back to 120", capa_timeout
        )
        config["capa_timeout_seconds"] = 120

    # Same three-part guard again.
    floss_timeout = config.get("floss_timeout_seconds", 300)
    if not isinstance(floss_timeout, (int, float)) or isinstance(
        floss_timeout, bool
    ) or floss_timeout <= 0:
        logger.warning(
            "Invalid floss_timeout_seconds %r — falling back to 300", floss_timeout
        )
        config["floss_timeout_seconds"] = 300

    # ------------------------------------------------------------------
    # Step 3: rule_sources, the one structured setting.
    #
    # Per-source defaults are filled with setdefault so a user can name
    # just a URL and get a working source. Non-dict entries are skipped
    # rather than repaired: there is no sane default for a source that is
    # not even a mapping.
    # ------------------------------------------------------------------
    sources = config.get("rule_sources")
    if sources is not None:
        if not isinstance(sources, list):
            logger.warning("rule_sources must be a list — falling back to defaults")
            # deepcopy, not the constant itself. Assigning DEFAULTS'
            # own list here would alias it into the returned config and
            # undo the deepcopy at the top of get_config — a caller
            # mutating config["rule_sources"] would then rewrite the
            # module constant, and every later load in the process would
            # inherit the change.
            config["rule_sources"] = copy.deepcopy(DEFAULTS["rule_sources"])
        else:
            for src in sources:
                if not isinstance(src, dict):
                    continue
                src.setdefault("type", "git")
                src.setdefault("branch", "master")
                src.setdefault("enabled", True)
                src.setdefault("directory", src.get("name", "unknown"))
