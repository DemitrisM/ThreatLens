"""Config loading: search order, validation, and isolation from DEFAULTS."""

import copy

import pytest

from core.config_loader import (
    DEFAULTS,
    ConfigNotFound,
    _validate,
    get_config,
)
from core.pipeline import _MODULE_REGISTRY


# ------------------------------------------------------------------- defaults


def test_defaults_match_the_module_registry():
    assert set(DEFAULTS["enabled_modules"]) == set(_MODULE_REGISTRY)


def test_defaults_carry_every_tuning_key_modules_read():
    """These keys live in config.yaml. Without them in DEFAULTS they vanish
    on the no-config path and modules silently fall back to their own
    hardcoded values."""
    for key in (
        "archive_full_recursion",
        "max_archive_recursion_depth",
        "max_archive_extracted_size_mb",
        "archive_bomb_ratio_threshold",
        "archive_bomb_member_count_threshold",
        "archive_member_mime_check_max_mb",
        "max_onenote_size_mb",
        "max_onenote_blobs",
        "onenote_full_recursion",
        "max_onenote_recursion_depth",
        "max_lnk_size_mb",
        "lnk_ansi_codepage",
    ):
        assert key in DEFAULTS, f"missing tuning key: {key}"


# ------------------------------------------------------------------ isolation


def test_get_config_does_not_alias_defaults(tmp_path):
    """`dict(DEFAULTS)` is shallow — the returned enabled_modules list was
    the *same object* as the module-level constant."""
    config = get_config(tmp_path / "absent.yaml", required=False)
    assert config["enabled_modules"] is not DEFAULTS["enabled_modules"]
    assert config["rule_sources"] is not DEFAULTS["rule_sources"]


def test_mutating_a_returned_config_cannot_corrupt_defaults(tmp_path):
    before = copy.deepcopy(DEFAULTS)
    config = get_config(tmp_path / "absent.yaml", required=False)
    config["enabled_modules"].append("bogus")
    config["rule_sources"][0]["url"] = "http://evil"
    assert DEFAULTS == before


def test_validate_does_not_mutate_defaults_rule_sources(tmp_path):
    """_validate calls setdefault on each rule source; with a shallow copy
    those dicts were DEFAULTS' own objects."""
    before = copy.deepcopy(DEFAULTS["rule_sources"])
    get_config(tmp_path / "absent.yaml", required=False)
    assert DEFAULTS["rule_sources"] == before


# --------------------------------------------------------------- search order


def test_explicit_missing_path_raises(tmp_path):
    """Silently falling back to defaults on an explicit --config means the
    user believes settings applied when they did not."""
    with pytest.raises(ConfigNotFound):
        get_config(tmp_path / "nope.yaml", required=True)


def test_absent_default_path_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = get_config(None)
    assert config["enabled_modules"]


def test_env_var_is_used_when_no_flag_given(tmp_path, monkeypatch):
    cfg = tmp_path / "env.yaml"
    cfg.write_text("log_level: DEBUG\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("THREATLENS_CONFIG", str(cfg))
    assert get_config(None)["log_level"] == "DEBUG"


def test_explicit_flag_beats_the_env_var(tmp_path, monkeypatch):
    env_cfg = tmp_path / "env.yaml"
    env_cfg.write_text("log_level: DEBUG\n")
    flag_cfg = tmp_path / "flag.yaml"
    flag_cfg.write_text("log_level: ERROR\n")
    monkeypatch.setenv("THREATLENS_CONFIG", str(env_cfg))
    assert get_config(flag_cfg)["log_level"] == "ERROR"


def test_cwd_config_beats_the_user_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("THREATLENS_CONFIG", raising=False)
    (tmp_path / "config.yaml").write_text("log_level: ERROR\n")
    home = tmp_path / "home"
    (home / ".config" / "threatlens").mkdir(parents=True)
    (home / ".config" / "threatlens" / "config.yaml").write_text("log_level: DEBUG\n")
    monkeypatch.setenv("HOME", str(home))
    assert get_config(None)["log_level"] == "ERROR"


def test_user_config_is_the_last_resort(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("THREATLENS_CONFIG", raising=False)
    home = tmp_path / "home"
    (home / ".config" / "threatlens").mkdir(parents=True)
    (home / ".config" / "threatlens" / "config.yaml").write_text("log_level: DEBUG\n")
    monkeypatch.setenv("HOME", str(home))
    assert get_config(None)["log_level"] == "DEBUG"


# ------------------------------------------------------------------ validation


def test_missing_explicit_config_never_skips_validation(tmp_path):
    """The old early-return bypassed _validate entirely."""
    cfg = tmp_path / "c.yaml"
    cfg.write_text("dynamic_provider: nonsense\n")
    assert get_config(cfg)["dynamic_provider"] == "none"


def test_capa_timeout_is_validated():
    for bad in (0, -5, "soon", None):
        config = {"capa_timeout_seconds": bad}
        _validate(config)
        assert config["capa_timeout_seconds"] == 240


def test_valid_capa_timeout_survives():
    config = {"capa_timeout_seconds": 240}
    _validate(config)
    assert config["capa_timeout_seconds"] == 240


def test_module_timeout_is_still_validated():
    config = {"module_timeout_seconds": -1}
    _validate(config)
    assert config["module_timeout_seconds"] == 60


def test_malformed_yaml_still_exits(tmp_path):
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("key: [unclosed\n")
    with pytest.raises(SystemExit):
        get_config(cfg)


# ----------------------------------------------------------------------
# DEFAULTS isolation
# ----------------------------------------------------------------------

def test_malformed_rule_sources_does_not_alias_the_defaults(tmp_path):
    """The rule_sources fallback must hand out a copy, not the constant.

    get_config deepcopies DEFAULTS so a caller cannot corrupt the module
    constant for the rest of the process. The fallback for a malformed
    rule_sources assigned DEFAULTS["rule_sources"] directly, which
    reintroduced exactly the aliasing the deepcopy exists to prevent.
    """
    from core import config_loader

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("rule_sources: not-a-list\n", encoding="utf-8")

    original = copy.deepcopy(config_loader.DEFAULTS["rule_sources"])

    config = config_loader.get_config(cfg_file)
    # Mutate what the caller was handed, the way any consumer legitimately might.
    config["rule_sources"].append({"name": "injected", "enabled": True})
    config["rule_sources"][0]["url"] = "https://attacker.example/evil.git"

    assert config_loader.DEFAULTS["rule_sources"] == original, (
        "mutating the returned config corrupted the module-level DEFAULTS"
    )

    # A second, independent load must not see the first caller's mutation.
    second = config_loader.get_config(cfg_file)
    assert second["rule_sources"] == original


# ----------------------------------------------------------------------
# Boolean switches
#
# The failure these cover is not a crash. A quoted YAML scalar is a
# string, a non-empty string is truthy, and every reader in the codebase
# spells `bool(config.get(key, default))` — so `pdf_javascript_execution:
# "false"` armed a V8 context for a user who had just written the word
# false. Nothing logged, and the report's own disclosure agreed with the
# armed state, because it reports what happened rather than what was
# asked for.
# ----------------------------------------------------------------------

def test_the_quoted_false_is_truthy_in_python():
    """The premise the rest of this section rests on.

    Pinned as a test rather than left as a comment because the whole
    design — strict bools, fail-closed execution switches — is only
    justified while this is true, and a reader meeting `_BOOL_KEYS` for
    the first time is entitled to see the reason stated executably.
    """
    assert bool("false") is True
    assert bool("no") is True
    assert bool("off") is True


def test_yaml_spells_the_unquoted_forms_as_real_bools():
    """Which is why only a *quoted* value reaches the validator.

    If YAML handed us strings for these, strictness would reject the
    ordinary spellings and the setting would be unusable.
    """
    import yaml

    parsed = yaml.safe_load(
        "a: false\nb: no\nc: off\nd: true\ne: yes\nf: on\n"
    )
    assert all(isinstance(v, bool) for v in parsed.values())
    assert parsed["a"] is False and parsed["b"] is False and parsed["c"] is False


def test_a_quoted_false_does_not_arm_pdf_javascript(tmp_path):
    """The headline case, end to end through get_config."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text('pdf_javascript_execution: "false"\n', encoding="utf-8")

    config = get_config(cfg)

    assert config["pdf_javascript_execution"] is False, (
        "a quoted false armed JavaScript execution"
    )
    # The point-of-use spelling in pdf_analysis, applied to the validated
    # value. This is the line that was wrong before validation existed.
    assert bool(config.get("pdf_javascript_execution", True)) is False


def test_an_unreadable_execution_switch_fails_closed():
    """Not merely 'falls back' — falls back to OFF.

    Every other key in this module substitutes its default. This one
    cannot: its default is True, so substituting it would answer an
    unreadable value by executing the sample's JavaScript.
    """
    for bad in ("false", "no", "0", 0, 1, None, [], "yes", "please"):
        config = {"pdf_javascript_execution": bad}
        _validate(config)
        assert config["pdf_javascript_execution"] is False, (
            f"{bad!r} did not disarm execution"
        )


def test_a_real_boolean_execution_switch_survives():
    """The fail-closed rule must not quietly disable a switch that was set
    correctly — otherwise the feature is 'execution is always off', which
    would cost the runtime-assembled PDF stages and pass this file's other
    tests just fine."""
    for good in (True, False):
        config = {"pdf_javascript_execution": good}
        _validate(config)
        assert config["pdf_javascript_execution"] is good


def test_ordinary_boolean_keys_fall_back_to_their_default():
    """The non-execution keys keep the module's usual rule."""
    for key in ("floss_emulation", "archive_full_recursion", "onenote_full_recursion"):
        config = {key: "true"}
        _validate(config)
        assert config[key] is DEFAULTS[key], f"{key} did not fall back"


def test_a_quoted_false_does_not_silently_enable_recursion():
    """The same trap on a key whose cost is time rather than safety.

    `archive_full_recursion: "false"` is truthy, so it switched ON the
    full-pipeline walk over every nested member — the opposite of what it
    reads like, and on a setting whose whole purpose is to bound work."""
    config = {"archive_full_recursion": "false"}
    _validate(config)
    assert config["archive_full_recursion"] is False


def test_every_boolean_default_is_actually_a_bool():
    """_BOOL_KEYS is maintained by hand. This catches the case where a
    default changes type and the key silently stops being checked as the
    thing it is."""
    from core.config_loader import _BOOL_KEYS

    for key in _BOOL_KEYS:
        assert key in DEFAULTS, f"{key} is validated but has no default"
        assert isinstance(DEFAULTS[key], bool), f"{key} default is not a bool"


def test_bool_keys_covers_every_boolean_default():
    """The other direction: a boolean added to DEFAULTS without being
    added to _BOOL_KEYS keeps the quoted-string trap."""
    from core.config_loader import _BOOL_KEYS

    boolean_defaults = {k for k, v in DEFAULTS.items() if isinstance(v, bool)}
    assert boolean_defaults <= set(_BOOL_KEYS), (
        f"unvalidated boolean keys: {boolean_defaults - set(_BOOL_KEYS)}"
    )


def test_the_warning_names_the_value_and_says_execution_was_disarmed(caplog):
    """A silent disarm is its own failure: the user asked for something
    the tool could not read, and must be told which way it resolved."""
    import logging

    config = {"pdf_javascript_execution": "false"}
    with caplog.at_level(logging.WARNING, logger="core.config_loader"):
        _validate(config)

    message = caplog.text
    assert "pdf_javascript_execution" in message
    assert "'false'" in message
    assert "execution disarmed" in message
