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
        assert config["capa_timeout_seconds"] == 120


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
