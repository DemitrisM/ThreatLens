"""VirusTotal credential handling.

The key used to be reachable only from a file on disk. It can now come
from the environment, which is what makes a container run possible
without baking a secret into an image layer.

Deliberately **no `--vt-key` flag**: an argv secret is visible to every
user on the host via `ps`/`/proc/PID/cmdline` and is recorded in shell
history, and it helps with neither Docker path (mounted config or
env-file). See docs/superpowers/specs for the reasoning.
"""

import json
import os
import stat

import pytest

from core.config_loader import VT_KEY_ENV_VAR, get_config


def write_config(path, body: str):
    path.write_text(body)
    path.chmod(0o600)
    return path


# ------------------------------------------------------------ env precedence


def test_env_var_supplies_the_key_with_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("THREATLENS_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(VT_KEY_ENV_VAR, "k" * 64)
    assert get_config(None)["virustotal_api_key"] == "k" * 64


def test_env_var_overrides_the_config_file(tmp_path, monkeypatch):
    cfg = write_config(tmp_path / "c.yaml", 'virustotal_api_key: "from_file"\n')
    monkeypatch.setenv(VT_KEY_ENV_VAR, "from_env")
    assert get_config(cfg)["virustotal_api_key"] == "from_env"


def test_config_file_is_used_when_env_is_unset(tmp_path, monkeypatch):
    cfg = write_config(tmp_path / "c.yaml", 'virustotal_api_key: "from_file"\n')
    monkeypatch.delenv(VT_KEY_ENV_VAR, raising=False)
    assert get_config(cfg)["virustotal_api_key"] == "from_file"


def test_empty_env_var_does_not_clobber_the_config_file(tmp_path, monkeypatch):
    """An exported-but-empty variable is a common shell accident."""
    cfg = write_config(tmp_path / "c.yaml", 'virustotal_api_key: "from_file"\n')
    monkeypatch.setenv(VT_KEY_ENV_VAR, "")
    assert get_config(cfg)["virustotal_api_key"] == "from_file"


def test_whitespace_env_var_does_not_clobber_the_config_file(tmp_path, monkeypatch):
    cfg = write_config(tmp_path / "c.yaml", 'virustotal_api_key: "from_file"\n')
    monkeypatch.setenv(VT_KEY_ENV_VAR, "   ")
    assert get_config(cfg)["virustotal_api_key"] == "from_file"


def test_env_var_is_stripped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(VT_KEY_ENV_VAR, "  spaced_key  ")
    assert get_config(None)["virustotal_api_key"] == "spaced_key"


# ------------------------------------------------------- no flag on the CLI


@pytest.mark.parametrize("verb", ["scan", "triage", "compare"])
def test_no_verb_exposes_a_key_flag(verb):
    """A credential must never be passable on argv."""
    from cli import cli as cli_group

    names = {p.name for p in cli_group.commands[verb].params}
    assert "vt_key" not in names
    for param in cli_group.commands[verb].params:
        for opt in getattr(param, "opts", []):
            assert "key" not in opt.lower(), f"{verb} exposes {opt}"


# ------------------------------------------------------- permission warning


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_world_readable_config_holding_a_key_warns(tmp_path, caplog):
    cfg = tmp_path / "c.yaml"
    cfg.write_text('virustotal_api_key: "secret"\n')
    cfg.chmod(0o644)
    with caplog.at_level("WARNING"):
        get_config(cfg)
    assert any("readable" in r.message.lower() for r in caplog.records)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_the_warning_never_prints_the_key(tmp_path, caplog):
    cfg = tmp_path / "c.yaml"
    cfg.write_text('virustotal_api_key: "SUPERSECRETVALUE"\n')
    cfg.chmod(0o644)
    with caplog.at_level("WARNING"):
        get_config(cfg)
    assert "SUPERSECRETVALUE" not in caplog.text


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_private_config_does_not_warn(tmp_path, caplog):
    cfg = write_config(tmp_path / "c.yaml", 'virustotal_api_key: "secret"\n')
    with caplog.at_level("WARNING"):
        get_config(cfg)
    assert not any("readable" in r.message.lower() for r in caplog.records)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_keyless_config_does_not_warn_about_permissions(tmp_path, caplog):
    """Only a file actually holding a secret is worth nagging about."""
    cfg = tmp_path / "c.yaml"
    cfg.write_text("log_level: DEBUG\n")
    cfg.chmod(0o644)
    with caplog.at_level("WARNING"):
        get_config(cfg)
    assert not any("readable" in r.message.lower() for r in caplog.records)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_permission_check_reports_the_mode(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text('virustotal_api_key: "s"\n')
    cfg.chmod(0o644)
    assert stat.S_IMODE(cfg.stat().st_mode) & 0o077


# --------------------------------------------------- the key never escapes


SECRET = "z" * 64


def report_with_key():
    return {
        "file": "/samples/x.exe",
        "module_results": [
            {
                "module": "virustotal",
                "status": "success",
                "data": {"found": True, "request": {"api_key": SECRET}},
                "score_delta": 10,
                "reason": "",
            }
        ],
        "scoring": {"total_score": 10, "risk_band": "LOW", "breakdown": []},
        "timing": {"total_seconds": 1.0},
        "dynamic": None,
    }


def test_key_absent_from_json_output():
    from reporting.json_reporter import build_json_report

    assert SECRET not in json.dumps(build_json_report(report_with_key()), default=str)


def test_key_absent_from_every_terminal_detail_level():
    from tests.conftest import render_report

    for detail in (0, 1, 2):
        assert SECRET not in render_report(report_with_key(), detail)


def test_key_absent_from_html_output(tmp_path):
    from reporting.html_reporter import write_html_report

    assert SECRET not in write_html_report(report_with_key(), tmp_path).read_text()
