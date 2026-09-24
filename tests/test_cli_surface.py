"""Tests for the Pass 1 command surface.

Covers what the redesign actually promises, rather than the internals of the
analysis modules: four verbs, a bounded flag set per verb, usage errors that
point at the right verb, machine formats that land on stdout alone, and exit
codes that a CI pipeline can branch on.

The pipeline itself is always stubbed — these tests must stay fast and must
never touch the network or a real sample.
"""

import importlib
import json
from pathlib import Path
from unittest import mock

import click
import pytest
from click.testing import CliRunner

import cli
from cli import cli as cli_group
from cli._exit import EXIT_OK, EXIT_RUNTIME, EXIT_THREAT, EXIT_USAGE

#: ``cli.scan`` &c. resolve to the *command* objects re-exported by
#: ``cli/__init__.py``, so patching has to go through the module objects.
VERB_MODULES = {
    name: importlib.import_module(f"cli.{name}")
    for name in ("scan", "triage", "compare", "rules")
}

# ── Fixtures and helpers ────────────────────────────────────────────


def make_runner() -> CliRunner:
    """Return a runner that captures stdout and stderr separately.

    Click 8.1 needs ``mix_stderr=False`` for that; 8.2 removed the argument
    and separates the streams unconditionally. Note that on 8.2+
    ``Result.output`` is the *interleaved* pair — stream-discipline assertions
    must go through :func:`stdout_of`.
    """
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:  # pragma: no cover — Click >= 8.2
        return CliRunner()


def stdout_of(result) -> str:
    """Return a result's stdout only, on either Click stream model."""
    return result.stdout


def stderr_of(result) -> str:
    """Return a result's stderr, tolerating either Click stream model."""
    try:
        return result.stderr
    except ValueError:  # pragma: no cover — streams were mixed
        return ""


def fake_report(path, *, score: int = 70, band: str = "HIGH") -> dict:
    """A minimal report shaped like ``run_pipeline``'s return value."""
    return {
        "file": str(path),
        "module_results": [
            {
                "module": "file_intake",
                "status": "success",
                # Keys mirror core.file_intake exactly — the terminal
                # reporter treats file_type as a dict, not a string.
                "data": {
                    "file_name": Path(path).name,
                    "file_path": str(path),
                    "file_size": 1024,
                    "file_type": {
                        "mime_type": "application/x-dosexec",
                        "description": "PE32 executable (GUI) Intel 80386",
                    },
                    "hashes": {
                        "md5": "0" * 32,
                        "sha256": "0" * 64,
                        "tlsh": "T1" + "0" * 68,
                        "ssdeep": "3:abc:def",
                    },
                },
                "score_delta": 0,
                "reason": "metadata only",
                "elapsed_seconds": 0.01,
            },
            {
                "module": "virustotal",
                "status": "success",
                # A credential smuggled into module data must never be
                # serialised — see reporting.json_reporter._sanitise_results.
                "data": {"detections": 65, "virustotal_api_key": "SECRET"},
                "score_delta": score,
                "reason": "65/75 engines flagged the sample",
                "elapsed_seconds": 0.02,
            },
        ],
        "scoring": {
            "total_score": score,
            "risk_band": band,
            "breakdown": [{"module": "virustotal", "score_delta": score, "reason": "VT"}],
        },
        "timing": {"elapsed_seconds": 0.03, "per_module": {}},
        "dynamic": None,
    }


@pytest.fixture
def stub_config(monkeypatch):
    """Neutralise config loading so tests never read the real config.yaml."""

    def _fake_get_config(_path=None):
        return {
            "log_level": "WARNING",
            "enabled_modules": ["file_intake", "virustotal"],
            "output_dir": "./reports",
            "module_timeout_seconds": 60,
            "capa_timeout_seconds": 120,
        }

    for module in VERB_MODULES.values():
        monkeypatch.setattr(module, "get_config", _fake_get_config)
    return _fake_get_config


@pytest.fixture
def stub_pipeline(monkeypatch):
    """Replace ``run_pipeline`` in every verb with a scriptable stub.

    Returns a setter: call it with a function ``(file, config, **kw) -> dict``
    (or one that raises) to control what the verbs see.
    """

    def _install(func):
        for name in ("scan", "triage", "compare"):
            monkeypatch.setattr(VERB_MODULES[name], "run_pipeline", func)

    _install(lambda file, config, **kw: fake_report(file))
    return _install


@pytest.fixture
def sample(tmp_path):
    """A file that exists — enough for ``click.Path(exists=True)``."""
    path = tmp_path / "suspicious.exe"
    path.write_bytes(b"MZ" + b"\x00" * 128)
    return path


# ── Group wiring ────────────────────────────────────────────────────


def test_group_exposes_exactly_the_four_verbs():
    visible = {
        name
        for name, command in cli_group.commands.items()
        if not command.hidden
    }
    assert visible == {"scan", "triage", "compare", "rules"}


def test_short_help_flag_works():
    result = make_runner().invoke(cli_group, ["-h"])
    assert result.exit_code == EXIT_OK
    assert "scan" in stdout_of(result)


def test_help_wraps_at_a_fixed_width_not_the_terminal_width():
    assert cli.CONTEXT_SETTINGS["max_content_width"] == 100
    assert cli.CONTEXT_SETTINGS["help_option_names"] == ["-h", "--help"]


def test_version_reports_the_single_sourced_version():
    result = make_runner().invoke(cli_group, ["--version"])
    assert result.exit_code == EXIT_OK
    assert cli.__version__ in stdout_of(result)


@pytest.mark.parametrize("verb", ["scan", "triage", "compare"])
def test_no_verb_exceeds_nine_options(verb):
    command = cli_group.commands[verb]
    options = [p for p in command.params if not isinstance(p, click.Argument)]
    assert len(options) <= 9, f"{verb} has {len(options)} options"


def test_rules_update_stays_within_the_option_budget():
    update = cli_group.commands["rules"].commands["update"]
    options = [p for p in update.params if not isinstance(p, click.Argument)]
    assert len(options) <= 9


@pytest.mark.parametrize("verb", ["scan", "triage", "compare"])
def test_every_option_is_documented(verb):
    command = cli_group.commands[verb]
    undocumented = [
        p.name
        for p in command.params
        if isinstance(p, click.Option) and not p.help
    ]
    assert undocumented == []


# ── Usage errors (exit 2) ───────────────────────────────────────────


def test_removed_analyse_verb_points_at_both_replacements():
    result = make_runner().invoke(cli_group, ["analyse", "whatever.exe"])
    assert result.exit_code == EXIT_USAGE
    message = stdout_of(result) + stderr_of(result)
    assert "scan" in message and "triage" in message


def test_scan_rejects_a_directory_and_names_triage(tmp_path, stub_config):
    result = make_runner().invoke(cli_group, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_USAGE
    assert "triage" in stdout_of(result) + stderr_of(result)


def test_triage_rejects_a_file_and_names_scan(sample, stub_config):
    result = make_runner().invoke(cli_group, ["triage", str(sample)])
    assert result.exit_code == EXIT_USAGE
    assert "scan" in stdout_of(result) + stderr_of(result)


def test_text_format_cannot_be_redirected_to_a_file(sample, tmp_path, stub_config):
    result = make_runner().invoke(
        cli_group, ["scan", str(sample), "-o", str(tmp_path / "r.txt")]
    )
    assert result.exit_code == EXIT_USAGE


def test_unknown_flag_is_a_usage_error(sample):
    result = make_runner().invoke(cli_group, ["scan", str(sample), "--bogus"])
    assert result.exit_code == EXIT_USAGE


def test_missing_file_is_a_usage_error(tmp_path):
    result = make_runner().invoke(cli_group, ["scan", str(tmp_path / "nope.exe")])
    assert result.exit_code == EXIT_USAGE


def test_check_and_force_are_mutually_exclusive(stub_config):
    result = make_runner().invoke(cli_group, ["rules", "update", "--check", "--force"])
    assert result.exit_code == EXIT_USAGE
    assert "mutually exclusive" in stdout_of(result) + stderr_of(result)


def test_invalid_profile_is_a_usage_error(sample, stub_config):
    result = make_runner().invoke(cli_group, ["scan", str(sample), "-p", "turbo"])
    assert result.exit_code == EXIT_USAGE


# ── Machine output and stream discipline ────────────────────────────


def test_json_format_puts_parseable_json_on_stdout(sample, stub_config, stub_pipeline):
    result = make_runner().invoke(cli_group, ["scan", str(sample), "-f", "json"])
    assert result.exit_code == EXIT_OK, stdout_of(result)

    payload = json.loads(stdout_of(result))
    assert payload["meta"]["tool"] == "ThreatLens"
    assert payload["meta"]["version"] == cli.__version__
    assert payload["scoring"]["total_score"] == 70


def test_json_output_never_leaks_the_api_key(sample, stub_config, stub_pipeline):
    result = make_runner().invoke(cli_group, ["scan", str(sample), "-f", "json"])
    assert "SECRET" not in stdout_of(result)
    assert "virustotal_api_key" not in stdout_of(result)


def test_jsonl_is_a_single_line(sample, stub_config, stub_pipeline):
    result = make_runner().invoke(cli_group, ["scan", str(sample), "-f", "jsonl"])
    lines = stdout_of(result).strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["scoring"]["risk_band"] == "HIGH"


def test_diagnostics_stay_off_stdout(sample, tmp_path, stub_config, stub_pipeline):
    """``-o`` writes the report; the "written to" notice must go to stderr."""
    target = tmp_path / "out" / "report.json"
    result = make_runner().invoke(
        cli_group, ["scan", str(sample), "-f", "json", "-o", str(target)]
    )
    assert result.exit_code == EXIT_OK, stdout_of(result)
    assert stdout_of(result).strip() == ""
    assert json.loads(target.read_text())["scoring"]["total_score"] == 70


def test_text_format_renders_without_crashing(sample, stub_config, stub_pipeline):
    result = make_runner().invoke(cli_group, ["scan", str(sample)])
    assert result.exit_code == EXIT_OK, stdout_of(result) + stderr_of(result)
    assert "HIGH" in stdout_of(result)


def test_hash_only_prints_hashes_and_skips_analysis(sample, stub_config, stub_pipeline):
    result = make_runner().invoke(cli_group, ["scan", str(sample), "--hash-only"])
    assert result.exit_code == EXIT_OK, stdout_of(result)
    assert "SHA256:" in stdout_of(result)
    assert "Threat Score" not in stdout_of(result)


def test_hash_only_supports_json(sample, stub_config, stub_pipeline):
    result = make_runner().invoke(
        cli_group, ["scan", str(sample), "--hash-only", "-f", "json"]
    )
    assert result.exit_code == EXIT_OK, stdout_of(result)
    assert json.loads(stdout_of(result))["hashes"]["sha256"] == "0" * 64


# ── Exit codes ──────────────────────────────────────────────────────


def test_no_fail_on_always_exits_zero(sample, stub_config, stub_pipeline):
    result = make_runner().invoke(cli_group, ["scan", str(sample), "-f", "json"])
    assert result.exit_code == EXIT_OK


def test_fail_on_trips_when_the_band_reaches_the_threshold(
    sample, stub_config, stub_pipeline
):
    result = make_runner().invoke(
        cli_group, ["scan", str(sample), "-f", "json", "--fail-on", "HIGH"]
    )
    assert result.exit_code == EXIT_THREAT
    # The report is still emitted — the caller gets data *and* a verdict.
    assert json.loads(stdout_of(result))["scoring"]["risk_band"] == "HIGH"


def test_fail_on_stays_quiet_below_the_threshold(sample, stub_config, stub_pipeline):
    stub_pipeline(lambda file, config, **kw: fake_report(file, score=10, band="LOW"))
    result = make_runner().invoke(
        cli_group, ["scan", str(sample), "-f", "json", "--fail-on", "MEDIUM"]
    )
    assert result.exit_code == EXIT_OK


def test_pipeline_failure_exits_three_without_a_traceback(
    sample, stub_config, stub_pipeline
):
    def _boom(file, config, **kw):
        raise RuntimeError("libmagic exploded")

    stub_pipeline(_boom)
    result = make_runner().invoke(cli_group, ["scan", str(sample), "-f", "json"])
    assert result.exit_code == EXIT_RUNTIME
    assert "Traceback" not in stdout_of(result) + stderr_of(result)
    assert "libmagic exploded" in stdout_of(result) + stderr_of(result)


def test_unwritable_output_exits_three(sample, stub_config, stub_pipeline):
    result = make_runner().invoke(
        cli_group,
        ["scan", str(sample), "-f", "json", "-o", "/proc/definitely/not/here.json"],
    )
    assert result.exit_code == EXIT_RUNTIME
    assert "Traceback" not in stdout_of(result) + stderr_of(result)


# ── triage ──────────────────────────────────────────────────────────


@pytest.fixture
def sample_dir(tmp_path):
    """Two files at the top level, one nested, one dotfile."""
    (tmp_path / "a.exe").write_bytes(b"MZ\x00")
    (tmp_path / "b.exe").write_bytes(b"MZ\x01")
    (tmp_path / ".hidden.exe").write_bytes(b"MZ\x02")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "c.exe").write_bytes(b"MZ\x03")
    return tmp_path


def test_triage_jsonl_emits_one_line_per_file_and_no_chrome(
    sample_dir, stub_config, stub_pipeline
):
    result = make_runner().invoke(cli_group, ["triage", str(sample_dir), "-f", "jsonl"])
    assert result.exit_code == EXIT_OK, stdout_of(result) + stderr_of(result)

    lines = stdout_of(result).strip().splitlines()
    assert len(lines) == 2  # a.exe, b.exe — dotfile and subdirectory excluded
    names = {json.loads(line)["file"].rsplit("/", 1)[-1] for line in lines}
    assert names == {"a.exe", "b.exe"}
    assert "Triage Summary" not in stdout_of(result)


def test_triage_recursive_descends_but_still_skips_dotfiles(
    sample_dir, stub_config, stub_pipeline
):
    result = make_runner().invoke(
        cli_group, ["triage", str(sample_dir), "-r", "-f", "jsonl"]
    )
    assert result.exit_code == EXIT_OK
    names = {
        json.loads(line)["file"].rsplit("/", 1)[-1]
        for line in stdout_of(result).strip().splitlines()
    }
    assert names == {"a.exe", "b.exe", "c.exe"}


def test_triage_json_emits_one_array(sample_dir, stub_config, stub_pipeline):
    result = make_runner().invoke(cli_group, ["triage", str(sample_dir), "-f", "json"])
    payload = json.loads(stdout_of(result))
    assert isinstance(payload, list)
    assert len(payload) == 2


def test_triage_min_score_hides_quiet_files(sample_dir, stub_config, stub_pipeline):
    scores = iter([80, 10])

    def _varying(file, config, **kw):
        score = next(scores)
        return fake_report(file, score=score, band="HIGH" if score > 55 else "LOW")

    stub_pipeline(_varying)
    result = make_runner().invoke(
        cli_group, ["triage", str(sample_dir), "-f", "jsonl", "--min-score", "50"]
    )
    assert len(stdout_of(result).strip().splitlines()) == 1


def test_triage_exits_three_when_a_file_fails(sample_dir, stub_config, stub_pipeline):
    calls = iter([True, False])

    def _flaky(file, config, **kw):
        if next(calls):
            raise RuntimeError("unreadable")
        return fake_report(file)

    stub_pipeline(_flaky)
    result = make_runner().invoke(cli_group, ["triage", str(sample_dir), "-f", "jsonl"])
    assert result.exit_code == EXIT_RUNTIME


def test_runtime_failure_outranks_a_threat_verdict(
    sample_dir, stub_config, stub_pipeline
):
    calls = iter([True, False])

    def _flaky(file, config, **kw):
        if next(calls):
            raise RuntimeError("unreadable")
        return fake_report(file, score=99, band="CRITICAL")

    stub_pipeline(_flaky)
    result = make_runner().invoke(
        cli_group, ["triage", str(sample_dir), "-f", "jsonl", "--fail-on", "LOW"]
    )
    assert result.exit_code == EXIT_RUNTIME


def test_triage_fail_on_trips_on_any_file(sample_dir, stub_config, stub_pipeline):
    scores = iter([10, 90])

    def _varying(file, config, **kw):
        score = next(scores)
        return fake_report(file, score=score, band="LOW" if score < 30 else "CRITICAL")

    stub_pipeline(_varying)
    result = make_runner().invoke(
        cli_group, ["triage", str(sample_dir), "-f", "jsonl", "--fail-on", "HIGH"]
    )
    assert result.exit_code == EXIT_THREAT


def test_triage_on_an_empty_directory_is_not_an_error(tmp_path, stub_config):
    result = make_runner().invoke(cli_group, ["triage", str(tmp_path), "-f", "jsonl"])
    assert result.exit_code == EXIT_OK
    assert stdout_of(result).strip() == ""
    assert "No files found" in stderr_of(result)


def test_triage_isolates_config_between_files(sample_dir, stub_config, stub_pipeline):
    """One file's module bookkeeping must not leak into the next file's run."""
    seen: list[int] = []

    def _record(file, config, **kw):
        seen.append(len(config.get("_module_results_so_far", [])))
        config["_module_results_so_far"] = ["polluted"]
        return fake_report(file)

    stub_pipeline(_record)
    make_runner().invoke(cli_group, ["triage", str(sample_dir), "-f", "jsonl"])
    assert seen == [0, 0]


def test_min_score_does_not_suppress_fail_on(sample_dir, stub_config, stub_pipeline):
    """A display filter must not decide the exit code.

    `--min-score` is documented as hiding files from the output. It was
    applied before the reports list was built, so a hidden file was also
    invisible to `--fail-on` — and `triage --min-score 90 --fail-on HIGH`
    exited 0 on a directory holding a HIGH file, which is the exact
    invocation a CI gate would use to catch one.
    """
    scores = iter([60, 10])

    def _varying(file, config, **kw):
        score = next(scores)
        return fake_report(file, score=score, band="HIGH" if score > 55 else "LOW")

    stub_pipeline(_varying)
    result = make_runner().invoke(
        cli_group,
        ["triage", str(sample_dir), "-f", "jsonl",
         "--min-score", "90", "--fail-on", "HIGH"],
    )

    assert stdout_of(result).strip() == "", "the file should still be hidden"
    assert result.exit_code == EXIT_THREAT


def test_min_score_does_not_shrink_the_reported_sweep_time(
    sample_dir, stub_config, stub_pipeline, monkeypatch
):
    """The time was spent whether or not the row was printed.

    `--min-score` filters the table; summing the printed rows' timings
    reported a fraction of the real cost, which is the number a user
    reads to decide whether a sweep is affordable.
    """
    import cli.triage as triage_mod

    scores = iter([80, 10])

    def _varying(file, config, **kw):
        score = next(scores)
        report = fake_report(file, score=score, band="HIGH" if score > 55 else "LOW")
        report["timing"] = {"start": 0.0, "end": 4.0, "elapsed_seconds": 4.0}
        return report

    stub_pipeline(_varying)

    seen: dict[str, float] = {}

    def _spy(reports, failures, elapsed, console):
        seen["elapsed"] = elapsed

    monkeypatch.setattr(
        "reporting.triage_reporter.print_triage_table",
        lambda reports, failures, elapsed, console: _spy(
            reports, failures, elapsed, console
        ),
    )

    make_runner().invoke(
        cli_group, ["triage", str(sample_dir), "--min-score", "50"]
    )

    assert seen["elapsed"] == 8.0, "both files were analysed"


# ── --hash-only ─────────────────────────────────────────────────────


def test_hash_only_does_not_reach_the_dynamic_provider(sample, stub_config):
    """Restricting `enabled_modules` does not restrict detonation.

    The dynamic provider is gated by `config["dynamic_provider"]` alone,
    entirely independently of `enabled_modules`. `--hash-only` set the
    module list and left that key untouched, so a config naming a provider
    would have detonated the sample for a request that only ever wanted
    four hashes. Harmless while every provider is a stub, and a live one
    is the point at which it stops being harmless.
    """
    seen: dict[str, object] = {}

    def _spy(file, config, **kw):
        seen["provider"] = config.get("dynamic_provider")
        seen["modules"] = list(config.get("enabled_modules", []))
        return fake_report(file)

    scan_mod = importlib.import_module("cli.scan")

    with mock.patch.object(scan_mod, "run_pipeline", _spy):
        result = make_runner().invoke(
            cli_group, ["scan", str(sample), "--hash-only"]
        )

    assert result.exit_code == EXIT_OK, stdout_of(result)
    assert seen["modules"] == ["file_intake"]
    assert seen["provider"] == "none"


def test_hash_only_honours_the_output_path(sample, stub_config, stub_pipeline, tmp_path):
    """`-o` was accepted and silently ignored, writing to stdout instead.

    No file was created and the exit status was 0, so a caller redirecting
    into a pipeline of its own got an empty path and no indication why.
    """
    target = tmp_path / "hashes.json"

    result = make_runner().invoke(
        cli_group,
        ["scan", str(sample), "--hash-only", "-f", "json", "-o", str(target)],
    )

    assert result.exit_code == EXIT_OK, stdout_of(result)
    assert json.loads(target.read_text())["hashes"]["sha256"] == "0" * 64
    assert stdout_of(result).strip() == ""


def test_hash_only_rejects_html_before_running_anything(sample, stub_config):
    """A known-invalid invocation must not hash the file first."""
    called = False

    def _spy(file, config, **kw):
        nonlocal called
        called = True
        return fake_report(file)

    scan_mod = importlib.import_module("cli.scan")

    with mock.patch.object(scan_mod, "run_pipeline", _spy):
        result = make_runner().invoke(
            cli_group, ["scan", str(sample), "--hash-only", "-f", "html"]
        )

    assert result.exit_code == EXIT_USAGE
    assert called is False


# ── rules update ────────────────────────────────────────────────────


def _rules_report(*actions: str) -> dict:
    return {
        "git_available": True,
        "sources": [
            {
                "name": f"src{i}",
                "action": action,
                "error": "fatal: could not read from remote repository"
                if action == "error"
                else None,
                "rule_count": 0,
            }
            for i, action in enumerate(actions)
        ],
        "validation": None,
    }


def test_a_failed_rule_update_does_not_exit_zero(stub_config, monkeypatch):
    """Every source failing to clone reported success.

    The CLI formatted the per-source error panels and returned normally,
    so `rules update` in a scheduled job exited 0 with no rules fetched —
    and the next scan ran against whatever was already on disk, or
    against nothing.
    """
    import core.rule_updater as updater

    monkeypatch.setattr(updater, "check_git_available", lambda: True)
    monkeypatch.setattr(
        updater, "update_all_sources", lambda config, **kw: _rules_report("error")
    )

    result = make_runner().invoke(cli_group, ["rules", "update"])

    assert result.exit_code == EXIT_RUNTIME


def test_a_partial_rule_update_also_exits_three(stub_config, monkeypatch):
    """One source working does not make the run complete."""
    import core.rule_updater as updater

    monkeypatch.setattr(updater, "check_git_available", lambda: True)
    monkeypatch.setattr(
        updater,
        "update_all_sources",
        lambda config, **kw: _rules_report("pulled", "error"),
    )

    result = make_runner().invoke(cli_group, ["rules", "update"])

    assert result.exit_code == EXIT_RUNTIME
    # The source that did work is still reported.
    assert "src0" in stdout_of(result) + stderr_of(result)


def test_a_successful_rule_update_exits_zero(stub_config, monkeypatch):
    import core.rule_updater as updater

    monkeypatch.setattr(updater, "check_git_available", lambda: True)
    monkeypatch.setattr(
        updater,
        "update_all_sources",
        lambda config, **kw: _rules_report("pulled", "up_to_date"),
    )

    result = make_runner().invoke(cli_group, ["rules", "update"])

    assert result.exit_code == EXIT_OK


def test_validate_only_rejects_the_flags_it_would_ignore(stub_config):
    """`--force` silently did nothing, which is the same class of defect
    as `--hash-only -o` being accepted and ignored."""
    for extra in ("--force", "--check"):
        result = make_runner().invoke(
            cli_group, ["rules", "update", "--validate-only", extra]
        )
        assert result.exit_code == EXIT_USAGE, extra


def test_validate_only_runs_offline_and_exits_zero(stub_config, monkeypatch):
    """It returns before the source-failure check, so it needs its own test.

    Nothing in this path touches the network or the per-source report;
    broken rules are a finding, not a failure to run, so the exit status
    stays 0 and `yara_scanner` isolates them at scan time.
    """
    import core.rule_updater as updater

    called: dict[str, bool] = {"network": False}
    monkeypatch.setattr(
        updater,
        "update_all_sources",
        lambda *a, **kw: called.__setitem__("network", True) or {},
    )
    monkeypatch.setattr(
        updater,
        "validate_rules",
        lambda rules_dir: {
            "total_files": 3,
            "valid_count": 2,
            "broken_count": 1,
            "broken_files": [{"file": "bad.yar", "error": "syntax error"}],
        },
    )

    result = make_runner().invoke(cli_group, ["rules", "update", "--validate-only"])

    assert result.exit_code == EXIT_OK, stdout_of(result) + stderr_of(result)
    assert called["network"] is False
    assert "2/3" in stdout_of(result)


def test_compare_does_not_render_a_missing_hash_as_truncated(tmp_path, stub_config, monkeypatch):
    """`"N/A"[:16] + "…"` reads as a hash that begins with N/A.

    The ellipsis was appended unconditionally, so a file whose
    `file_intake` did not succeed produced `N/A…` — a missing value
    dressed up as a truncated one.
    """
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"MZ\x01")
    b.write_bytes(b"MZ\x02")

    def _no_hashes(file, config, **kw):
        report = fake_report(file)
        for r in report["module_results"]:
            if r.get("module") == "file_intake":
                r["status"] = "error"
        return report

    compare_mod = importlib.import_module("cli.compare")
    monkeypatch.setattr(compare_mod, "run_pipeline", _no_hashes)

    result = make_runner().invoke(cli_group, ["compare", str(a), str(b)])

    assert result.exit_code == EXIT_OK, stdout_of(result) + stderr_of(result)
    assert "N/A…" not in stdout_of(result)
    assert "N/A" in stdout_of(result)
