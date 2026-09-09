"""Tests for the analysis pipeline orchestrator.

The orchestrator is what makes design rule 2 true: whatever a module does —
raise, hang, return nonsense, fail to import — the other twelve still run and
the user still gets a report. Nothing tested that until now.

Modules are injected by monkeypatching ``_load_module`` rather than by writing
real files, so a test can make a module misbehave in one line.
"""

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from core import pipeline as pl
from core.pipeline import (
    MODULE_ALIASES,
    _MODULE_REGISTRY,
    _error_result,
    _load_module,
    _run_module,
    _skipped_result,
    module_names,
    resolve_module_name,
    run_pipeline,
)


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    return p


def _module(run=None, **extra):
    """Build a fake module object exposing the given run()."""
    return SimpleNamespace(run=run, **extra)


def _ok(delta=0, **extra):
    def run(file_path, config):
        return {"status": "success", "data": {}, "score_delta": delta,
                "reason": "ok", **extra}
    return _module(run)


def _install(monkeypatch, mapping):
    """Point the registry at fake modules keyed by canonical name."""
    monkeypatch.setattr(pl, "_MODULE_REGISTRY",
                        {name: f"fake.{name}" for name in mapping})
    monkeypatch.setattr(pl, "_load_module",
                        lambda path: mapping.get(path.split(".", 1)[1]))


# ----------------------------------------------------------------------
# Name resolution
# ----------------------------------------------------------------------

def test_registry_key_resolves_to_itself():
    assert resolve_module_name("pe_analysis") == "pe_analysis"


@pytest.mark.parametrize("alias, canonical", sorted(MODULE_ALIASES.items()))
def test_every_alias_resolves_to_a_real_registry_key(alias, canonical):
    assert resolve_module_name(alias) == canonical
    assert canonical in _MODULE_REGISTRY


def test_resolution_is_case_insensitive_and_strips_whitespace():
    assert resolve_module_name("  PE  ") == "pe_analysis"
    assert resolve_module_name("VT") == "virustotal"


def test_unknown_name_resolves_to_none_rather_than_raising():
    """None keeps the policy decision with the caller.

    The CLI turns it into a usage error; enabled_modules only warns and
    skips, so a stale config cannot make the tool unrunnable.
    """
    assert resolve_module_name("definitely_not_a_module") is None


def test_module_names_are_sorted_and_complete():
    assert module_names() == sorted(_MODULE_REGISTRY)


def test_registry_holds_the_thirteen_documented_modules():
    assert len(_MODULE_REGISTRY) == 13
    assert "file_intake" in _MODULE_REGISTRY
    assert "virustotal" in _MODULE_REGISTRY


# ----------------------------------------------------------------------
# _load_module — graceful degradation
# ----------------------------------------------------------------------

def test_loading_a_missing_module_returns_none_not_an_exception(caplog):
    with caplog.at_level(logging.WARNING):
        assert _load_module("modules.static.no_such_module_at_all") is None
    assert "no_such_module_at_all" in caplog.text


def test_loading_a_real_module_returns_it():
    assert _load_module("core.file_intake") is not None


# ----------------------------------------------------------------------
# _run_module — the result contract is repaired, never trusted
# ----------------------------------------------------------------------

def test_module_without_run_is_skipped(sample):
    out = _run_module(SimpleNamespace(), "m", sample, {})
    assert out["status"] == "skipped"
    assert out["score_delta"] == 0


def test_module_returning_a_non_dict_becomes_an_error(sample):
    out = _run_module(_module(lambda f, c: "not a dict"), "m", sample, {})
    assert out["status"] == "error"
    assert out["score_delta"] == 0


def test_module_that_raises_becomes_an_error_carrying_the_message(sample):
    def boom(file_path, config):
        raise ValueError("parser exploded")

    out = _run_module(_module(boom), "m", sample, {})
    assert out["status"] == "error"
    assert "parser exploded" in out["reason"]
    assert out["score_delta"] == 0


def test_partial_result_is_completed_with_defaults(sample):
    """A module may omit keys; the reporters must still be able to index."""
    out = _run_module(_module(lambda f, c: {"data": {"x": 1}}), "m", sample, {})
    assert out["module"] == "m"
    assert out["status"] == "success"
    assert out["score_delta"] == 0
    assert out["reason"] == ""


def test_module_supplied_values_are_not_overwritten(sample):
    out = _run_module(_ok(delta=42), "m", sample, {})
    assert out["score_delta"] == 42
    assert out["reason"] == "ok"


# ----------------------------------------------------------------------
# run_pipeline — orchestration
# ----------------------------------------------------------------------

def test_report_has_the_documented_shape(monkeypatch, sample):
    _install(monkeypatch, {"a": _ok(10)})
    report = run_pipeline(sample, {"enabled_modules": ["a"]})
    assert set(report) == {"file", "module_results", "scoring", "timing", "dynamic"}
    assert report["file"] == str(sample)
    assert report["scoring"]["total_score"] == 10
    assert set(report["timing"]) == {"start", "end", "elapsed_seconds"}


def test_elapsed_seconds_is_attached_to_every_static_result(monkeypatch, sample):
    _install(monkeypatch, {"a": _ok(1), "b": _ok(2)})
    report = run_pipeline(sample, {"enabled_modules": ["a", "b"]})
    assert all("elapsed_seconds" in r for r in report["module_results"])


def test_unknown_module_in_enabled_modules_is_skipped_not_fatal(monkeypatch, sample):
    """A stale config file must not make the tool unrunnable."""
    _install(monkeypatch, {"a": _ok(5)})
    report = run_pipeline(sample, {"enabled_modules": ["a", "ghost"]})
    by_name = {r["module"]: r for r in report["module_results"]}
    assert by_name["ghost"]["status"] == "skipped"
    assert report["scoring"]["total_score"] == 5


def test_unimportable_module_is_skipped(monkeypatch, sample):
    monkeypatch.setattr(pl, "_MODULE_REGISTRY", {"a": "fake.a"})
    monkeypatch.setattr(pl, "_load_module", lambda path: None)
    report = run_pipeline(sample, {"enabled_modules": ["a"]})
    assert report["module_results"][0]["status"] == "skipped"


def test_one_raising_module_does_not_stop_the_others(monkeypatch, sample):
    """Design rule 2, end to end."""
    def boom(file_path, config):
        raise RuntimeError("nope")

    _install(monkeypatch, {"first": _ok(10), "bad": _module(boom), "last": _ok(20)})
    report = run_pipeline(sample, {"enabled_modules": ["first", "bad", "last"]})
    statuses = {r["module"]: r["status"] for r in report["module_results"]}
    assert statuses == {"first": "success", "bad": "error", "last": "success"}
    assert report["scoring"]["total_score"] == 30


def test_modules_run_in_the_order_enabled_modules_lists_them(monkeypatch, sample):
    order = []

    def make(name):
        def run(file_path, config):
            order.append(name)
            return {"status": "success", "data": {}, "score_delta": 0, "reason": ""}
        return _module(run)

    _install(monkeypatch, {"x": make("x"), "y": make("y"), "z": make("z")})
    run_pipeline(sample, {"enabled_modules": ["z", "x", "y"]})
    assert order == ["z", "x", "y"]


# ----------------------------------------------------------------------
# Cross-module handoff
# ----------------------------------------------------------------------

def test_a_later_module_sees_earlier_results(monkeypatch, sample):
    """virustotal relies on this to read hashes archive_analysis found."""
    seen = {}

    def second(file_path, config):
        seen["prior"] = [r["module"] for r in config["_module_results_so_far"]]
        return {"status": "success", "data": {}, "score_delta": 0, "reason": ""}

    _install(monkeypatch, {"first": _ok(1), "second": _module(second)})
    run_pipeline(sample, {"enabled_modules": ["first", "second"]})
    assert seen["prior"] == ["first"]


def test_prior_results_are_a_copy_not_the_live_accumulator(monkeypatch, sample):
    """A module mutating the handoff must not corrupt the report."""
    def vandal(file_path, config):
        config["_module_results_so_far"].clear()
        config["_module_results_so_far"].append({"module": "injected"})
        return {"status": "success", "data": {}, "score_delta": 0, "reason": ""}

    _install(monkeypatch, {"first": _ok(1), "vandal": _module(vandal)})
    report = run_pipeline(sample, {"enabled_modules": ["first", "vandal"]})
    names = [r["module"] for r in report["module_results"]]
    assert names == ["first", "vandal"]
    assert "injected" not in names


# ----------------------------------------------------------------------
# Progress callback
# ----------------------------------------------------------------------

def test_progress_callback_fires_start_and_done_per_module(monkeypatch, sample):
    events = []
    _install(monkeypatch, {"a": _ok(), "b": _ok()})
    run_pipeline(sample, {"enabled_modules": ["a", "b"]},
                 progress_cb=lambda i, t, n, e: events.append((i, t, n, e)))
    assert events == [
        (0, 2, "a", "start"), (0, 2, "a", "done"),
        (1, 2, "b", "start"), (1, 2, "b", "done"),
    ]


def test_pipeline_runs_without_a_progress_callback(monkeypatch, sample):
    _install(monkeypatch, {"a": _ok()})
    assert run_pipeline(sample, {"enabled_modules": ["a"]})["module_results"]


# ----------------------------------------------------------------------
# Dynamic providers
# ----------------------------------------------------------------------

def test_no_dynamic_provider_by_default(monkeypatch, sample):
    _install(monkeypatch, {"a": _ok()})
    report = run_pipeline(sample, {"enabled_modules": ["a"]})
    assert report["dynamic"] is None


def test_unavailable_provider_is_skipped(monkeypatch, sample):
    provider = _module(lambda f, c: {"score_delta": 50},
                       is_available=lambda config: False)
    monkeypatch.setattr(pl, "_MODULE_REGISTRY", {"a": "fake.a"})
    monkeypatch.setattr(pl, "_DYNAMIC_REGISTRY", {"speakeasy": "fake.dyn"})
    monkeypatch.setattr(pl, "_load_module",
                        lambda path: provider if path == "fake.dyn" else _ok())
    report = run_pipeline(sample, {"enabled_modules": ["a"],
                                   "dynamic_provider": "speakeasy"})
    assert report["dynamic"] is None


def test_available_provider_result_is_scored(monkeypatch, sample):
    provider = _module(lambda f, c: {"status": "success", "data": {},
                                     "score_delta": 25, "reason": "detonated"},
                       is_available=lambda config: True)
    monkeypatch.setattr(pl, "_MODULE_REGISTRY", {"a": "fake.a"})
    monkeypatch.setattr(pl, "_DYNAMIC_REGISTRY", {"speakeasy": "fake.dyn"})
    monkeypatch.setattr(pl, "_load_module",
                        lambda path: provider if path == "fake.dyn" else _ok())
    report = run_pipeline(sample, {"enabled_modules": ["a"],
                                   "dynamic_provider": "speakeasy"})
    assert report["dynamic"]["module"] == "dynamic_speakeasy"
    assert report["scoring"]["total_score"] == 25


def test_unknown_dynamic_provider_is_skipped(monkeypatch, sample, caplog):
    _install(monkeypatch, {"a": _ok()})
    with caplog.at_level(logging.WARNING):
        report = run_pipeline(sample, {"enabled_modules": ["a"],
                                       "dynamic_provider": "not_a_provider"})
    assert report["dynamic"] is None


# ----------------------------------------------------------------------
# Result builders
# ----------------------------------------------------------------------

def test_error_and_skipped_results_never_move_the_score():
    """A module that did not run must not affect the verdict either way."""
    assert _error_result("m", "why")["score_delta"] == 0
    assert _skipped_result("m", "why")["score_delta"] == 0
    assert _error_result("m", "why")["status"] == "error"
    assert _skipped_result("m", "why")["status"] == "skipped"


# ----------------------------------------------------------------------
# Known gap: the orchestrator does not enforce module_timeout_seconds
# ----------------------------------------------------------------------

def test_orchestrator_does_not_enforce_module_timeout_seconds(monkeypatch, sample):
    """Pins a KNOWN GAP rather than asserting desired behaviour.

    Design rule 5 says every module needs a timeout. config_loader
    validates ``module_timeout_seconds`` and nothing ever reads it: the
    orchestrator has no watchdog, and timeouts are enforced only inside
    the modules that shell out (capa's subprocess, XLM's 30s cap).

    A slow pure-Python module therefore runs to completion regardless of
    the setting. This test documents that so the gap is visible in the
    suite instead of being mistaken for coverage. When a watchdog is
    added, this test should be inverted.
    """
    calls = []

    def slow(file_path, config):
        calls.append("ran to completion")
        return {"status": "success", "data": {}, "score_delta": 0, "reason": ""}

    _install(monkeypatch, {"slow": _module(slow)})
    report = run_pipeline(sample, {"enabled_modules": ["slow"],
                                   "module_timeout_seconds": 0.0001})

    assert calls == ["ran to completion"]
    assert report["module_results"][0]["status"] == "success"
