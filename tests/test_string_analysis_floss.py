"""FLOSS extraction — the invocation, the fallback chain, and the bonus.

``bin/floss`` was absent for the whole life of the project, so
``_run_floss`` and ``_extract_floss_strings`` had never executed once and
had no test at all. Every number quoted below was measured over the 30 PE
samples in the corpus, three arms each (raw extractor, ``--only static``,
full default FLOSS).

The headline measurement, because it is why emulation sits behind
``-p deep``: full emulation costs 30.0 minutes against 69 seconds for
``--only static`` — 26x — and produced **zero** suspicious-category
matches from emulated strings across all 30 samples. What it does buy is
the +10 structural bonus, which fires on 13 of the 30: a binary that
builds strings on the stack has paid to hide them whether or not those
strings match a pattern.
"""

import json
import subprocess

import pytest

from modules.static import string_analysis as sa


class _Proc:
    def __init__(self, stdout=b"", returncode=0, stderr=b""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def _doc(**counts):
    """A FLOSS JSON document with the requested per-section counts."""
    sections = {
        name: [{"string": f"{name}-{i}"} for i in range(counts.get(name, 0))]
        for name in ("static_strings", "decoded_strings", "stack_strings",
                     "tight_strings", "language_strings")
    }
    return json.dumps({"strings": sections}).encode()


# ----------------------------------------------------------------- invocation


def test_standard_asks_floss_for_static_strings_only(tmp_path, monkeypatch):
    """The whole cost control. Measured: ``--only static`` is flat at ~1s
    regardless of file size, while full emulation ranged 0.7s to 271.1s
    on the same 30 samples."""
    binary = tmp_path / "floss"
    binary.write_text("")
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return _Proc(stdout=_doc(static_strings=3))

    monkeypatch.setattr(subprocess, "run", fake_run)
    sa._run_floss(tmp_path / "s.exe", binary, 300, emulation=False)
    assert "--only" in seen["cmd"] and "static" in seen["cmd"]


def test_deep_asks_floss_for_everything(tmp_path, monkeypatch):
    binary = tmp_path / "floss"
    binary.write_text("")
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return _Proc(stdout=_doc(static_strings=3, decoded_strings=1))

    monkeypatch.setattr(subprocess, "run", fake_run)
    sa._run_floss(tmp_path / "s.exe", binary, 300, emulation=True)
    assert "--only" not in seen["cmd"]


def test_a_missing_binary_is_not_an_error(tmp_path):
    result, failure = sa._run_floss(tmp_path / "s.exe", tmp_path / "nope", 300,
                                    emulation=False)
    assert result is None and failure == "missing"


# ------------------------------------------------------------------- failures


@pytest.mark.parametrize("proc,expected", [
    (_Proc(returncode=1, stderr=b"boom"), "exit"),
    (_Proc(stdout=b"not json at all"), "badjson"),
    (_Proc(stdout=b""), "badjson"),
])
def test_every_floss_failure_degrades_rather_than_raising(
    tmp_path, monkeypatch, proc, expected
):
    """Design rule 2. A non-zero exit is total failure by design: FLOSS
    writes its JSON document whole at the end of a successful run, so a
    failed run has no partial output worth salvaging."""
    binary = tmp_path / "floss"
    binary.write_text("")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: proc)
    result, failure = sa._run_floss(tmp_path / "s.exe", binary, 300,
                                    emulation=True)
    assert result is None
    assert failure == expected, "the caller branches on this, so it must be exact"


def test_a_timed_out_emulation_retries_static_instead_of_falling_to_raw(
    tmp_path, monkeypatch
):
    """The two-step fallback.

    FLOSS buffers its JSON and writes nothing when killed, so a timed-out
    emulation run yields no strings at all. Falling straight back to the
    in-tree raw extractor would mean spending the full budget and then
    returning a *worse* result than a one-second ``--only static`` run
    would have given. So the timeout retries static first, and only a
    failure of that reaches the raw path.
    """
    binary = tmp_path / "floss"
    binary.write_text("")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if "--only" not in cmd:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 300))
        return _Proc(stdout=_doc(static_strings=4))

    monkeypatch.setattr(subprocess, "run", fake_run)
    cfg = {"floss_binary": str(binary), "floss_emulation": True,
           "floss_timeout_seconds": 300}
    result = sa.run(sample, cfg)

    assert len(calls) == 2, "expected a full attempt then a static retry"
    assert "--only" in calls[1]
    assert result["data"]["source"] == "floss"
    assert result["data"]["floss_mode"] == "static"
    assert result["data"]["floss_emulation_timed_out"] is True


def test_a_timeout_must_not_render_as_a_clean_zero(tmp_path, monkeypatch):
    """A skip that reads as a finding. `0 decoded / 0 stack` after a
    timed-out deep run says "this sample does not obfuscate its strings",
    which is the opposite of what happened. The same defect class as the
    lnk and onenote size-cap bypasses."""
    binary = tmp_path / "floss"
    binary.write_text("")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)

    def fake_run(cmd, **kw):
        if "--only" not in cmd:
            raise subprocess.TimeoutExpired(cmd, 300)
        return _Proc(stdout=_doc(static_strings=2))

    monkeypatch.setattr(subprocess, "run", fake_run)
    data = sa.run(sample, {"floss_binary": str(binary), "floss_emulation": True,
                           "floss_timeout_seconds": 300})["data"]
    assert data["floss_emulation_timed_out"] is True
    assert data["floss_mode"] != "full"


# --------------------------------------------------------------------- parsing


def test_tight_strings_are_recorded_and_score(tmp_path, monkeypatch):
    """`tight_count` was computed and read by nothing — not stored in
    ``data``, not tested by the +10 bonus. FLOSS documents tight strings
    as "a special form of stack strings, decoded on the stack", so a
    sample using only tight strings hid them just as thoroughly and
    scored nothing for it. 45 tight strings across the corpus."""
    binary = tmp_path / "floss"
    binary.write_text("")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: _Proc(stdout=_doc(tight_strings=6)))
    result = sa.run(sample, {"floss_binary": str(binary),
                             "floss_emulation": True})
    assert result["data"]["floss_tight_strings"] == 6
    assert result["score_delta"] >= 10, "tight strings must earn the bonus"


def test_language_strings_are_recorded(tmp_path, monkeypatch):
    """FLOSS 3.x emits these for Go, Rust and .NET. Recorded because
    discarding a section FLOSS produces is arbitrary — not because it
    detects: measured on 3 Go samples, they matched only categories the
    raw extractor already matched, gaining nothing on any of them."""
    binary = tmp_path / "floss"
    binary.write_text("")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: _Proc(stdout=_doc(language_strings=9)))
    data = sa.run(sample, {"floss_binary": str(binary)})["data"]
    assert data["floss_language_strings"] == 9


def test_a_static_only_run_earns_no_obfuscation_bonus(tmp_path, monkeypatch):
    """The bonus is for hidden strings, and `--only static` finds none by
    construction. Firing it on the standard profile would add +10 to
    every PE for nothing."""
    binary = tmp_path / "floss"
    binary.write_text("")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: _Proc(stdout=_doc(static_strings=500)))
    result = sa.run(sample, {"floss_binary": str(binary),
                             "floss_emulation": False})
    assert result["data"]["floss_mode"] == "static"
    assert "obfuscated" not in result["reason"].lower()


def test_extract_handles_both_entry_shapes():
    assert sa._extract_floss_strings(["bare", {"string": "dict"},
                                      {"value": "alt"}, {}, 7]) == \
        ["bare", "dict", "alt"]


# ------------------------------------------------------------------ rendering


def _render(data, detail=0):
    from io import StringIO

    from rich.console import Console

    from reporting.terminal_reporter._common import use_console
    from reporting.terminal_reporter.findings import print_suspicious_strings

    buf = StringIO()
    con = Console(file=buf, width=100, no_color=True, highlight=False)
    results = [{"module": "string_analysis", "status": "success",
                "data": data, "score_delta": 10, "reason": ""}]
    with use_console(con):
        print_suspicious_strings(results, detail)
    return buf.getvalue()


def test_a_downgraded_run_says_so_in_the_report():
    """No `floss_*` field rendered anywhere before this. A deep run that
    timed out and fell back to static must say so — otherwise the absence
    of decoded strings reads as the sample having none."""
    out = _render({"source": "floss", "floss_mode": "static",
                   "floss_emulation_timed_out": True,
                   "floss_decoded_strings": 0, "floss_stack_strings": 0,
                   "floss_tight_strings": 0, "suspicious_matches": []})
    assert "timed out" in out.lower() or "static" in out.lower()
    assert out.strip(), "a downgraded run rendered nothing at all"


def test_hidden_string_counts_are_shown_because_they_scored():
    """These earn the +10 bonus, so the report must show what earned it."""
    out = _render({"source": "floss", "floss_mode": "full",
                   "floss_emulation_timed_out": False,
                   "floss_decoded_strings": 4, "floss_stack_strings": 2,
                   "floss_tight_strings": 1, "suspicious_matches": []})
    assert "4" in out and "2" in out and "1" in out


def test_a_quiet_static_run_stays_quiet_at_detail_zero():
    """`--only static` on a clean file has nothing to report. Printing an
    extraction line for it would put a row on every scan to say nothing
    happened."""
    out = _render({"source": "floss", "floss_mode": "static",
                   "floss_emulation_timed_out": False,
                   "floss_decoded_strings": 0, "floss_stack_strings": 0,
                   "floss_tight_strings": 0, "suspicious_matches": []})
    assert out.strip() == ""


# ------------------------------------------------- why the run failed matters


def test_a_floss_crash_is_not_reported_as_a_timeout(tmp_path, monkeypatch):
    """`_run_floss` answers None for five different failures — missing
    binary, timeout, OSError, non-zero exit, unparseable JSON. Treating
    every one of them as a timeout tells the analyst the emulator ran out
    of time when it actually crashed, and the reporter then prints
    "emulation timed out" over a a run that never got that far."""
    binary = tmp_path / "floss"
    binary.write_text("")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if "--only" not in cmd:
            return _Proc(returncode=1, stderr=b"vivisect exploded")
        return _Proc(stdout=_doc(static_strings=3))

    monkeypatch.setattr(subprocess, "run", fake_run)
    data = sa.run(sample, {"floss_binary": str(binary), "floss_emulation": True,
                           "floss_timeout_seconds": 300})["data"]
    assert data["floss_emulation_timed_out"] is False, \
        "a crash was reported to the user as a timeout"


def test_a_missing_binary_does_not_trigger_a_pointless_retry(tmp_path, monkeypatch):
    """Nothing to retry with. The retry exists to salvage a timed-out
    emulation run; re-invoking an absent binary just repeats the same
    is_file() check and logs a timeout that never happened."""
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    calls = []
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or _Proc())

    data = sa.run(sample, {"floss_binary": str(tmp_path / "absent"),
                           "floss_emulation": True})["data"]
    assert calls == [], "FLOSS was invoked despite the binary being absent"
    assert data["source"] == "raw"
    assert data["floss_emulation_timed_out"] is False
