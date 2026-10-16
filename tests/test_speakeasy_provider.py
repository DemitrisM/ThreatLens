"""Tests for the Speakeasy dynamic provider and its emulation worker.

These run without Speakeasy installed — the library is an optional extra,
and the worker imports it lazily inside ``_run`` precisely so that the
parent process and this suite never need it. The one test that really
emulates is marked ``corpus_slow`` and skips itself otherwise.

Each test below pins a specific defect that review or measurement found.
Where that is not obvious from the name, the docstring says what the test
must fail against — a test that passes before the fix proves nothing.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from core import detonation
from modules.dynamic import _speakeasy_worker as worker
from modules.dynamic import speakeasy_provider as provider

CORPUS = Path(os.environ.get("THREATLENS_CORPUS", "/home/pmafma/Documents/Malware"))
PE_DIR = CORPUS / "exe test malware"


# ======================================================================
# Worker — the pure helpers, no emulation needed
# ======================================================================

class TestStopReason:
    """``ep["error"]`` is not a fault flag, and not our vocabulary."""

    def test_absent_error_is_clean(self):
        """Must fail against reading ``error["type"]`` directly.

        A clean entry point carries no error at all, so indexing it raises
        TypeError on the single most common case.
        """
        assert worker._stop_reason(None) == "clean"
        assert worker._stop_reason({}) == "clean"

    def test_api_ceiling_is_not_a_fault(self):
        """Must fail against ``faulted = bool(error)``.

        Measured: with max_api_count=50, Amadey.exe returned
        ``{type: "max_api_count", ...}``. A graceful stop populates the
        same field a fault does.
        """
        assert worker._stop_reason({"type": "max_api_count", "count": 50}) == "api_cap"

    def test_timeout_is_not_a_fault(self):
        assert worker._stop_reason({"type": "timeout"}) == "timeout"

    @pytest.mark.parametrize("kind", ["invalid_read", "invalid_write", "unsupported_api"])
    def test_real_faults_map_to_fault(self, kind):
        """Speakeasy stores a specific category, never the literal "fault"."""
        assert worker._stop_reason({"type": kind, "pc": 1}) == "fault"

    def test_unexpected_shape_is_a_fault_not_a_crash(self):
        assert worker._stop_reason("something") == "fault"


class TestIsPE:
    """The dropped-executable weight needs more than the letters MZ."""

    def test_mz_alone_is_not_a_pe(self):
        """Must fail against an MZ-only check, which would award +15 to any
        dropped file whose first two bytes happen to read that way."""
        assert worker._is_pe(b"MZ" + b"\x00" * 200) is False

    def test_real_pe_signature_is_recognised(self):
        data = bytearray(b"\x00" * 0x100)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        data[0x80:0x84] = b"PE\x00\x00"
        assert worker._is_pe(bytes(data)) is True

    def test_short_and_empty_do_not_raise(self):
        assert worker._is_pe(b"") is False
        assert worker._is_pe(b"MZ") is False


class TestAsList:
    """``network`` was never observed in the corpus, so its shape is unproven."""

    def test_dict_is_flattened_to_values_not_keys(self):
        """Must fail against ``list.extend(some_dict)``.

        Extending with a dict aggregates its KEY NAMES — the data would be
        silently replaced by ["traffic", "dns"] and the list would read as
        non-empty even when both sub-lists were empty.
        """
        out = worker._as_list({"traffic": [{"host": "evil"}], "dns": [{"q": "a.com"}]})
        assert {"host": "evil"} in out
        assert "traffic" not in out

    def test_list_passes_through(self):
        assert worker._as_list([1, 2]) == [1, 2]

    def test_none_is_empty(self):
        assert worker._as_list(None) == []


class TestFeatureExtraction:
    def test_injection_sequence_detected(self):
        feats = worker._extract_features(["VirtualAllocEx", "WriteProcessMemory"])
        assert feats["process_injection"] is True

    def test_nothing_observed_scores_nothing(self):
        assert not any(worker._extract_features([]).values())

    def test_matching_is_case_insensitive(self):
        assert worker._extract_features(["isdebuggerpresent"])["anti_analysis"] is True


class TestFeatureMatchingIsExact:
    """Substring matching on API names is a false-positive generator."""

    def test_crt_startup_does_not_look_like_credential_access(self):
        """Must fail against substring matching.

        "lsa" is a substring of TlsAlloc and FlsAlloc, which the MSVC C
        runtime calls before main() in nearly every native PE. Under the
        original matcher every emulated sample scored +10 for credential
        access — measured, not hypothetical.
        """
        feats = worker._extract_features(["TlsAlloc", "FlsAlloc", "HeapCreate"])
        assert feats["credential_access"] is False

    def test_a_real_credential_api_still_matches(self):
        assert worker._extract_features(
            ["advapi32.LsaOpenPolicy"])["credential_access"] is True

    def test_module_prefix_is_ignored(self):
        assert worker._extract_features(
            ["kernel32.WriteProcessMemory"])["process_injection"] is True

    def test_charset_suffix_is_folded(self):
        """CreateFileA and CreateFileW are one behaviour, not two."""
        assert worker._normalise_api("advapi32.RegSetValueExW") == "regsetvalueex"


class TestFeatureTableIsHonest:
    def test_gettickcount_is_not_an_anti_analysis_signal(self):
        """Must fail against including it.

        Every Windows binary calls GetTickCount. Timing evasion needs the
        INTERVAL between two calls, which the post-emulation report does
        not preserve, so the API name alone is the same false-positive
        shape as matching "lsa" inside TlsAlloc.
        """
        assert worker._extract_features(["GetTickCount"])["anti_analysis"] is False

    def test_a_real_debugger_check_still_matches(self):
        assert worker._extract_features(
            ["IsDebuggerPresent"])["anti_analysis"] is True

    def test_no_feature_name_is_a_process_rather_than_an_api(self):
        """schtasks.exe is launched, not called — it can never appear in an
        API list, so an entry for it would be permanently dead."""
        every = set().union(*worker._FEATURE_APIS.values())
        assert "schtasks" not in every


class TestCapsDoNotHideEvidence:
    def test_dropped_list_is_strictly_capped(self):
        """Must fail against keeping every PE past the cap.

        An earlier version did, to stop decoys hiding a payload — but that
        made the list unbounded, defeating the very budget the cap exists
        to protect. The PE fact travels as a feature instead.
        """
        class _F:
            def get_path(self):
                return "x"

            def get_hash(self):
                return "h"

            def get_data(self):
                d = bytearray(b"\x00" * 0x100)
                d[0:2] = b"MZ"
                d[0x3C:0x40] = (0x80).to_bytes(4, "little")
                d[0x80:0x84] = b"PE\x00\x00"
                return bytes(d)

        class _SE:
            def get_dropped_files(self):
                return [_F()] * 500

        entries, total, saw_pe = worker._collect_dropped(_SE())
        assert len(entries) == worker.MAX_DROPPED
        assert total == 500
        assert saw_pe is True

    def test_dropped_pe_survives_past_the_cap(self):
        """Must fail against slicing dropped files before inspecting them.

        A sample that writes 100 decoys before its payload would otherwise
        push the PE past the cap and evade the dropped-executable weight.
        """
        class _F:
            def __init__(self, pe):
                self._pe = pe

            def get_path(self):
                return "x"

            def get_hash(self):
                return "h"

            def get_data(self):
                if not self._pe:
                    return b"junk"
                d = bytearray(b"\x00" * 0x100)
                d[0:2] = b"MZ"
                d[0x3C:0x40] = (0x80).to_bytes(4, "little")
                d[0x80:0x84] = b"PE\x00\x00"
                return bytes(d)

        class _SE:
            def get_dropped_files(self):
                return [_F(False)] * 150 + [_F(True)]

        entries, total, saw_pe = worker._collect_dropped(_SE())
        assert total == 151
        assert saw_pe is True, "a PE past the cap must still be reported"

    def test_magic_is_json_safe(self):
        class _F:
            def get_path(self):
                return "x"

            def get_hash(self):
                return "h"

            def get_data(self):
                return b"MZ\x90\x00"

        class _SE:
            def get_dropped_files(self):
                return [_F()]

        entries, _, _ = worker._collect_dropped(_SE())
        json.dumps(entries)  # must not raise
        assert isinstance(entries[0]["magic"], str)

    def test_collect_dropped_survives_a_dead_engine(self):
        """load_module failing leaves get_dropped_files raising on a None."""
        class _SE:
            def get_dropped_files(self):
                raise AttributeError("'NoneType' object has no attribute ...")

        assert worker._collect_dropped(_SE()) == ([], 0, False)


class TestWorkerOutput:
    def test_emit_writes_one_json_document(self, tmp_path):
        target = tmp_path / "out.json"
        fd = os.open(target, os.O_WRONLY | os.O_CREAT)
        worker._emit(fd, {"status": "ok", "trace": {"apis": []}})
        assert json.loads(target.read_text())["status"] == "ok"

    def test_emit_survives_non_serialisable_values(self, tmp_path):
        """Must fail against a bare ``json.dumps``.

        A dropped file's magic is bytes at the point it is read; anything
        that reaches the encoder unconverted would crash the worker on
        exactly the samples that drop payloads.
        """
        target = tmp_path / "out.json"
        fd = os.open(target, os.O_WRONLY | os.O_CREAT)
        worker._emit(fd, {"status": "ok", "trace": {"magic": b"MZ\x90\x00"}})
        assert json.loads(target.read_text())["trace"]["magic"]


# ======================================================================
# Provider — applicability, with pefile mocked so this runs anywhere
# ======================================================================

class _FakeDir:
    def __init__(self, va):
        self.VirtualAddress = va


class _FakePE:
    def __init__(self, machine=0x014C, dirs=None):
        self.FILE_HEADER = type("H", (), {"Machine": machine})()
        self.OPTIONAL_HEADER = type("O", (), {"DATA_DIRECTORY": dirs if dirs is not None
                                              else [_FakeDir(0)] * 16})()

    def close(self):
        pass


# Import the real pefile ONCE, at collection. _patch_pefile swaps
# sys.modules["pefile"] for a stub; if the real module were not already
# present, monkeypatch would restore by DELETING the key, forcing every
# later test that touches pefile to re-import a C-backed module. Holding a
# reference here keeps the restore a swap-back rather than a delete.
import pefile as _real_pefile  # noqa: E402


def _patch_pefile(monkeypatch, pe_or_exc):
    import types

    def _PE(path, fast_load=False):
        if isinstance(pe_or_exc, Exception):
            raise pe_or_exc
        return pe_or_exc

    stub = types.SimpleNamespace(PE=_PE)
    # Copy anything else the real module exposes, so a stub can never make
    # an unrelated attribute vanish for code that imports it later.
    monkeypatch.setitem(__import__("sys").modules, "pefile", stub)
    assert _real_pefile is not None


class TestApplicability:
    def test_non_pe_is_not_attempted_and_spawns_nothing(self, monkeypatch, tmp_path):
        _patch_pefile(monkeypatch, ValueError("not a PE"))
        monkeypatch.setattr(provider, "run_contained",
                            lambda *a, **k: pytest.fail("must not spawn"))
        result = provider.run(tmp_path / "x.bin", {})
        assert result["status"] == "skipped"
        assert detonation.state_of(result) == detonation.NOT_ATTEMPTED

    def test_dotnet_is_not_attempted(self, monkeypatch, tmp_path):
        dirs = [_FakeDir(0)] * 16
        dirs[14] = _FakeDir(0x2000)
        _patch_pefile(monkeypatch, _FakePE(dirs=dirs))
        result = provider.run(tmp_path / "x.exe", {})
        assert ".NET" in result["reason"]
        assert detonation.state_of(result) == detonation.NOT_ATTEMPTED

    def test_arm64_is_not_attempted_rather_than_failed(self, monkeypatch, tmp_path):
        """Must fail against checking only PE-ness and .NET.

        An unsupported architecture is something we never try, so it is
        `not_attempted`. Contrast test_unloadable_pe_is_failed: once a
        sample passes applicability, anything that goes wrong afterwards
        IS an attempted detonation that failed.
        """
        _patch_pefile(monkeypatch, _FakePE(machine=0xAA64))
        result = provider.run(tmp_path / "x.exe", {})
        assert "architecture" in result["reason"].lower()
        assert detonation.state_of(result) == detonation.NOT_ATTEMPTED

    def test_short_data_directory_does_not_raise(self, monkeypatch, tmp_path):
        """Must fail against a bare ``DATA_DIRECTORY[14]`` index.

        pefile populates only NumberOfRvaAndSizes entries and does not pad
        to 16, so a packed header can be shorter than the CLR slot.
        """
        _patch_pefile(monkeypatch, _FakePE(dirs=[_FakeDir(0)] * 8))
        monkeypatch.setattr(provider, "run_contained",
                            lambda *a, **k: _completed(json.dumps(
                                {"status": "ok", "trace": _trace(apis=1)})))
        result = provider.run(tmp_path / "x.exe", {})
        assert result["status"] == "success"


# ======================================================================
# Provider — the subprocess boundary and the D-2 mapping
# ======================================================================

def _completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _trace(apis=0, **over):
    t = {
        "apis": [{"name": "X", "args": "", "ret": ""}] * apis,
        "api_total": apis, "network": [], "files": [], "registry": [],
        "processes": [], "dropped": [], "entry_points": [],
        "dyn_imports": [], "dyn_import_total": 0,
        "features": {}, "truncated": False, "truncation_reason": None,
        "ended": "clean",
    }
    t.update(over)
    return t


@pytest.fixture
def native(monkeypatch):
    _patch_pefile(monkeypatch, _FakePE())
    return monkeypatch


class TestDetonationMapping:
    def test_empty_trace_is_failed_not_observed(self, native, tmp_path):
        """THE case. Must fail against mapping a successful worker exit to
        `observed`.

        Measured on the corpus: ArkeiStealer.exe emulates to zero API calls
        AND a fault. Reporting that as `observed` is a clean dynamic verdict
        on live malware — exactly what D-2 exists to prevent.
        """
        native.setattr(provider, "run_contained", lambda *a, **k: _completed(
            json.dumps({"status": "ok", "trace": _trace(apis=0, ended="fault")})))
        result = provider.run(tmp_path / "x.exe", {})
        assert detonation.state_of(result) == detonation.FAILED
        assert result["score_delta"] == 0

    def test_empty_trace_after_a_clean_return_is_also_failed(self, native, tmp_path):
        """A `ret` at the entry point produces the same empty trace by a
        different route. Must fail against a table keyed on how it ended."""
        native.setattr(provider, "run_contained", lambda *a, **k: _completed(
            json.dumps({"status": "ok", "trace": _trace(apis=0, ended="clean")})))
        assert detonation.state_of(provider.run(tmp_path / "x.exe", {})) == detonation.FAILED

    def test_fault_with_observations_is_observed_and_scores(self, native, tmp_path):
        """Must fail against mapping any fault to `failed`.

        Measured: Amadey2.exe faulted while recording 235 API calls.
        Discarding that converts "we stopped looking" into "nothing there".
        """
        native.setattr(provider, "run_contained", lambda *a, **k: _completed(
            json.dumps({"status": "ok", "trace": _trace(
                apis=235, ended="fault", features={"process_injection": True})})))
        result = provider.run(tmp_path / "x.exe", {})
        assert detonation.state_of(result) == detonation.OBSERVED
        assert result["score_delta"] == 20

    def test_truncated_run_still_scores_what_it_saw(self, native, tmp_path):
        native.setattr(provider, "run_contained", lambda *a, **k: _completed(
            json.dumps({"status": "ok", "trace": _trace(
                apis=9, truncated=True, truncation_reason="api_cap",
                features={"persistence": True})})))
        result = provider.run(tmp_path / "x.exe", {})
        assert detonation.state_of(result) == detonation.OBSERVED
        assert "truncated" in result["reason"]

    def test_worker_unavailable_is_not_attempted(self, native, tmp_path):
        """Must fail against a schema with no unavailability state.

        The trace schema alone cannot say "Speakeasy is missing", and an
        empty trace would otherwise map to `failed` — reporting a broken
        emulation where none was ever attempted.
        """
        native.setattr(provider, "run_contained", lambda *a, **k: _completed(
            json.dumps({"status": "unavailable",
                        "reason": "ImportError: No module named 'distutils'"})))
        result = provider.run(tmp_path / "x.exe", {})
        assert detonation.state_of(result) == detonation.NOT_ATTEMPTED
        assert "distutils" in result["reason"]

    def test_unparseable_output_is_failed_and_the_scan_survives(self, native, tmp_path):
        native.setattr(provider, "run_contained",
                       lambda *a, **k: _completed("not json at all", returncode=1))
        result = provider.run(tmp_path / "x.exe", {})
        assert detonation.state_of(result) == detonation.FAILED

    def test_outer_timeout_is_failed_with_a_reason(self, native, tmp_path):
        def _boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="x", timeout=90)
        native.setattr(provider, "run_contained", _boom)
        result = provider.run(tmp_path / "x.exe", {})
        assert detonation.state_of(result) == detonation.FAILED
        assert "timed out" in result["reason"].lower()

    def test_worker_that_cannot_start_does_not_kill_the_scan(self, native, tmp_path):
        def _boom(*a, **k):
            raise OSError("no interpreter")
        native.setattr(provider, "run_contained", _boom)
        assert provider.run(tmp_path / "x.exe", {})["status"] == "error"


class TestUnloadable:
    def test_unloadable_pe_is_failed_not_skipped(self, native, tmp_path):
        """Must fail against mapping `unloadable` to not_attempted.

        Applicability already proved this is a supported native PE, so the
        worker did attempt a detonation — load_module does the full
        directory parse, section mapping and import resolution, and a
        packed or header-tampered sample is precisely what breaks it.
        Reporting "never attempted" would hide a failed detonation, which
        D-3 exists to render.
        """
        # A reason only reachable AFTER applicability passed: pefile parsed
        # the headers in the parent, and Speakeasy's own loader — which
        # also maps sections and resolves imports — then failed. A
        # PEFormatError would have been caught in the parent instead and
        # is correctly not_attempted, because we never classified the file.
        native.setattr(provider, "run_contained", lambda *a, **k: _completed(
            json.dumps({"status": "ok", "trace": {
                "unloadable": "SpeakeasyError: Failed to map section .text"}})))
        result = provider.run(tmp_path / "packed.exe", {})
        assert detonation.state_of(result) == detonation.FAILED
        assert result["status"] == "error"


class TestTruncationIsHonest:
    """Truncation is claimed only when something was actually cut short."""

    def test_all_clean_entry_points_are_not_truncated(self):
        """Must fail against claiming truncation from cumulative totals.

        Speakeasy's budgets are per entry point and the worker cannot halt
        it part-way, so a total crossing a single-entry budget means
        nothing was cut short — every entry point still ran to a clean
        return.
        """
        truncated, reason, ended = worker._summarise(["clean", "clean"], False)
        assert truncated is False
        assert reason is None
        assert ended == "clean"

    def test_a_real_timeout_is_not_relabelled(self):
        """Must fail against letting a cumulative API total overwrite the
        reason: a run that only timed out would report "api_cap"."""
        _, reason, ended = worker._summarise(["clean", "timeout"], False)
        assert reason == "timeout"
        assert ended == "timeout"

    def test_a_cap_stop_is_reported_as_a_cap(self):
        truncated, reason, _ = worker._summarise(["api_cap"], False)
        assert (truncated, reason) == (True, "api_cap")

    def test_one_fault_among_clean_entry_points_is_not_a_whole_file_fault(self):
        """Exports are invoked with synthesised arguments, so a fault on one
        says nothing about the sample."""
        assert worker._summarise(["clean", "fault"], False)[2] == "clean"

    def test_every_entry_point_faulting_is_a_fault(self):
        assert worker._summarise(["fault", "fault"], False)[2] == "fault"

    def test_no_entry_points_plus_an_interrupt_is_a_fault(self):
        assert worker._summarise([], True)[2] == "fault"

    def test_no_entry_points_at_all_is_a_fault_not_clean(self):
        """Must fail against reporting an empty report as "clean".

        load_module succeeded or _run would have returned already, so
        Speakeasy did run something — an empty entry-point list means the
        report failed to describe it, which includes the case where
        get_report() itself raised. Calling that "clean" is a claim about
        a run we cannot see, and it contradicts the provider, which turns
        an empty trace into a failed detonation.
        """
        assert worker._summarise([], False)[2] == "fault"

    def test_an_interrupt_truncates_even_when_earlier_entries_were_clean(self):
        """Must fail against consulting `interrupted` only when nothing ran.

        An unhandled exception out of run_module ends the queue: the entry
        point then running was cut off and everything still queued never
        ran. Reporting that as a clean, un-truncated emulation because
        DllMain happened to succeed first describes a run that did not
        happen.
        """
        truncated, reason, ended = worker._summarise(["clean", "clean"], True)
        assert (truncated, reason, ended) == (True, "interrupted", "fault")


class TestProcessBoundary:
    def test_no_config_value_reaches_argv(self, native, tmp_path):
        """Must fail against serialising the config dict onto the command
        line — design rule 9, and ``/proc/PID/cmdline`` is world-readable."""
        seen = {}

        def _capture(argv, **kwargs):
            seen["argv"] = argv
            seen["env"] = kwargs.get("env", {})
            return _completed(json.dumps({"status": "ok", "trace": _trace(apis=1)}))

        native.setattr(provider, "run_contained", _capture)
        provider.run(tmp_path / "x.exe",
                     {"virustotal_api_key": "SECRET-KEY-VALUE",
                      "speakeasy_timeout_seconds": 5})
        assert not any("SECRET-KEY-VALUE" in part for part in seen["argv"])

    def test_credentials_are_stripped_from_the_worker_environment(self, native,
                                                                  tmp_path, monkeypatch):
        """Must fail against passing ``os.environ`` straight through.

        The worker emulates attacker-controlled instructions under a unicorn
        with a published escape; a key reachable from inside it is a key the
        escape gets.
        """
        monkeypatch.setenv("THREATLENS_VT_KEY", "SECRET-KEY-VALUE")
        seen = {}

        def _capture(argv, **kwargs):
            seen["env"] = kwargs.get("env", {})
            return _completed(json.dumps({"status": "ok", "trace": _trace(apis=1)}))

        native.setattr(provider, "run_contained", _capture)
        provider.run(tmp_path / "x.exe", {})
        assert "THREATLENS_VT_KEY" not in seen["env"]

    def test_outer_timeout_exceeds_the_inner_bound(self, native, tmp_path):
        """The graceful path must be reachable: if the hard kill fired first
        every sample would report `failed` and the emulator would look
        broken rather than misconfigured."""
        seen = {}

        def _capture(argv, **kwargs):
            seen["timeout"] = kwargs["timeout"]
            return _completed(json.dumps({"status": "ok", "trace": _trace(apis=1)}))

        native.setattr(provider, "run_contained", _capture)
        provider.run(tmp_path / "x.exe", {"speakeasy_timeout_seconds": 60})
        assert seen["timeout"] > 60


class TestMalformedHeaders:
    def test_missing_optional_header_does_not_escape(self, monkeypatch, tmp_path):
        """Must fail against a bare try/finally with no except.

        A COFF-like file with SizeOfOptionalHeader == 0 loads without
        raising but never gets an OPTIONAL_HEADER, so touching it raises
        AttributeError straight into the pipeline — design rule 2.
        """
        class _Headless:
            FILE_HEADER = type("H", (), {"Machine": 0x014C})()

            def close(self):
                pass

        _patch_pefile(monkeypatch, _Headless())
        result = provider.run(tmp_path / "x.exe", {})
        assert result["status"] == "skipped"
        assert detonation.state_of(result) == detonation.NOT_ATTEMPTED


class TestArgvSeparator:
    def test_a_leading_dash_in_the_path_is_not_parsed_as_a_flag(self, native,
                                                                tmp_path):
        """Must fail against argv built without "--"."""
        seen = {}

        def _capture(argv, **kwargs):
            seen["argv"] = argv
            return _completed(json.dumps({"status": "ok", "trace": _trace(apis=1)}))

        native.setattr(provider, "run_contained", _capture)
        provider.run(Path("-weird-name.exe"), {})
        argv = seen["argv"]
        assert "--" in argv, "no separator: a leading dash would parse as a flag"
        # Resolution alone would also defuse this one, since an absolute
        # path cannot start with "-". The separator stays because it is the
        # guarantee that does not depend on resolution succeeding.
        assert argv.index("--") == len(argv) - 2
        assert argv[-1].endswith("-weird-name.exe")

    def test_the_sample_path_is_absolute(self, native, tmp_path):
        """Must fail against passing the path through unresolved.

        run_contained overrides the worker's cwd to the repo root, so a
        relative path checked in the parent would be reopened against a
        different directory — reporting a good PE as unloadable for anyone
        scanning from outside the repo.
        """
        seen = {}

        def _capture(argv, **kwargs):
            seen["argv"] = argv
            seen["cwd"] = kwargs.get("cwd")
            return _completed(json.dumps({"status": "ok", "trace": _trace(apis=1)}))

        native.setattr(provider, "run_contained", _capture)
        provider.run(Path("relative-name.exe"), {})
        assert Path(seen["argv"][-1]).is_absolute()


class TestRuntimeResolvedImports:
    """The one part of the emulator that measurably pays off here."""

    def test_they_are_reported_in_the_reason(self, native, tmp_path):
        """13 of 21 corpus PEs resolve imports at runtime; an analyst
        should see that without opening the raw JSON."""
        native.setattr(provider, "run_contained", lambda *a, **k: _completed(
            json.dumps({"status": "ok", "trace": _trace(
                apis=5, dyn_imports=["GetProcAddress"] * 41,
                dyn_import_total=41)})))
        assert "41 imports resolved at runtime" in provider.run(
            tmp_path / "x.exe", {})["reason"]

    def test_they_are_not_scored(self, native, tmp_path):
        """Must fail against weighting them.

        Legitimate packed and licensed software resolves imports the same
        way, and this project has no benign corpus, so the false-positive
        rate is unmeasured. Scoring it would move every packed sample on an
        untested assumption.
        """
        delta, _ = provider._score(_trace(
            dyn_imports=["GetProcAddress"] * 41, dyn_import_total=41))
        assert delta == 0

    def test_they_count_as_an_observation(self, native, tmp_path):
        """A run that resolved imports and nothing else still looked at
        something, so it is `observed` — not a failed detonation."""
        native.setattr(provider, "run_contained", lambda *a, **k: _completed(
            json.dumps({"status": "ok", "trace": _trace(
                apis=0, dyn_imports=["LoadLibraryA"], dyn_import_total=1)})))
        result = provider.run(tmp_path / "x.exe", {})
        assert detonation.state_of(result) == detonation.OBSERVED


class TestDynImportCollection:
    def test_names_survive_whatever_shape_they_arrive_in(self):
        class _SE:
            def get_dyn_imports(self):
                return ["kernel32.LoadLibraryA", {"name": "GetProcAddress"}, 42]

        names, total = worker._collect_dyn_imports(_SE())
        assert total == 3
        assert "kernel32.LoadLibraryA" in names
        assert "GetProcAddress" in names

    def test_a_dead_engine_yields_nothing_rather_than_raising(self):
        class _SE:
            def get_dyn_imports(self):
                raise AttributeError("'NoneType' object has no attribute ...")

        assert worker._collect_dyn_imports(_SE()) == ([], 0)


class TestScoring:
    def test_delta_is_never_negative(self):
        """D-1 clamps in the pipeline too, but a provider that relies on the
        backstop is already wrong."""
        delta, _ = provider._score(_trace())
        assert delta >= 0

    def test_dropped_pe_scores_but_a_dropped_text_file_does_not(self):
        with_pe, _ = provider._score(_trace(features={"dropped_pe": True}))
        without, _ = provider._score(_trace(features={"dropped_pe": False}))
        assert with_pe - without == provider._DROPPED_PE_WEIGHT

    def test_a_pe_dropped_past_the_cap_still_scores(self):
        """Must fail against scoring from the capped `dropped` list.

        The worker caps that list to bound the pipe, so a sample writing a
        hundred decoys before its payload would hide the PE from scoring.
        The fact travels as a feature instead.
        """
        delta, _ = provider._score(_trace(dropped=[], features={"dropped_pe": True}))
        assert delta == provider._DROPPED_PE_WEIGHT

    def test_emulating_alone_scores_zero(self):
        """D-7: weight the finding, not the stage."""
        assert provider._score(_trace(apis=500))[0] == 0


class TestAvailability:
    def test_selected_provider_is_available(self):
        assert provider.is_available({"dynamic_provider": "speakeasy"}) is True

    def test_other_providers_are_not(self):
        assert provider.is_available({"dynamic_provider": "none"}) is False
        assert provider.is_available({}) is False


# ======================================================================
# The one test that really emulates
# ======================================================================

@pytest.mark.corpus_slow
@pytest.mark.skipif(not PE_DIR.exists(), reason="corpus not present")
def test_real_emulation_produces_a_trace():
    pytest.importorskip("speakeasy")
    sample = PE_DIR / "Amadey.exe"
    if not sample.exists():
        pytest.skip("Amadey.exe not in corpus")
    trace = worker._run(str(sample), 20, 5000)
    assert trace["api_total"] > 0
    assert trace["ended"] in ("clean", "fault", "api_cap", "timeout")
