"""file_intake tests — hashing, backend selection and the ppdeep size cap.

The cap exists because ``ppdeep``, the pure-Python ssdeep fallback, costs a
measured 0.78 s/MB on this corpus and up to 4.4 s/MB on a sample that forces
ssdeep to halve its blocksize and rescan. A 30 MB archive took 227 s in
``file_intake`` while the rest of the scan took 0.3 s. The C ``ssdeep``
extension is roughly two orders of magnitude faster and is deliberately left
uncapped.
"""

from __future__ import annotations

import pytest

from core import file_intake
from core.config_loader import DEFAULTS


# ----------------------------------------------------------------------
# The cap's default and its home in DEFAULTS
# ----------------------------------------------------------------------

def test_ppdeep_cap_has_a_default_in_config_defaults():
    """The no-config path must behave identically to the configured one."""
    assert "max_ppdeep_size_mb" in DEFAULTS
    assert DEFAULTS["max_ppdeep_size_mb"] == 8


# ----------------------------------------------------------------------
# The cap applies to the pure-Python backend only
# ----------------------------------------------------------------------

def _write(tmp_path, name, size):
    p = tmp_path / name
    p.write_bytes(b"A" * size)
    return p


def test_pure_python_backend_skips_a_file_over_the_cap(tmp_path, monkeypatch):
    """Over the cap on ppdeep, ssdeep is None rather than a 200-second stall."""
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", True)

    called = []

    class _Boom:
        @staticmethod
        def hash(_data):
            called.append(1)
            raise AssertionError("ppdeep must not be called above the cap")

    monkeypatch.setattr(file_intake, "ssdeep", _Boom, raising=False)

    target = _write(tmp_path, "big.bin", 2048)
    hashes = file_intake._compute_hashes(target, {"max_ppdeep_size_mb": 0.001})

    assert hashes["ssdeep"] is None
    assert called == []
    # The cheap hashes are unaffected — only the fuzzy hash is dropped.
    assert hashes["sha256"]
    assert hashes["md5"]


def test_pure_python_backend_still_hashes_under_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", True)

    class _Stub:
        @staticmethod
        def hash(_data):
            return "3:stub:stub"

    monkeypatch.setattr(file_intake, "ssdeep", _Stub, raising=False)

    target = _write(tmp_path, "small.bin", 512)
    hashes = file_intake._compute_hashes(target, {"max_ppdeep_size_mb": 8})

    assert hashes["ssdeep"] == "3:stub:stub"


def test_c_backend_is_not_capped(tmp_path, monkeypatch):
    """The C extension is fast enough that a size cap would only lose data."""
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", False)

    class _Stub:
        @staticmethod
        def hash(_data):
            return "3:cbackend:cbackend"

    monkeypatch.setattr(file_intake, "ssdeep", _Stub, raising=False)

    target = _write(tmp_path, "big.bin", 2048)
    hashes = file_intake._compute_hashes(target, {"max_ppdeep_size_mb": 0.001})

    assert hashes["ssdeep"] == "3:cbackend:cbackend"


def test_cap_is_configurable(tmp_path, monkeypatch):
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", True)

    class _Stub:
        @staticmethod
        def hash(_data):
            return "3:configured:configured"

    monkeypatch.setattr(file_intake, "ssdeep", _Stub, raising=False)

    target = _write(tmp_path, "mid.bin", 4096)

    # 4096 bytes is under 1 MiB, so a generous cap hashes it...
    assert file_intake._compute_hashes(
        target, {"max_ppdeep_size_mb": 1},
    )["ssdeep"] == "3:configured:configured"

    # ...and a cap below the file size drops it.
    assert file_intake._compute_hashes(
        target, {"max_ppdeep_size_mb": 0.001},
    )["ssdeep"] is None


def test_missing_config_key_falls_back_to_the_default(tmp_path, monkeypatch):
    """An empty config must not disable the guard.

    Asserting that a tiny file still hashes would only prove the fallback
    exceeds 256 bytes — a regression setting it to infinity would pass that.
    So this pins the ceiling: a file over the 8 MiB default must be skipped
    when the key is absent entirely.
    """
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", True)

    calls = []

    class _Stub:
        @staticmethod
        def hash(_data):
            calls.append(1)
            return "3:default:default"

    monkeypatch.setattr(file_intake, "ssdeep", _Stub, raising=False)

    under = _write(tmp_path, "under.bin", 256)
    assert file_intake._compute_hashes(under, {})["ssdeep"] == "3:default:default"
    assert calls == [1]

    over = _write(tmp_path, "over.bin", 9 * 1024 * 1024)
    assert file_intake._compute_hashes(over, {})["ssdeep"] is None
    assert calls == [1], "the default ceiling must still apply with no config key"


# ----------------------------------------------------------------------
# The skip must be visible, not silent
# ----------------------------------------------------------------------

def test_skipping_over_the_cap_is_logged(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", True)

    target = _write(tmp_path, "big.bin", 4096)
    with caplog.at_level("WARNING"):
        file_intake._compute_hashes(target, {"max_ppdeep_size_mb": 0.001})

    assert any(
        "ssdeep" in r.message.lower() for r in caplog.records
    ), "the dropped fuzzy hash must say why it was dropped"


# ----------------------------------------------------------------------
# run() threads config through — the cap is useless if run() ignores it
# ----------------------------------------------------------------------

def test_run_passes_config_into_hashing(tmp_path, monkeypatch):
    """run() must hand the config to _compute_hashes, not drop it.

    Raising from the stub cannot prove this: ``_compute_hashes`` wraps the
    ssdeep call in ``except Exception``, and AssertionError is an Exception,
    so a raised failure is swallowed and the result is None either way —
    exactly what the cap produces. Verified by sabotage: with the config
    argument removed from run()'s call, a raising stub still passed. Record
    the call instead and assert it never happened.
    """
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", True)

    calls = []

    class _Recorder:
        @staticmethod
        def hash(_data):
            calls.append(1)
            return "3:shouldnothappen:shouldnothappen"

    monkeypatch.setattr(file_intake, "ssdeep", _Recorder, raising=False)

    target = _write(tmp_path, "big.bin", 4096)
    result = file_intake.run(target, {"max_ppdeep_size_mb": 0.001})

    assert result["status"] == "success"
    assert calls == [], "run() dropped the config — the cap never reached hashing"
    assert result["data"]["hashes"]["ssdeep"] is None


# ----------------------------------------------------------------------
# Backend detection
# ----------------------------------------------------------------------

def test_pure_python_flag_is_defined_and_boolean():
    """Whichever backend loaded, the module must know which one it was."""
    assert isinstance(file_intake._SSDEEP_IS_PURE_PYTHON, bool)
    if not file_intake._HAS_SSDEEP:
        pytest.skip("no ssdeep backend available at all")


# ----------------------------------------------------------------------
# Malformed cap values must degrade, not crash
# ----------------------------------------------------------------------

@pytest.mark.parametrize("bad", [None, "", "eight", [], {}])
def test_unusable_cap_value_falls_back_to_the_default(tmp_path, monkeypatch, bad):
    """A null or non-numeric cap in config.yaml must not kill the pipeline.

    ``.get()`` returns the stored value when the key is present, so an
    explicit ``max_ppdeep_size_mb: null`` reaches the comparison as None.
    Design rule 2 forbids an unhandled exception from a config quirk.
    """
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", True)

    class _Stub:
        @staticmethod
        def hash(_data):
            return "3:fellback:fellback"

    monkeypatch.setattr(file_intake, "ssdeep", _Stub, raising=False)

    target = _write(tmp_path, "small.bin", 256)
    # 256 bytes is under the 8 MiB default, so falling back means hashing.
    hashes = file_intake._compute_hashes(target, {"max_ppdeep_size_mb": bad})
    assert hashes["ssdeep"] == "3:fellback:fellback"


# ----------------------------------------------------------------------
# The uncapped C backend must not load the whole file into memory
# ----------------------------------------------------------------------

def test_c_backend_streams_from_disk_when_it_can(tmp_path, monkeypatch):
    """An uncapped backend reading via read_bytes() is an OOM waiting to happen.

    The C extension is exempt from the size cap, so nothing bounds the file
    it may be handed. ``read_bytes()`` would allocate all of it; a SIGKILL
    from the OOM killer cannot be caught, which would breach design rule 2.
    python-ssdeep ships ``hash_from_file``, so prefer it when present.
    """
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", False)

    seen = {}

    class _CBackend:
        @staticmethod
        def hash_from_file(path):
            seen["path"] = str(path)
            return "3:streamed:streamed"

        @staticmethod
        def hash(_data):
            seen["slurped"] = True
            return "3:slurped:slurped"

    monkeypatch.setattr(file_intake, "ssdeep", _CBackend, raising=False)

    target = _write(tmp_path, "big.bin", 4096)
    hashes = file_intake._compute_hashes(target, {})

    assert hashes["ssdeep"] == "3:streamed:streamed"
    assert seen.get("path") == str(target)
    assert "slurped" not in seen, "must not read the whole file into memory"


def test_backend_without_hash_from_file_still_works(tmp_path, monkeypatch):
    """ppdeep has no hash_from_file — the in-memory path must remain."""
    monkeypatch.setattr(file_intake, "_HAS_SSDEEP", True)
    monkeypatch.setattr(file_intake, "_SSDEEP_IS_PURE_PYTHON", True)

    class _PurePython:
        @staticmethod
        def hash(_data):
            return "3:inmemory:inmemory"

    monkeypatch.setattr(file_intake, "ssdeep", _PurePython, raising=False)

    target = _write(tmp_path, "small.bin", 256)
    assert file_intake._compute_hashes(target, {})["ssdeep"] == "3:inmemory:inmemory"
