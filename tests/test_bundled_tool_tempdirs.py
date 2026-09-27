"""A killed PyInstaller bundle must not leave its extraction directory behind.

`bin/floss` and `bin/capa` are PyInstaller one-file binaries: the bootloader
unpacks the whole application into ``$TMPDIR/_MEIxxxxxx`` on every run and
removes it on a clean exit. ``subprocess.run(timeout=...)`` terminates a
child with ``kill()`` — SIGKILL, which no bootloader can trap — so a run
that hits its budget leaks the entire extraction.

Measured before the fix: one timed-out `bin/floss` left 62.5 MB behind. That
is per invocation, `floss_timeout_seconds` defaults to 300 and a real corpus
sample emulates for 271.1 s, so the budget is genuinely reachable, and a
`triage` sweep repeats the loss for every file.

These tests pin the containment rather than the signal handling: the child
gets a private ``TMPDIR`` that is removed unconditionally, so what the child
did or did not manage to clean up before dying stops mattering.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest


# ======================================================================
# The helper itself
# ======================================================================
def test_private_extraction_dir_is_removed_after_a_kill(tmp_path, monkeypatch):
    """A child killed mid-run leaves nothing behind."""
    from modules.static._bundled_tool import private_extraction_dir

    monkeypatch.setenv("TMPDIR", str(tmp_path))

    # Stands in for the PyInstaller bootloader: unpacks into $TMPDIR, then
    # hangs until it is killed, exactly as a timing-out FLOSS does.
    script = tmp_path / "fake_bundle.py"
    script.write_text(
        "import tempfile, time\n"
        "tempfile.mkdtemp(prefix='_MEI')\n"
        "time.sleep(30)\n"
    )

    with private_extraction_dir("test_") as env:
        assert env is not None
        private = Path(env["TMPDIR"])
        assert private.is_dir()
        with pytest.raises(subprocess.TimeoutExpired):
            subprocess.run(
                [sys.executable, str(script)],
                capture_output=True,
                timeout=2,
                env=env,
            )
        # The child did leak — that is the whole premise of the fix.
        assert list(private.glob("_MEI*")), "fake bundle did not unpack"

    assert not private.exists(), "extraction directory survived the context"


def test_private_extraction_dir_is_a_fresh_child_of_the_process_tempdir():
    """The private dir is its own directory, not the shared temp root.

    Note it lands under ``tempfile.gettempdir()`` rather than under
    whatever ``$TMPDIR`` says at call time: ``gettempdir()`` resolves the
    environment once per process and caches it, so setting ``TMPDIR``
    later cannot move it. That is fine and is why only the *child's*
    environment is rewritten — what matters is that the directory is
    private to one invocation and is removed, not where it lives.
    """
    import tempfile as _tempfile

    from modules.static._bundled_tool import private_extraction_dir

    root = Path(_tempfile.gettempdir())
    with private_extraction_dir("test_") as env:
        private = Path(env["TMPDIR"])
        assert private.parent == root
        assert private != root
        assert private.is_dir()
    assert not private.exists()
    assert root.is_dir(), "the shared temp root must never be removed"


def test_private_tmpdir_does_not_leak_into_this_process(monkeypatch):
    """Only the child's environment is rewritten, never our own.

    ``archive_analysis`` calls ``tempfile.mkdtemp()`` in the same scan, so
    mutating ``os.environ`` here would silently redirect its extraction
    into a directory this module deletes the moment FLOSS returns.
    """
    from modules.static._bundled_tool import private_extraction_dir

    before = os.environ.get("TMPDIR")
    with private_extraction_dir("test_") as env:
        assert env["TMPDIR"] != os.environ.get("TMPDIR")
        assert os.environ.get("TMPDIR") == before
    assert os.environ.get("TMPDIR") == before


def test_private_extraction_dir_degrades_when_it_cannot_be_made(monkeypatch):
    """Design rule 2: losing the temp dir must not lose the analysis."""
    from modules.static import _bundled_tool

    def _boom(*_a, **_kw):
        raise OSError("no space left on device")

    monkeypatch.setattr(_bundled_tool.tempfile, "mkdtemp", _boom)
    with _bundled_tool.private_extraction_dir("test_") as env:
        # None means "run with the inherited environment" — the tool still
        # runs, it just cleans up the way it did before.
        assert env is None


# ======================================================================
# The two call sites
# ======================================================================
def _timeout_recording_run(recorder):
    """A subprocess.run stand-in that records TMPDIR then times out."""

    def _run(cmd, **kwargs):
        env = kwargs.get("env") or {}
        recorder.append(env.get("TMPDIR"))
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 1))

    return _run


def test_floss_timeout_leaves_no_extraction_dir(tmp_path, monkeypatch):
    from modules.static import string_analysis

    seen: list = []
    monkeypatch.setattr(string_analysis.subprocess, "run", _timeout_recording_run(seen))

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    floss = tmp_path / "floss"
    floss.write_text("#!/bin/sh\n")

    result, reason = string_analysis._run_floss(sample, floss, timeout=1, emulation=True)

    assert reason == "timeout"
    assert result is None
    assert seen and seen[0] is not None, "FLOSS was not given a private TMPDIR"
    assert not Path(seen[0]).exists(), "FLOSS extraction directory leaked"


def test_capa_timeout_leaves_no_extraction_dir(tmp_path, monkeypatch):
    from modules.static import capa_analysis

    seen: list = []
    monkeypatch.setattr(capa_analysis.subprocess, "run", _timeout_recording_run(seen))

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    capa = tmp_path / "capa"
    capa.write_text("#!/bin/sh\n")

    result, timed_out = capa_analysis._run_capa(sample, capa, timeout=1)

    assert timed_out is True
    assert result is None
    assert seen and seen[0] is not None, "capa was not given a private TMPDIR"
    assert not Path(seen[0]).exists(), "capa extraction directory leaked"
