"""archive_analysis must not leave extracted payloads on disk.

A scan materialises members into a temp directory so the MIME and embedded-PE
checks have bytes to look at. Those bytes are malware. Every path out of the
module — success, handler error, bomb guard trip, exception — has to clean up
after itself, or a triage run over a directory of samples quietly fills /tmp
with live payloads.
"""

from __future__ import annotations

import gzip
import tempfile
from pathlib import Path

import pytest

from modules.static.archive_analysis import run


def _temp_children() -> set[Path]:
    root = Path(tempfile.gettempdir())
    return {p for p in root.iterdir()} if root.is_dir() else set()


def _leaked(before: set[Path], prefixes: tuple[str, ...]) -> list[Path]:
    new = _temp_children() - before
    return sorted(p for p in new if p.name.startswith(prefixes))


_PREFIXES = ("archive_extract_", "single_stream_", "sfx_overlay_")


@pytest.fixture
def no_temp_leak():
    """Fail the test if the module leaves anything of ours behind."""
    before = _temp_children()
    yield
    leaked = _leaked(before, _PREFIXES)
    # Clean up regardless so one failure does not cascade.
    for p in leaked:
        try:
            if p.is_dir():
                import shutil

                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
        except OSError:
            pass
    assert leaked == [], f"left behind in temp: {[p.name for p in leaked]}"


def test_gzip_scan_leaves_no_temp_directory(tmp_path, no_temp_leak):
    """The single-stream path built its own tempdir that nothing cleaned up."""
    target = tmp_path / "payload.gz"
    with gzip.open(target, "wb") as fh:
        fh.write(b"MZ" + b"\x00" * 4096)

    result = run(target, {})
    assert result["status"] in ("success", "skipped")


def test_bzip2_scan_leaves_no_temp_directory(tmp_path, no_temp_leak):
    import bz2

    target = tmp_path / "payload.bz2"
    target.write_bytes(bz2.compress(b"MZ" + b"\x00" * 4096))
    assert run(target, {})["status"] in ("success", "skipped")


def test_xz_scan_leaves_no_temp_directory(tmp_path, no_temp_leak):
    import lzma

    target = tmp_path / "payload.xz"
    target.write_bytes(lzma.compress(b"MZ" + b"\x00" * 4096))
    assert run(target, {})["status"] in ("success", "skipped")


def test_zip_scan_leaves_no_temp_directory(tmp_path, no_temp_leak):
    import zipfile

    target = tmp_path / "bundle.zip"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("inner.exe", b"MZ" + b"\x00" * 2048)
    assert run(target, {})["status"] == "success"


def test_single_stream_payload_is_still_analysed(tmp_path):
    """Cleaning up must not cost us the inner-payload inspection.

    The decompressed bytes are what the MIME and embedded-PE checks read,
    so the fix has to keep them alive until the indicators have run.
    """
    target = tmp_path / "dropper.gz"
    with gzip.open(target, "wb") as fh:
        fh.write(b"MZ\x90\x00" + b"\x00" * 8192)

    data = run(target, {}).get("data", {})
    assert data.get("entry_count") == 1
    assert data.get("entries"), "the inner payload must still be enumerated"


# ----------------------------------------------------------------------
# A tripped bomb guard must stop downstream work, single-stream included
# ----------------------------------------------------------------------

def test_single_stream_bomb_does_not_mark_itself_extracted(tmp_path, monkeypatch):
    """`extracted` gates the mime, embedded-PE and recursion blocks.

    gz/bz2/xz decompress during enumeration, so they have a payload on disk
    before the guard runs. That is unavoidable for a format with no member
    listing — but once the guard trips, nothing further may touch it, and
    recursion above all.
    """
    import modules.static.archive_analysis as arch

    target = tmp_path / "bomb.gz"
    with gzip.open(target, "wb") as fh:
        fh.write(b"\x00" * (40 * 1024 * 1024))

    recursed = []
    monkeypatch.setattr(
        arch, "_recurse_into_inner_archives",
        lambda **kw: recursed.append(kw) or [],
    )

    data = run(target, {})["data"]

    assert data["bomb_guard"]["triggered"] is True
    assert recursed == [], "a tripped bomb guard must not recurse"
    assert "bomb_guard" in data["indicator_flags"]


def test_extraction_errors_reach_the_report(tmp_path, monkeypatch):
    """A failed extract is appended to meta after data['errors'] was copied.

    list() takes a snapshot, so anything appended later — every extraction
    failure — was dropped before the caller ever saw it.
    """
    import modules.static.archive_analysis as arch

    import zipfile

    target = tmp_path / "bundle.zip"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("inner.bin", b"A" * 1024)

    def _boom(*_a, **_kw):
        raise RuntimeError("extractor exploded")

    monkeypatch.setattr(arch, "_dispatch_extract", _boom)

    data = run(target, {})["data"]
    stages = [e.get("stage") for e in data.get("errors", [])]
    assert "extract" in stages, f"extraction failure was silenced: {data.get('errors')}"


def test_sfx_payload_dump_removes_its_file_when_the_write_fails(
    monkeypatch, no_temp_leak,
):
    """A failed write left the already-created tempfile on disk.

    ``_dump_payload`` opens with ``delete=False`` because the payload has to
    outlive the call. If the write then fails — a full disk is the realistic
    case — the old code returned None with the file already created, and
    returning None means the caller never learns a path it could clean up.
    Those are carved malware bytes, so they stay in /tmp until the host is
    rebooted.
    """
    import tempfile as _tempfile

    from modules.static.archive_analysis import sfx_detect

    real_factory = _tempfile.NamedTemporaryFile
    created: list[Path] = []

    def failing_factory(*args, **kwargs):
        handle = real_factory(*args, **kwargs)
        created.append(Path(handle.name))

        def boom(_data):
            raise OSError(28, "No space left on device")

        handle.write = boom
        return handle

    monkeypatch.setattr(
        sfx_detect.tempfile, "NamedTemporaryFile", failing_factory,
    )

    assert sfx_detect._dump_payload(b"MZ" + b"\x00" * 64) is None
    assert created, "the test did not exercise the tempfile path"
    assert not created[0].exists(), (
        f"payload tempfile survived a failed write: {created[0]}"
    )


def test_sfx_payload_dump_removes_its_file_on_a_non_oserror(
    monkeypatch, no_temp_leak,
):
    """Cleanup must not depend on the exception being an OSError.

    An overlay can be hundreds of megabytes, so MemoryError is a realistic
    failure here, and a triage run is exactly where someone presses Ctrl-C.
    Neither inherits from OSError, so an ``except OSError`` cleanup is
    skipped and the payload survives. The exception itself is allowed to
    propagate — swallowing KeyboardInterrupt would be worse — but the file
    must be gone either way.
    """
    import tempfile as _tempfile

    from modules.static.archive_analysis import sfx_detect

    real_factory = _tempfile.NamedTemporaryFile
    created: list[Path] = []

    def failing_factory(*args, **kwargs):
        handle = real_factory(*args, **kwargs)
        created.append(Path(handle.name))

        def boom(_data):
            raise MemoryError("cannot allocate overlay copy")

        handle.write = boom
        return handle

    monkeypatch.setattr(
        sfx_detect.tempfile, "NamedTemporaryFile", failing_factory,
    )

    with pytest.raises(MemoryError):
        sfx_detect._dump_payload(b"MZ" + b"\x00" * 64)

    assert created, "the test did not exercise the tempfile path"
    assert not created[0].exists(), (
        f"payload tempfile survived a non-OSError failure: {created[0]}"
    )


def test_sfx_payload_dump_fails_when_the_close_fails(monkeypatch, no_temp_leak):
    """A write that never reaches disk must not be reported as a payload.

    ``write`` on a buffered file can succeed while the data is still in
    memory; the flush happens at ``close``. If that flush fails — the full
    disk again — the file on disk is short or empty. Returning its path
    would hand the orchestrator a truncated payload to recurse into and
    score, which is a wrong answer rather than a missing one. The dump has
    to fail, and take the file with it.
    """
    import tempfile as _tempfile

    from modules.static.archive_analysis import sfx_detect

    real_factory = _tempfile.NamedTemporaryFile
    created: list[Path] = []

    def failing_factory(*args, **kwargs):
        handle = real_factory(*args, **kwargs)
        created.append(Path(handle.name))
        real_close = handle.close

        def boom():
            real_close()
            raise OSError(28, "No space left on device")

        handle.close = boom
        return handle

    monkeypatch.setattr(
        sfx_detect.tempfile, "NamedTemporaryFile", failing_factory,
    )

    assert sfx_detect._dump_payload(b"MZ" + b"\x00" * 64) is None
    assert created, "the test did not exercise the tempfile path"
    assert not created[0].exists(), (
        f"payload tempfile survived a failed close: {created[0]}"
    )


def test_sfx_payload_dump_survives_an_interrupt_during_close(
    monkeypatch, no_temp_leak,
):
    """Cleanup must not sit behind anything that can be interrupted.

    Ctrl-C is asynchronous: it lands wherever the interpreter happens to
    be, including inside the cleanup path itself. KeyboardInterrupt derives
    from BaseException, so an ``except OSError`` around a close() call in
    the same block as the unlink lets it skip the unlink entirely. The
    unlink therefore has to be the only statement that cannot be bypassed.
    """
    import tempfile as _tempfile

    from modules.static.archive_analysis import sfx_detect

    real_factory = _tempfile.NamedTemporaryFile
    created: list[Path] = []

    def failing_factory(*args, **kwargs):
        handle = real_factory(*args, **kwargs)
        created.append(Path(handle.name))

        def boom(_data):
            raise KeyboardInterrupt

        handle.write = boom
        real_close = handle.close

        def interrupted_close():
            real_close()
            raise KeyboardInterrupt

        handle.close = interrupted_close
        return handle

    monkeypatch.setattr(
        sfx_detect.tempfile, "NamedTemporaryFile", failing_factory,
    )

    with pytest.raises(KeyboardInterrupt):
        sfx_detect._dump_payload(b"MZ" + b"\x00" * 64)

    assert created, "the test did not exercise the tempfile path"
    assert not created[0].exists(), (
        f"payload tempfile survived an interrupt: {created[0]}"
    )
