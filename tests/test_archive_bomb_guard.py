"""The bomb guard must bound enumeration, not only extraction.

`archive_analysis` documents "bomb guard runs before extraction, so a zip-bomb
can never consume disk". That holds for formats with a central directory: the
member listing is metadata and costs nothing to read.

TAR has no central directory. `getmembers()` walks the whole stream, and for a
compressed tarball that means decompressing all of it just to learn what is
inside — before the guard has had anything to judge. A tar.gz of zeroes is the
classic shape, and the cost is paid during enumeration where no guard was
looking.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import time

import pytest

from modules.static.archive_analysis.tarball_handler import enumerate_tar


def _tar_gz_with(tmp_path, members, name="bomb.tar.gz"):
    """Build a gzipped tar whose members are sparse-ish runs of zeroes."""
    target = tmp_path / name
    with tarfile.open(target, "w:gz") as tf:
        for member_name, size in members:
            info = tarfile.TarInfo(member_name)
            info.size = size
            tf.addfile(info, io.BytesIO(b"\x00" * size))
    return target


def test_ordinary_tarball_still_enumerates_fully(tmp_path):
    """The guard must not cost us normal archives."""
    target = _tar_gz_with(tmp_path, [(f"f{i}.txt", 1024) for i in range(12)])
    entries, meta = enumerate_tar(target, {})
    assert len(entries) == 12
    assert not meta.handler_errors


def test_enumeration_stops_once_declared_size_passes_the_budget(tmp_path):
    """A member declaring more than the whole-tree budget ends the walk.

    The header is read before the data, so the declared size is known
    without decompressing the payload behind it.
    """
    target = _tar_gz_with(tmp_path, [
        ("small.txt", 1024),
        ("huge.bin", 8 * 1024 * 1024),
        ("never_reached.txt", 1024),
    ])

    entries, meta = enumerate_tar(target, {"max_archive_extracted_size_mb": 4})

    names = [e.name for e in entries]
    assert "small.txt" in names
    assert "never_reached.txt" not in names, "walk continued past the budget"
    assert any("budget" in str(e).lower() or "bomb" in str(e).lower()
               for e in meta.handler_errors), meta.handler_errors


def test_enumeration_stops_once_member_count_passes_the_threshold(tmp_path):
    target = _tar_gz_with(tmp_path, [(f"f{i}.txt", 16) for i in range(60)])

    entries, meta = enumerate_tar(
        target, {"archive_bomb_member_count_threshold": 20},
    )

    assert len(entries) <= 21, f"walked {len(entries)} members past a cap of 20"
    assert meta.handler_errors


def test_declared_size_is_rejected_without_reading_the_payload(tmp_path):
    """The guard must act on the header alone, not on inflated bytes.

    A wall-clock assertion cannot prove this: 40 MiB of zeroes inflates in
    well under a second, so a timing test passes on the vulnerable code too
    (measured: 600 MiB via getmembers() takes 2.65s). Raised by Gemini.

    So the bomb here is a header declaring 5 GiB with *no payload behind
    it* — the file ends immediately after the 512-byte header. Rejecting it
    on the declared size costs one header read. Anything that tries to walk
    past the member has to account for 5 GiB that does not exist.
    """
    header = tarfile.TarInfo("huge.bin")
    header.size = 5 * 1024 ** 3

    target = tmp_path / "declared.tar.gz"
    target.write_bytes(gzip.compress(header.tobuf()))

    start = time.monotonic()
    entries, meta = enumerate_tar(target, {"max_archive_extracted_size_mb": 4})
    elapsed = time.monotonic() - start

    assert elapsed < 5.0, f"enumeration took {elapsed:.1f}s"
    assert len(entries) == 1
    assert entries[0].size_uncompressed == 5 * 1024 ** 3
    assert meta.handler_errors, "a 5 GiB member under a 4 MiB budget must be flagged"
    assert "BOMB_BUDGET" in meta.handler_errors[0]["error"]


@pytest.mark.parametrize("call", [
    lambda t: enumerate_tar(t),          # no config argument at all
    lambda t: enumerate_tar(t, None),    # explicit None
    lambda t: enumerate_tar(t, {}),      # empty dict
])
def test_absent_config_uses_defaults(tmp_path, call):
    """All three no-config shapes must work, not just the empty dict."""
    target = _tar_gz_with(tmp_path, [("a.txt", 32)])
    entries, _meta = call(target)
    assert len(entries) == 1


def test_plain_uncompressed_tar_is_unaffected(tmp_path):
    target = tmp_path / "plain.tar"
    with tarfile.open(target, "w") as tf:
        for i in range(5):
            info = tarfile.TarInfo(f"f{i}.txt")
            info.size = 64
            tf.addfile(info, io.BytesIO(b"x" * 64))

    entries, meta = enumerate_tar(target, {})
    assert len(entries) == 5
    assert not meta.handler_errors
