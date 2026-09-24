"""onenote_analysis must not be removable by padding a file.

Skipping on size returns score 0, so appending bytes past the cap deletes
the module from a scan — the same shape that turned out to be an evasion in
lnk_analysis. The fix there was to bound the read, which does not transfer:
FileDataStoreObject records are scattered throughout a .one file, so a
truncated read loses real payloads rather than just their digests.
"""

from __future__ import annotations

import pathlib

import pytest

from modules.static.onenote_analysis import run
from modules.static.onenote_analysis.parser import walk_file_data_store_objects

_SAMPLE = pathlib.Path(
    "/home/pmafma/Documents/Malware/onenote test malware/Redline.one"
)

pytestmark = pytest.mark.skipif(
    not _SAMPLE.exists(), reason="corpus sample unavailable"
)


def test_padding_a_notebook_past_the_size_cap_does_not_skip_it(tmp_path):
    """The bypass: 51 MiB of nulls and the module returns nothing.

    Measured before the fix — the sample classifies MALICIOUS untouched
    and came back skipped with score 0 once padded.
    """
    original = run(_SAMPLE, {})
    assert original["data"]["classification"] == "MALICIOUS"

    padded = tmp_path / "padded.one"
    padded.write_bytes(_SAMPLE.read_bytes() + b"\x00" * (51 * 1024 * 1024))

    result = run(padded, {})

    assert result["status"] == "success"
    assert result["data"]["classification"] == "MALICIOUS"
    assert result["score_delta"] == original["score_delta"]


def test_a_payload_at_the_end_of_a_large_file_is_still_found(tmp_path):
    """Truncating the read would lose it, which is why the file is mapped.

    A .one file's records are scattered, not front-loaded. This puts the
    real notebook *after* 51 MiB of padding, where a bounded prefix read
    would never reach it.
    """
    trailing = tmp_path / "trailing.one"
    trailing.write_bytes(
        _SAMPLE.read_bytes()[:16] + b"\x00" * (51 * 1024 * 1024)
        + _SAMPLE.read_bytes()
    )

    result = run(trailing, {})

    assert result["status"] == "success"
    assert result["data"]["blob_count"] > 0


def test_an_absurd_declared_payload_length_is_not_materialised(tmp_path):
    """cbLength is attacker-controlled and drives a slice.

    Mapping the file means a record claiming gigabytes would be copied
    out of the mapping into memory by that slice. The per-blob ceiling is
    what stops one crafted length field doing what the file size cap used
    to guard against.
    """
    from modules.static.onenote_analysis.parser import (
        FILE_DATA_STORE_GUID,
        ONESTORE_HEADER_GUID,
    )

    crafted = (
        ONESTORE_HEADER_GUID
        + b"\x00" * 64
        + FILE_DATA_STORE_GUID
        + (2**40).to_bytes(8, "little")   # a terabyte, declared
        + b"\x00" * 12
        + b"MZ" + b"\x00" * 64
    )
    path = tmp_path / "absurd.one"
    path.write_bytes(crafted)

    blobs = walk_file_data_store_objects(crafted, max_payload_bytes=1024)

    assert blobs == []
    assert run(path, {})["status"] == "success"


def test_an_ordinary_notebook_is_unchanged(tmp_path):
    """The common path must behave exactly as before."""
    result = run(_SAMPLE, {})

    assert result["status"] == "success"
    assert result["data"]["blob_count"] == 7


def test_many_large_blobs_cannot_accumulate_past_the_budget(tmp_path):
    """A per-blob ceiling alone traded one memory bound for a worse one.

    Slicing a mapped file allocates a real bytes object, and the walker
    returns every payload in a list before anything consumes them. With
    only a per-record ceiling, max_blobs (200) times max_payload (50 MiB)
    is 10 GiB resident — worse than the whole-file cap that mapping
    replaced. The ceiling is a cumulative budget, so the total is what is
    bounded.
    """
    from modules.static.onenote_analysis.parser import (
        FILE_DATA_STORE_GUID,
        ONESTORE_HEADER_GUID,
    )

    payload = b"MZ" + b"\x00" * 4094          # 4 KiB per record
    record = FILE_DATA_STORE_GUID + len(payload).to_bytes(8, "little") \
        + b"\x00" * 12 + payload
    crafted = ONESTORE_HEADER_GUID + b"\x00" * 32 + record * 40

    blobs = walk_file_data_store_objects(
        crafted, max_blobs=200, max_payload_bytes=10 * 1024,
    )

    assert sum(len(p) for _, p in blobs) <= 10 * 1024
    assert len(blobs) < 40, "budget did not stop the accumulation"


def test_the_non_mappable_fallback_read_is_bounded(tmp_path, monkeypatch):
    """mmap fails on some filesystems, and the old size guard is gone.

    OSError from mmap is not only the empty-file case — FUSE and some
    network mounts refuse mapping, and a huge file can exhaust address
    space. Falling back to an unbounded read() there would pull the whole
    file into memory, which is the failure the size cap used to prevent.

    Asserted behaviourally: with the bound lowered, a record sitting past
    it is not recovered on the fallback path, while mapping finds it.
    """
    import mmap as mmap_module

    from modules.static import onenote_analysis
    from modules.static.onenote_analysis.parser import (
        FILE_DATA_STORE_GUID,
        ONESTORE_HEADER_GUID,
    )

    payload = b"MZ" + b"\x00" * 512
    record = (
        FILE_DATA_STORE_GUID
        + len(payload).to_bytes(8, "little")
        + b"\x00" * 12
        + payload
    )
    path = tmp_path / "far.one"
    path.write_bytes(ONESTORE_HEADER_GUID + b"\x00" * 8192 + record)

    # Mapped: the record past the bound is found.
    assert onenote_analysis.run(path, {})["data"]["blob_count"] == 1

    monkeypatch.setattr(onenote_analysis, "_FALLBACK_READ_BYTES", 4096)
    monkeypatch.setattr(
        mmap_module, "mmap",
        lambda *a, **k: (_ for _ in ()).throw(OSError("unsupported")),
    )

    result = onenote_analysis.run(path, {})

    assert result["status"] == "success"
    assert result["data"]["blob_count"] == 0, "fallback read was not bounded"


def test_an_over_budget_payload_is_skipped_not_scanned_through():
    """Resuming inside a valid payload finds records that are not records.

    A blob refused for budget is still structurally sound, so its extent
    is known and the scan can step over it. Resuming at the header
    instead walked the payload byte by byte — wasted work, and it reports
    any GUID *inside* the opaque payload as though it were a top-level
    record, which is a finding the file does not contain.
    """
    from modules.static.onenote_analysis.parser import (
        FILE_DATA_STORE_GUID,
        ONESTORE_HEADER_GUID,
    )

    # An over-budget record whose payload happens to contain the marker.
    inner = FILE_DATA_STORE_GUID + (16).to_bytes(8, "little") + b"\x00" * 12 + b"X" * 16
    payload = b"\x00" * 64 + inner + b"\x00" * 64
    record = (
        FILE_DATA_STORE_GUID
        + len(payload).to_bytes(8, "little")
        + b"\x00" * 12
        + payload
    )
    crafted = ONESTORE_HEADER_GUID + b"\x00" * 32 + record

    blobs = walk_file_data_store_objects(crafted, max_payload_bytes=32)

    assert blobs == [], f"scanned into the payload: {blobs}"
