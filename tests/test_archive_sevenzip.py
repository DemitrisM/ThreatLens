"""7z member normalisation.

py7zr reports a member through a ``FileInfo`` object whose field names and
types differ from every other handler's, so the mapping into an
``ArchiveEntry`` is where 7z-specific assumptions live — and where they go
wrong silently, because a wrong timestamp or a wrong encryption flag still
produces a well-formed report.
"""

from __future__ import annotations

import datetime
import os
import time
from pathlib import Path

import pytest

py7zr = pytest.importorskip("py7zr")

from modules.static.archive_analysis.sevenzip_handler import enumerate_7z


def _write_archive(path: Path, payload: Path, password: str | None = None) -> None:
    kwargs = {"password": password} if password else {}
    with py7zr.SevenZipFile(path, "w", **kwargs) as archive:
        archive.write(payload, payload.name)


@pytest.fixture
def sample(tmp_path) -> Path:
    src = tmp_path / "payload.bin"
    src.write_bytes(b"MZ" + b"\x00" * 1000)
    return src


def test_member_timestamps_are_not_shifted_by_the_host_timezone(
    tmp_path, sample, monkeypatch,
):
    """py7zr hands back an aware UTC datetime; mktime read it as local time.

    ``time.mktime`` takes a naive struct_time and interprets it in the
    host's zone. ``datetime.timetuple()`` discards the tzinfo, so a UTC
    timestamp was being converted as though it had been local all along —
    every 7z member's time was wrong by the host's offset, in the direction
    that makes a file from Kyiv look like it came from London. A malware
    report's timestamps are evidence; being uniformly wrong is worse than
    being absent, because nothing about the output says so.
    """
    archive = tmp_path / "plain.7z"
    _write_archive(archive, sample)

    monkeypatch.setenv("TZ", "Asia/Tokyo")  # UTC+9, no daylight saving
    time.tzset()
    try:
        entries, _ = enumerate_7z(archive)
        assert len(entries) == 1
        shifted = entries[0].timestamp
    finally:
        monkeypatch.delenv("TZ", raising=False)
        time.tzset()

    with py7zr.SevenZipFile(archive, "r") as handle:
        info = handle.list()[0]
    expected = int(info.creationtime.timestamp())

    assert shifted == expected, (
        f"timestamp off by {expected - shifted}s — the host offset, not the archive's"
    )


def test_an_encrypted_member_is_flagged(tmp_path, sample):
    """A password-protected archive's members must read as encrypted.

    The flag gates extraction, so a member wrongly read as plaintext is one
    py7zr is then asked to extract without a password.
    """
    archive = tmp_path / "enc.7z"
    _write_archive(archive, sample, password="pw")

    entries, _ = enumerate_7z(archive)

    assert len(entries) == 1
    assert entries[0].is_encrypted is True


def test_a_plain_member_is_not_flagged(tmp_path, sample):
    """And the converse, which the CRC heuristic got right only by accident."""
    archive = tmp_path / "plain.7z"
    _write_archive(archive, sample)

    entries, _ = enumerate_7z(archive)

    assert len(entries) == 1
    assert entries[0].is_encrypted is False


def test_a_directory_member_is_not_mistaken_for_an_encrypted_one(tmp_path):
    """Only directories lack a crc32, so reading CRC would invert the test.

    Measured against py7zr 1.1.0: an encrypted member carries the same
    crc32 as the same bytes stored unencrypted, and the entries that report
    ``crc32 is None`` are the directories. Any future attempt to base the
    encryption flag on CRC presence would therefore flag every folder and
    miss every encrypted payload.
    """
    folder = tmp_path / "sub"
    folder.mkdir()
    (folder / "inner.txt").write_text("hello")
    archive = tmp_path / "withdir.7z"
    with py7zr.SevenZipFile(archive, "w") as handle:
        handle.write(folder, "sub")
        handle.write(folder / "inner.txt", "sub/inner.txt")

    entries, _ = enumerate_7z(archive)

    assert entries, "expected the directory and its member"
    assert not any(e.is_encrypted for e in entries)


def test_the_preflight_budget_counts_encrypted_members(tmp_path, sample, monkeypatch):
    """Excluding encrypted members let a password-protected archive skip the cap.

    py7zr describes encryption only at archive level, so every member of a
    password-protected archive reads as encrypted. Summing just the
    unencrypted ones therefore produced 0 for such an archive, which passes
    any budget — and ``extractall`` then runs unbounded, decompressing
    whatever is not actually encrypted before it fails on whatever is.
    Since there is no way to tell the two apart here, every member has to
    count: refusing a fully-encrypted archive on its declared size costs
    nothing, because extracting it without the password would fail anyway.
    """
    archive = tmp_path / "enc.7z"
    _write_archive(archive, sample, password="pw")

    entries, _ = enumerate_7z(archive)
    assert entries and all(e.is_encrypted for e in entries)
    assert sum(e.size_uncompressed for e in entries) > 0

    opened: list[Path] = []
    real_open = py7zr.SevenZipFile

    def recording_open(*args, **kwargs):
        opened.append(args[0] if args else kwargs.get("file"))
        return real_open(*args, **kwargs)

    monkeypatch.setattr(py7zr, "SevenZipFile", recording_open)

    from modules.static.archive_analysis.sevenzip_handler import (
        extract_members_to_temp,
    )

    out = tmp_path / "out"
    out.mkdir()
    extract_members_to_temp(archive, entries, out, max_total_bytes=16)

    assert opened == [], "budget was bypassed — the archive was opened for extraction"
    assert list(out.iterdir()) == []
