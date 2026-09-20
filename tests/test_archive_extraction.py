"""Extraction must address members by identity, never by name.

A member's name is attacker-controlled and is not unique. Two records can
share one, and the archive libraries resolve a name to exactly one of them —
so extracting by name reads one member twice and never looks at the other.
The ZIP header-mismatch detector in this same package already treats
duplicate names as a real case it has to handle, which is the tell.

`doc_analysis` had this fixed once already (parts opened by ZipInfo rather
than by name); these are the remaining sites.
"""

from __future__ import annotations

import tarfile
import warnings
import zipfile
from pathlib import Path

import pytest

from modules.static.archive_analysis.entries import ArchiveEntry
from modules.static.archive_analysis.tarball_handler import (
    extract_tar_members_to_temp,
)
from modules.static.archive_analysis.zip_handler import (
    enumerate_zip,
    extract_members_to_temp,
)


# ----------------------------------------------------------------------
# ZIP
# ----------------------------------------------------------------------

def _dup_name_zip(tmp_path):
    """A ZIP with two members sharing one name.

    zipfile resolves a name to the *last* record, so extracting by name
    reads MALICIOUS twice and never reads BENIGN. Reverse the order and it
    reads BENIGN twice and the payload is never examined at all.
    """
    target = tmp_path / "dup.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(target, "w") as zf:
            zf.writestr("payload.bin", b"MALICIOUS" + b"\x00" * 64)
            zf.writestr("payload.bin", b"BENIGN" + b"\x00" * 64)
    return target


def test_duplicate_zip_names_are_each_extracted_once(tmp_path):
    target = _dup_name_zip(tmp_path)
    entries, _meta = enumerate_zip(target)
    assert len(entries) == 2, "both records must be enumerated"

    out = tmp_path / "out"
    out.mkdir()
    extract_members_to_temp(target, entries, out, 10 * 1024 * 1024)

    paths = [e.extracted_path for e in entries if e.extracted_path]
    assert len(paths) == 2, "both duplicate members must be materialised"

    contents = sorted(Path(p).read_bytes()[:9] for p in paths)
    assert contents == sorted([b"MALICIOUS", b"BENIGN\x00\x00\x00"]), (
        f"each record must yield its own bytes, got {contents}"
    )


def test_ordinary_zip_still_extracts(tmp_path):
    target = tmp_path / "plain.zip"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("a.txt", b"A" * 100)
        zf.writestr("b.txt", b"B" * 100)

    entries, _meta = enumerate_zip(target)
    out = tmp_path / "out"
    out.mkdir()
    extract_members_to_temp(target, entries, out, 10 * 1024 * 1024)

    assert all(e.extracted_path for e in entries)
    assert Path(entries[0].extracted_path).read_bytes() == b"A" * 100
    assert Path(entries[1].extracted_path).read_bytes() == b"B" * 100


# ----------------------------------------------------------------------
# TAR
# ----------------------------------------------------------------------

def test_duplicate_tar_names_are_each_extracted_once(tmp_path):
    """tar permits repeated names outright — later entries shadow earlier."""
    import io

    target = tmp_path / "dup.tar"
    with tarfile.open(target, "w") as tf:
        for payload in (b"FIRST" + b"\x00" * 32, b"SECOND" + b"\x00" * 31):
            info = tarfile.TarInfo("same.bin")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

    from modules.static.archive_analysis.tarball_handler import enumerate_tar

    entries, _meta = enumerate_tar(target, {})
    assert len(entries) == 2

    out = tmp_path / "out"
    out.mkdir()
    extract_tar_members_to_temp(target, entries, out, 10 * 1024 * 1024)

    paths = [e.extracted_path for e in entries if e.extracted_path]
    assert len(paths) == 2
    heads = sorted(Path(p).read_bytes()[:6] for p in paths)
    assert heads == sorted([b"FIRST\x00", b"SECOND"]), heads


# ----------------------------------------------------------------------
# The extracted-path mapping must not be built from the in-archive name
# ----------------------------------------------------------------------

def test_traversing_name_never_maps_outside_the_temp_dir(tmp_path):
    """A traversing name must not be allowed to read a file outside tmp_dir."""
    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "secret.txt").write_bytes(b"NOT PART OF THE ARCHIVE")

    entry = ArchiveEntry(name="../secret.txt", size_uncompressed=23)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([entry], out)
    assert entry.extracted_path is None, (
        f"mapped to {entry.extracted_path}, outside the scratch directory"
    )


def test_sanitised_traversing_member_is_still_found(tmp_path):
    """Refusing a traversing name outright would be a scanner bypass.

    py7zr and cabextract strip traversal on write, so `../malware.exe` is
    really extracted as `tmp_dir/malware.exe`. If the mapper refuses the
    name, the payload sits on disk unexamined and prefixing `../` skips
    7z/CAB analysis entirely. Raised by Gemini.
    """
    out = tmp_path / "out"
    out.mkdir()
    (out / "malware.exe").write_bytes(b"MZ" + b"\x00" * 64)

    entry = ArchiveEntry(name="../../malware.exe", size_uncompressed=66)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([entry], out)
    assert entry.extracted_path == str(out / "malware.exe"), (
        "sanitised payload was left unanalysed — this is the bypass"
    )


def test_symlink_in_scratch_dir_cannot_redirect_the_read(tmp_path):
    """Containment is checked on the resolved path, not the name."""
    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "outside.bin").write_bytes(b"OUTSIDE")
    try:
        (out / "link.bin").symlink_to(tmp_path / "outside.bin")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    entry = ArchiveEntry(name="link.bin", size_uncompressed=7)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([entry], out)
    assert entry.extracted_path is None, "a symlink out of tmp_dir was followed"


def test_normal_member_name_still_maps(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "inner.bin").write_bytes(b"X" * 40)

    entry = ArchiveEntry(name="inner.bin", size_uncompressed=40)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([entry], out)
    assert entry.extracted_path == str(out / "inner.bin")


def test_nested_member_name_maps_within_the_tree(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "sub").mkdir()
    (out / "sub" / "deep.bin").write_bytes(b"Y" * 12)

    entry = ArchiveEntry(name="sub/deep.bin", size_uncompressed=12)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([entry], out)
    assert entry.extracted_path == str(out / "sub" / "deep.bin")


@pytest.mark.parametrize("member_name", [
    "/nested/evil.exe",          # absolute — py7zr strips the leading slash
    "nested\\evil.exe",          # cabextract treats backslash as a separator
    "\\nested\\evil.exe",
    "../nested/evil.exe",        # traversal stripped, tree preserved
])
def test_sanitised_names_that_keep_their_tree_are_found(tmp_path, member_name):
    """Extractors may strip the root but keep the directory structure.

    Probing only the raw name and the flattened basename misses
    tmp_dir/nested/evil.exe entirely, so a leading slash or a backslash
    separator skipped 7z and CAB analysis outright. Raised by Gemini.
    """
    out = tmp_path / "out"
    (out / "nested").mkdir(parents=True)
    (out / "nested" / "evil.exe").write_bytes(b"MZ" + b"\x00" * 32)

    entry = ArchiveEntry(name=member_name, size_uncompressed=34)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([entry], out)
    assert entry.extracted_path == str(out / "nested" / "evil.exe"), (
        f"{member_name!r} was not located — payload would go unanalysed"
    )


def test_truncated_tar_does_not_crash_extraction(tmp_path):
    """enumerate_tar survives truncation; extraction must too (rule 2)."""
    import io

    full = tmp_path / "full.tar"
    with tarfile.open(full, "w") as tf:
        for i in range(4):
            payload = b"X" * 512
            info = tarfile.TarInfo(f"f{i}.bin")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

    raw = full.read_bytes()
    truncated = tmp_path / "truncated.tar"
    truncated.write_bytes(raw[: len(raw) // 3])

    from modules.static.archive_analysis.tarball_handler import enumerate_tar

    entries, _meta = enumerate_tar(truncated, {})

    out = tmp_path / "out"
    out.mkdir()
    # Must not raise...
    extract_tar_members_to_temp(truncated, entries, out, 10 * 1024 * 1024)

    # ...and must not discard the members that survived the truncation.
    # Asserting only "did not raise" masks a handler that bails out on the
    # first error and extracts nothing. Raised by Gemini.
    assert entries, "enumerate_tar should recover members before the cut"
    materialised = [e for e in entries if e.extracted_path]
    assert materialised, "intact members before the truncation were abandoned"
    for e in materialised:
        assert Path(e.extracted_path).read_bytes() == b"X" * 512


def test_extraction_walk_is_bounded_by_requested_members(tmp_path, monkeypatch):
    """Extraction must not re-inflate what enumeration refused to read.

    enumerate_tar abandons a hostile archive partway and returns a short
    entries list. The orchestrator's bomb guard then sees only those few
    members and may not trip — so if extraction walks the stream to the
    end, it decompresses everything the enumerator just declined.

    Counted rather than timed: gzip clears 100+ MB/s, so a wall-clock
    bound passes on the vulnerable code too. Both points raised by Gemini.
    """
    import io

    from modules.static.archive_analysis import tarball_handler

    target = tmp_path / "trailing_bomb.tar.gz"
    with tarfile.open(target, "w:gz") as tf:
        small = b"S" * 256
        info = tarfile.TarInfo("small.bin")
        info.size = len(small)
        tf.addfile(info, io.BytesIO(small))

        big = b"\x00" * (8 * 1024 * 1024)
        info = tarfile.TarInfo("bomb.bin")
        info.size = len(big)
        tf.addfile(info, io.BytesIO(big))

    entries, _meta = tarball_handler.enumerate_tar(target, {})
    entries = entries[:1]          # only the first member is requested

    walked = {"n": 0}
    real_open = tarball_handler.tarfile.open

    class _Counting:
        def __init__(self, inner):
            self._inner = inner

        def __iter__(self):
            for member in self._inner:
                walked["n"] += 1
                yield member

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *exc):
            return self._inner.__exit__(*exc)

        def __getattr__(self, attr):
            return getattr(self._inner, attr)

    monkeypatch.setattr(
        tarball_handler.tarfile, "open",
        lambda *a, **kw: _Counting(real_open(*a, **kw)),
    )

    out = tmp_path / "out"
    out.mkdir()
    extract_tar_members_to_temp(target, entries, out, 10 * 1024 * 1024)

    assert entries[0].extracted_path, "the requested member must still extract"
    assert Path(entries[0].extracted_path).read_bytes() == b"S" * 256
    assert walked["n"] == 1, (
        f"walked {walked['n']} members — it read past the requested one"
    )


def test_surviving_file_is_attributed_to_the_last_writer(tmp_path):
    """The extractor writes duplicates in order; the survivor is the last.

    Claiming forward handed the file to the first entry, labelling the
    surviving bytes with the name of the record they overwrote.
    Raised by Gemini.
    """
    out = tmp_path / "out"
    out.mkdir()
    (out / "dup.bin").write_bytes(b"LAST-WRITER")

    first = ArchiveEntry(name="dup.bin", size_uncompressed=11)
    last = ArchiveEntry(name="dup.bin", size_uncompressed=11)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([first, last], out)

    assert last.extracted_path == str(out / "dup.bin"), (
        "the surviving bytes belong to the last writer"
    )
    assert first.extracted_path is None, (
        "the overwritten member must not be reported as analysed"
    )


def test_duplicate_names_are_reported_as_recoverable_for_zip():
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [
        ArchiveEntry(name="payload.bin"),
        ArchiveEntry(name="payload.bin"),
        ArchiveEntry(name="other.txt"),
    ]
    dupes = detect_duplicate_member_names(entries, "zip")
    assert len(dupes) == 1
    assert dupes[0]["name"] == "payload.bin"
    assert dupes[0]["count"] == 2
    assert dupes[0]["recoverable"] is True


@pytest.mark.parametrize("fmt", ["7z", "cab"])
def test_duplicate_names_are_unrecoverable_for_externally_unpacked_formats(fmt):
    """py7zr and cabextract overwrite — the shadowed bytes are gone."""
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [ArchiveEntry(name="a.exe"), ArchiveEntry(name="a.exe")]
    dupes = detect_duplicate_member_names(entries, fmt)
    assert dupes[0]["recoverable"] is False


def test_unique_names_report_nothing():
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [ArchiveEntry(name=f"f{i}.txt") for i in range(5)]
    assert detect_duplicate_member_names(entries, "zip") == []


def test_two_entries_never_claim_the_same_extracted_file(tmp_path):
    """Both would otherwise map to the survivor and read as analysed."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "dup.bin").write_bytes(b"SURVIVOR")

    a = ArchiveEntry(name="dup.bin", size_uncompressed=8)
    b = ArchiveEntry(name="dup.bin", size_uncompressed=8)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([a, b], out)
    mapped = [e for e in (a, b) if e.extracted_path]
    assert len(mapped) == 1, "the overwritten member must not be reported as analysed"


def test_shadowed_member_scores():
    from modules.static.archive_analysis.scoring import score_archive

    delta, reason, fired, _cls = score_archive(
        {"duplicate_member_name", "shadowed_member_unrecoverable"},
    )
    assert delta >= 8
    assert any("duplicate" in f.lower() for f in fired)
    assert any("unrecoverable" in f.lower() for f in fired)


def test_collapsing_name_does_not_orphan_a_distinct_payload(tmp_path):
    """A name that resolves onto a claimed file must keep searching.

    Three members: `malware.exe`, `nested/harmless.txt`, and
    `nested/../malware.exe`. A sanitising extractor writes the third to
    tmp_dir/nested/malware.exe, but its raw name resolves out to
    tmp_dir/malware.exe — already claimed by the first. Abandoning the
    search there orphaned the real payload, and since all three names are
    distinct, no duplicate-name indicator fired to cover it.
    Raised by Gemini.
    """
    out = tmp_path / "out"
    (out / "nested").mkdir(parents=True)
    (out / "malware.exe").write_bytes(b"FIRST-PAYLOAD")
    (out / "nested" / "harmless.txt").write_bytes(b"harmless")
    (out / "nested" / "malware.exe").write_bytes(b"SECOND-PAYLOAD")

    first = ArchiveEntry(name="malware.exe", size_uncompressed=13)
    second = ArchiveEntry(name="nested/harmless.txt", size_uncompressed=8)
    third = ArchiveEntry(name="nested/../malware.exe", size_uncompressed=14)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([first, second, third], out)

    assert first.extracted_path == str(out / "malware.exe")
    assert second.extracted_path == str(out / "nested" / "harmless.txt")
    assert third.extracted_path == str(out / "nested" / "malware.exe"), (
        "the distinct payload was orphaned and would go unanalysed"
    )


# ----------------------------------------------------------------------
# Duplicate detection must see collisions that raw names hide
# ----------------------------------------------------------------------

def test_distinct_names_that_collapse_to_one_file_are_flagged():
    """Raw-name counting missed the case the indicator exists for.

    "a.exe", "./a.exe" and "nested/../a.exe" are three different strings
    that an extractor writes to one file. Raised by Gemini.
    """
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [
        ArchiveEntry(name="a.exe"),
        ArchiveEntry(name="./a.exe"),
        ArchiveEntry(name="nested/../a.exe"),
    ]
    dupes = detect_duplicate_member_names(entries, "7z")
    assert len(dupes) == 1
    assert dupes[0]["count"] == 3
    assert dupes[0]["recoverable"] is False


def test_genuinely_distinct_names_are_not_flagged():
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [ArchiveEntry(name="a.exe"), ArchiveEntry(name="nested/b.exe")]
    assert detect_duplicate_member_names(entries, "7z") == []


def test_iso_duplicates_are_unrecoverable():
    """pycdlib has no index-based read, so a shadowed ISO record is lost."""
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [ArchiveEntry(name="setup.exe"), ArchiveEntry(name="setup.exe")]
    assert detect_duplicate_member_names(entries, "iso")[0]["recoverable"] is False


def test_symlink_loop_does_not_crash_the_mapper(tmp_path):
    """resolve() raises RuntimeError on a loop before Python 3.13."""
    out = tmp_path / "out"
    out.mkdir()
    try:
        (out / "a").symlink_to(out / "b")
        (out / "b").symlink_to(out / "a")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    entry = ArchiveEntry(name="a", size_uncompressed=1)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    # Must not raise.
    _map_extracted_paths([entry], out)
    assert entry.extracted_path is None


@pytest.mark.parametrize("fmt", ["7z", "cab", "iso", "zip", "tar", "rar"])
def test_shared_basename_is_never_a_collision(fmt):
    """A shared basename across directories is entirely ordinary.

    Measured: py7zr.extractall preserves the tree, so dir1/style.css and
    dir2/style.css are written side by side and both survive. Treating that
    as a collision would score +8 and classify MALICIOUS for any benign
    archive holding a common filename in two folders.
    """
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [
        ArchiveEntry(name="css/style.css"),
        ArchiveEntry(name="admin/css/style.css"),
    ]
    assert detect_duplicate_member_names(entries, fmt) == []


def test_one_row_per_collision_not_per_shared_spelling():
    """Two members named identically agree on all their spellings.

    Grouping by spelling rendered the same collision three times in the
    report. Raised by Gemini.
    """
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [
        ArchiveEntry(name="nested/../a.exe"),
        ArchiveEntry(name="nested/../a.exe"),
    ]
    dupes = detect_duplicate_member_names(entries, "7z")
    assert len(dupes) == 1, f"one collision should be one row, got {dupes}"
    assert dupes[0]["count"] == 2


def test_separate_collisions_are_reported_separately():
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [
        ArchiveEntry(name="x.bin"), ArchiveEntry(name="x.bin"),
        ArchiveEntry(name="y.bin"), ArchiveEntry(name="y.bin"),
    ]
    dupes = detect_duplicate_member_names(entries, "zip")
    assert [d["name"] for d in dupes] == ["x.bin", "y.bin"]


# ----------------------------------------------------------------------
# Drive letters — the mapper and the indicator must agree on them
# ----------------------------------------------------------------------

@pytest.mark.parametrize("decoy_pair", [
    ("malware.exe", "C:\\malware.exe"),
    ("malware.exe", "/malware.exe"),
    ("dir/x.exe", "D:\\dir\\x.exe"),
])
def test_drive_letter_decoy_is_a_detected_collision(decoy_pair):
    """Sanitising extractors strip the drive letter and the absolute root.

    So "C:\\malware.exe" and "malware.exe" land on one file. Leaving the
    drive letter on meant they never matched, so a payload could occupy a
    decoy's destination unnoticed. Raised by Gemini.
    """
    from modules.static.archive_analysis.indicators import (
        detect_duplicate_member_names,
    )

    entries = [ArchiveEntry(name=n) for n in decoy_pair]
    dupes = detect_duplicate_member_names(entries, "7z")
    assert dupes, f"{decoy_pair} target the same file but were not flagged"
    assert dupes[0]["count"] == 2


def test_mapper_and_indicator_share_one_canonicalisation():
    """They drifted repeatedly, and every drift was a silent hole.

    A payload the mapper could not place was also a collision the indicator
    failed to report, so the two must derive from the same function.
    """
    from modules.static.archive_analysis import entries as entries_mod
    from modules.static.archive_analysis import indicators, sevenzip_handler

    assert indicators.member_destinations is entries_mod.member_destinations
    assert sevenzip_handler.member_destinations is entries_mod.member_destinations


@pytest.mark.parametrize("name, expected_first", [
    ("C:\\evil.exe", "evil.exe"),
    ("/evil.exe", "evil.exe"),
    ("nested/../evil.exe", "nested/evil.exe"),
    ("./evil.exe", "evil.exe"),
    ("plain.exe", "plain.exe"),
])
def test_most_likely_destination_comes_first(name, expected_first):
    """The mapper probes in order, so the sanitised form must lead."""
    from modules.static.archive_analysis.entries import member_destinations

    assert member_destinations(name)[0] == expected_first


def test_a_fallback_candidate_never_outranks_a_primary(tmp_path):
    """`nested/../evil.exe` must not hijack plain `evil.exe`'s only slot.

    Its third spelling resolves to tmp_dir/evil.exe, which is the other
    member's sole candidate. Claiming in one pass let whichever ran first
    take it, misattributing the payload and orphaning the other member.
    Raised by Gemini.
    """
    out = tmp_path / "out"
    (out / "nested").mkdir(parents=True)
    (out / "evil.exe").write_bytes(b"PLAIN-MEMBER")
    (out / "nested" / "evil.exe").write_bytes(b"NESTED-MEMBER")

    plain = ArchiveEntry(name="evil.exe", size_uncompressed=12)
    nested = ArchiveEntry(name="nested/../evil.exe", size_uncompressed=13)

    from modules.static.archive_analysis.sevenzip_handler import (
        _map_extracted_paths,
    )

    _map_extracted_paths([plain, nested], out)

    assert plain.extracted_path == str(out / "evil.exe")
    assert nested.extracted_path == str(out / "nested" / "evil.exe")
    assert Path(plain.extracted_path).read_bytes() == b"PLAIN-MEMBER"
    assert Path(nested.extracted_path).read_bytes() == b"NESTED-MEMBER"
