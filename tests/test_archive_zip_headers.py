"""The ZIP local-header / central-directory mismatch detector.

A ZIP carries every member's size twice: once in the local file header that
precedes the data, and once in the central directory at the tail. Nothing
makes them agree. Windows Explorer and 7-Zip extract from the local header;
Python's ``zipfile``, and therefore everything in this pipeline that reads a
member's size, reads the central directory. An archive whose two views
disagree is one where the scanner and the victim's extractor see different
files, which is the whole reason the raw parser exists beside ``zipfile``.

These tests build the archives byte by byte. A ZIP that lies cannot be
produced by a library that writes correct ones.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from modules.static.archive_analysis.zip_handler import _find_header_mismatches

_LFH_SIG = 0x04034B50
_CD_SIG = 0x02014B50
_EOCD_SIG = 0x06054B50

_NAME = b"payload.bin"
_PAYLOAD = b"MZ" + b"\x00" * 200_000


def _build_zip(
    path: Path,
    *,
    lfh_sizes: tuple[int, int] | None = None,
    cd_sizes: tuple[int, int] | None = None,
    lfh_flag: int = 0,
    cd_flag: int = 0,
    cd_method: int = 8,
    lfh_extra: bytes = b"",
    cd_extra: bytes = b"",
) -> tuple[int, int]:
    """Write a one-member ZIP, with each header's fields chosen separately.

    ``None`` means "declare the truth". ``lfh_flag`` sets the local
    header's general-purpose bit field; ``0x08`` is the data-descriptor
    bit that marks a streamed member. Returns the true
    ``(compressed, uncompressed)`` pair so a test can assert against it.
    """
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)  # noqa: E501
    blob = compressor.compress(_PAYLOAD) + compressor.flush()
    crc = zlib.crc32(_PAYLOAD) & 0xFFFFFFFF
    true_sizes = (len(blob), len(_PAYLOAD))

    lfh_comp, lfh_uncomp = lfh_sizes if lfh_sizes is not None else true_sizes
    cd_comp, cd_uncomp = cd_sizes if cd_sizes is not None else true_sizes

    local = struct.pack(
        "<IHHHHHIIIHH",
        _LFH_SIG, 20, lfh_flag, 8, 0, 0,
        crc, lfh_comp, lfh_uncomp, len(_NAME), len(lfh_extra),
    ) + _NAME + lfh_extra

    out = local + blob
    cd_offset = len(out)

    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        _CD_SIG, 20, 20, cd_flag, cd_method, 0, 0, crc,
        cd_comp, cd_uncomp, len(_NAME), len(cd_extra), 0, 0, 0, 0, 0,
    ) + _NAME + cd_extra

    out += central
    out += struct.pack(
        "<IHHHHIIH", _EOCD_SIG, 0, 0, 1, 1, len(central), cd_offset, 0,
    )
    path.write_bytes(out)
    return true_sizes


def test_a_central_directory_that_understates_a_member_is_reported(tmp_path):
    """Zeroing the central directory hid a 200 KB member from every size check.

    ``zipfile`` reads the central directory, so a member declared as 0/0
    there reports ``file_size == 0`` — and the decompression-bomb guard sums
    exactly that field. The local header still declares the real size, so
    Explorer and 7-Zip unpack the payload in full. Both of the detector's
    size comparisons required the central-directory value to be non-zero
    before a difference counted, so the anomaly it exists to catch was the
    one shape it skipped.
    """
    target = tmp_path / "understated.zip"
    true_comp, true_uncomp = _build_zip(target, cd_sizes=(0, 0))

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    found = mismatches[0]
    assert found["name"] == _NAME.decode()
    assert found["compressed_size"] == {"lfh": true_comp, "cd": 0}
    assert found["uncompressed_size"] == {"lfh": true_uncomp, "cd": 0}


def test_an_uncompressed_size_disagreement_is_reported(tmp_path):
    """The bomb guard reads uncompressed size, which was never compared.

    Both headers were parsed into records carrying ``uncompressed_size`` and
    only ``compressed_size`` was ever diffed. An attacker could therefore
    keep the compressed sizes identical — so nothing looked odd — while the
    two headers disagreed about how far the member expands, which is the
    figure every bomb threshold is measured against.
    """
    target = tmp_path / "expanding.zip"
    true_comp, true_uncomp = _build_zip(target, cd_sizes=None)
    # Rebuild with matching compressed sizes but a lying uncompressed one.
    _build_zip(target, cd_sizes=(true_comp, 512))

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    assert "compressed_size" not in mismatches[0]
    assert mismatches[0]["uncompressed_size"] == {"lfh": true_uncomp, "cd": 512}


def test_a_streamed_member_is_not_reported(tmp_path):
    """Zeros in the local header are ordinary when bit 3 says they are.

    A member written to a non-seekable stream cannot know its sizes when the
    local header goes out, so it writes zeros there, sets general-purpose
    bit 3, and publishes the real figures in a trailing data descriptor and
    the central directory. That is legal and common, so the detector has to
    stay silent — but it must read the flag that declares it rather than
    inferring it from the zeros, which an attacker also controls.
    """
    target = tmp_path / "streamed.zip"
    _build_zip(target, lfh_sizes=(0, 0), lfh_flag=0x08, cd_flag=0x08)

    assert _find_header_mismatches(target) == []


def test_a_zeroed_size_without_the_streaming_flag_is_reported(tmp_path):
    """Excusing a zero field by field let an attacker blind one comparison.

    Treating any zero in the local header as "this member was streamed"
    granted the exemption per field. An attacker could then declare a real
    compressed size — proving the member was not streamed, since the size
    was evidently known — while zeroing only the uncompressed size, the one
    field every bomb threshold is measured against. The exemption has to be
    an entry-level decision taken from bit 3, not a per-field reading of
    whether a number happens to be zero.
    """
    target = tmp_path / "half_zeroed.zip"
    true_comp, true_uncomp = _build_zip(target)
    _build_zip(target, lfh_sizes=(true_comp, 0), cd_sizes=(true_comp, 4096))

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    assert "compressed_size" not in mismatches[0]
    assert mismatches[0]["uncompressed_size"] == {"lfh": 0, "cd": 4096}


def test_an_honest_archive_reports_nothing(tmp_path):
    """The baseline: agreeing headers must produce no finding."""
    target = tmp_path / "honest.zip"
    _build_zip(target)

    assert _find_header_mismatches(target) == []


def test_two_non_zero_sizes_that_disagree_are_still_reported(tmp_path):
    """The original case the detector was written for, kept as a guard."""
    target = tmp_path / "disagree.zip"
    true_comp, true_uncomp = _build_zip(target)
    _build_zip(target, cd_sizes=(true_comp + 4096, true_uncomp + 4096))

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    assert mismatches[0]["compressed_size"] == {
        "lfh": true_comp, "cd": true_comp + 4096,
    }


def test_headers_that_disagree_about_streaming_are_reported(tmp_path):
    """Taking the streaming exemption from one header let it be claimed alone.

    Reading bit 3 from the local header only gave an attacker a cleaner
    version of the same bypass: set it in the LFH so the detector exempts
    the member from every size comparison, clear it in the CD and declare
    small sizes there so the bomb guard is satisfied, and put the real
    figures in the data descriptor that Explorer and 7-Zip actually read.
    The two headers disagreeing about whether a data descriptor exists is
    itself the anomaly, so it is reported in its own right.

    Verified against 91 real ZIP-shaped files — the sample corpus plus
    packaged wheels — with no header disagreeing about this bit.
    """
    target = tmp_path / "flag_split.zip"
    _build_zip(target, lfh_flag=0x08, cd_flag=0x00, cd_sizes=(512, 4096))

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    found = mismatches[0]
    assert found["data_descriptor_flag"] == {"lfh": True, "cd": False}
    # The exemption must not apply, so the sizes are compared as well.
    assert found["compressed_size"]["cd"] == 512
    assert found["uncompressed_size"]["cd"] == 4096


def _zip64_local_extra(uncompressed: int, compressed: int) -> bytes:
    """A local header's Zip64 field, which always carries both sizes."""
    payload = struct.pack("<QQ", uncompressed, compressed)
    return struct.pack("<HH", 0x0001, len(payload)) + payload


def test_a_resolved_zip64_sentinel_that_agrees_is_not_reported(tmp_path):
    """0xFFFFFFFF is a redirection, and following it must end the question.

    When a size does not fit 32 bits the header stores 0xFFFFFFFF and the
    real value moves to the Zip64 extended-information field. Writers do
    emit the sentinel in the local header while the central directory
    carries an ordinary 32-bit value — APT36.docm in the sample corpus does
    exactly that, with a proper 0x0001 field, for the members that use it.
    Once resolved the two agree, so there is nothing to report.
    """
    target = tmp_path / "zip64_sentinel.zip"
    _build_zip(
        target,
        lfh_sizes=(0xFFFFFFFF, 0xFFFFFFFF),
        lfh_extra=_zip64_local_extra(655, 288),
        cd_sizes=(288, 655),
    )

    assert _find_header_mismatches(target) == []


def test_a_resolved_zip64_sentinel_that_disagrees_is_reported(tmp_path):
    """Skipping the sentinel outright was itself an evasion primitive.

    Declare a small size in the central directory so the bomb guard is
    satisfied, put the sentinel in the local header, and point it at the
    real 64-bit size. A streaming extractor follows the sentinel and
    unpacks the payload in full. While the comparison skipped any field
    holding a sentinel, the split it exists to catch was the one shape it
    declined to look at.
    """
    target = tmp_path / "zip64_split.zip"
    _build_zip(
        target,
        lfh_sizes=(0xFFFFFFFF, 0xFFFFFFFF),
        lfh_extra=_zip64_local_extra(8 * 1024 * 1024, 4096),
        cd_sizes=(4096, 512),
    )

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    assert mismatches[0]["uncompressed_size"] == {
        "lfh": 8 * 1024 * 1024, "cd": 512,
    }


def test_a_sentinel_with_no_zip64_field_is_reported(tmp_path):
    """A promise the extra field does not keep is a finding, not a skip.

    The sentinel means "the real value is in the Zip64 field". Without one
    there is no size any reader can obtain, so this is a header that
    diverges from every interpretation of itself rather than a benign
    encoding to stay quiet about.
    """
    target = tmp_path / "unbacked_sentinel.zip"
    _build_zip(target, lfh_sizes=(0xFFFFFFFF, 0xFFFFFFFF), cd_sizes=(288, 655))

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    assert mismatches[0]["zip64_sentinel_unresolved"] == {
        "lfh": True, "cd": False,
    }


def test_a_compression_method_disagreement_is_reported(tmp_path):
    """The original reason the raw parser exists, pinned by a test.

    An LFH declaring one compression method while the CD declares another
    makes two readers decode the same bytes differently — the parser
    differential this module was written to find. It had no test of its
    own, so when the size comparison beside it was rewritten the check was
    dropped and the whole suite still passed.
    """
    target = tmp_path / "method_split.zip"
    _build_zip(target, cd_method=0)  # CD says stored, LFH says deflate

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    assert mismatches[0]["compression_method"] == {"lfh": 8, "cd": 0}


def _build_two_member_zip(path: Path, *, second_cd_method: int) -> None:
    """Write a ZIP with two members sharing one name.

    The first agrees with its local header; the second does not. Every
    archive library resolves the shared name to one record, so a scanner
    that looks at one of them looks at the wrong one half the time.
    """
    blobs = []
    out = b""
    centrals = []
    for method in (8, 8):
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        blob = compressor.compress(_PAYLOAD) + compressor.flush()
        blobs.append(blob)

    offsets = []
    for idx, blob in enumerate(blobs):
        offsets.append(len(out))
        crc = zlib.crc32(_PAYLOAD) & 0xFFFFFFFF
        out += struct.pack(
            "<IHHHHHIIIHH",
            _LFH_SIG, 20, 0, 8, 0, 0,
            crc, len(blob), len(_PAYLOAD), len(_NAME), 0,
        ) + _NAME + blob

    cd_offset = len(out)
    for idx, blob in enumerate(blobs):
        crc = zlib.crc32(_PAYLOAD) & 0xFFFFFFFF
        method = 8 if idx == 0 else second_cd_method
        centrals.append(struct.pack(
            "<IHHHHHHIIIHHHHHII",
            _CD_SIG, 20, 20, 0, method, 0, 0, crc,
            len(blob), len(_PAYLOAD), len(_NAME), 0, 0, 0, 0, 0, offsets[idx],
        ) + _NAME)

    central = b"".join(centrals)
    out += central
    out += struct.pack(
        "<IHHHHIIH", _EOCD_SIG, 0, 0, 2, 2, len(central), cd_offset, 0,
    )
    path.write_bytes(out)


def test_a_mismatch_behind_a_duplicate_name_is_still_reported(tmp_path):
    """Skipping repeated names let a clean decoy hide a diverging record.

    Repeated member names are distinct central-directory records, each
    pointing at its own local header. Deduplicating by name meant only the
    first was ever compared, so placing a benign record first hid whatever
    the second declared — and a duplicate name is already the shape this
    package treats as payload-hiding, which makes it the last place the
    comparison should stop looking.
    """
    target = tmp_path / "shadowed_mismatch.zip"
    _build_two_member_zip(target, second_cd_method=0)

    mismatches = _find_header_mismatches(target)

    assert len(mismatches) == 1, mismatches
    assert mismatches[0]["name"] == _NAME.decode()
    assert mismatches[0]["compression_method"] == {"lfh": 8, "cd": 0}


def test_duplicate_names_that_both_agree_report_nothing(tmp_path):
    """Dropping the dedupe must not start reporting honest repeats.

    A duplicate name is scored separately by the duplicate-member
    indicator. This function's job is the header differential, so two
    records that each agree with their own local header are silent here
    however many times the name repeats.
    """
    target = tmp_path / "honest_duplicates.zip"
    _build_two_member_zip(target, second_cd_method=8)

    assert _find_header_mismatches(target) == []
