"""Raw MS-ONESTORE parser for the triage path.

Modern ``.one`` files (OneNote 2007+) use the MS-ONESTORE Revision
Store File Format, **not** OLE/CFB. Triage only needs two things from
the spec:

* The 16-byte file header GUID — proves this is a OneNote file.
* The :data:`FILE_DATA_STORE_GUID` records — attacker-supplied blob
  carriers (PE, MSI, LNK, script, …).

Walking the full revision-store tree is overkill for a static triage
tool; the well-known `onedump.py` approach (scan for the GUID, read the
length field, slice the payload) is industry standard and is what
forensic teams use. This module re-implements that in pure Python with
bounds checks so malformed length fields can't read past end-of-file.

Design notes
------------
Scanning for a GUID rather than walking the revision store is what makes
the parser immune to structural damage. A dropper only needs OneNote to
open the file far enough to show a lure image and let the victim
double-click an attachment, so the rest of the revision tree is often
malformed — and a tree-walking parser that gives up there gives up
before reaching the payload. A byte scan has no tree to lose.

The cost is honest to state: this finds blobs, not their page context.
It cannot say which page an attachment sits on or what the lure said.
For triage that is the right trade; for a forensic timeline it is not.

**Every loop here advances monotonically by construction.** A malformed
record sets the cursor to ``payload_start``, which is always greater
than the match offset, so the next ``find`` starts strictly further on.
The length field is attacker-controlled, so that property has to come
from the arithmetic rather than from trusting the file.
"""

from __future__ import annotations

from pathlib import Path

# {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3} — first 16 bytes of every .one file.
ONESTORE_HEADER_GUID: bytes = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")

# {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC} — FileDataStoreObject marker.
FILE_DATA_STORE_GUID: bytes = bytes.fromhex("E716E3BD65261145A4C48D4D0B7A9EAC")

# Header layout: GUID(16) | cbLength(8) | unused(4) | reserved(8) | payload(cbLength)
#
# The payload starts at the full 36, not at 24 where cbLength ends: the
# twelve bytes between are part of the header. Slicing from the wrong
# offset yields a payload shifted by twelve bytes, which still decodes
# to *something* and would type every blob wrongly rather than failing.
_FDSO_HEADER_SIZE = 36

# Heuristic markers OneNote emits around password-protected sections.
# Two signals combined reduce false positives — bare "Encryption" would
# hit benign metadata strings.
_ENCRYPTION_MARKERS: tuple[bytes, ...] = (
    b"jcidEncryptedData",
    b"Microsoft Enhanced RSA and AES",
)

_ONENOTE_EXTENSIONS = frozenset({".one", ".onepkg"})


def is_onenote_file(file_path: Path) -> bool:
    """Return True when the file is a OneNote container.

    Args:
        file_path: The candidate file.

    Returns:
        Whether this module should look at it.

    Preferred check is the 16-byte header GUID. ``.onepkg`` bundle
    files are also accepted so the skip message can be descriptive —
    the CAB unpacking itself is delegated to ``archive_analysis``.

    An unreadable file falls back to the extension rather than
    returning False. Answering "not a OneNote file" for a file that
    could not be opened would be a claim about its contents that
    nothing supports; deferring to the name lets the caller's own error
    handling report what actually happened.
    """
    suffix = file_path.suffix.lower()
    try:
        with file_path.open("rb") as fh:
            head = fh.read(16)
    except OSError:
        return suffix in _ONENOTE_EXTENSIONS
    if head == ONESTORE_HEADER_GUID:
        return True
    return suffix in _ONENOTE_EXTENSIONS


def walk_file_data_store_objects(
    data, max_blobs: int = 200, max_payload_bytes: int | None = None,
) -> list[tuple[int, bytes]]:
    """Return ``[(offset, payload_bytes), …]`` for every well-formed FDSO.

    Args:
        data:              The file's bytes, or anything supporting
                           ``find`` and slicing — the caller passes a
                           memory map, so a large notebook is never read
                           into RAM whole.
        max_blobs:         Output cap, so a crafted file cannot exhaust
                           memory by repeating the marker.
        max_payload_bytes: **Cumulative** budget across every payload
                           returned, not a per-record ceiling.
                           ``cbLength`` is attacker-controlled and drives
                           the slice that copies a payload out of the
                           mapping, so a per-record limit alone would
                           allow ``max_blobs`` times that limit —
                           defaults of 200 and 50 MiB are 10 GiB
                           resident, worse than the whole-file cap that
                           mapping replaced. A record that does not fit
                           the remaining budget is skipped like any
                           other malformed one, and the walk continues,
                           so a later small payload is still recovered.

    Returns:
        One tuple per well-formed record, in file order.

    Malformed records are skipped rather than raised on, and there are
    two distinct kinds. A ``cbLength`` that overruns the file, or one of
    zero, means this record cannot be read — the scan resumes past its
    header and keeps going, because the next record is independently
    addressable. A length field truncated by end-of-file ends the walk
    instead: there is nothing left to resume into.

    The cursor advance is what makes the loop terminate, and both skip
    paths advance strictly. ``payload_start`` is 36 bytes past the match;
    ``payload_end`` is that plus ``cb_length``, so it is never behind it
    even when the length is zero. Which one is used depends on whether
    the record's extent is known: an unreadable length forces the
    conservative step, a known one lets the scan jump the payload.

    A ``cb_length`` of zero is treated as malformed rather than as an
    empty payload. Nothing legitimate stores a zero-length attachment,
    and a record carrying one is a marker without content.
    """
    out: list[tuple[int, bytes]] = []
    file_len = len(data)
    offset = 0
    extracted = 0
    while True:
        idx = data.find(FILE_DATA_STORE_GUID, offset)
        if idx == -1:
            break
        header_end = idx + 16
        length_end = header_end + 8
        if length_end > file_len:
            break
        cb_length = int.from_bytes(data[header_end:length_end], "little")
        payload_start = idx + _FDSO_HEADER_SIZE
        payload_end = payload_start + cb_length
        if payload_end > file_len:
            # The length field cannot be trusted, so the record's extent
            # is unknown. Resume just past the header — the only offset
            # that is certainly inside the file and certainly forward.
            offset = payload_start
            continue

        over_budget = (
            max_payload_bytes is not None
            and extracted + cb_length > max_payload_bytes
        )
        if cb_length == 0 or over_budget:
            # Structurally sound, so the extent *is* known and the scan
            # steps over it in one move. Resuming at the header instead
            # would walk the payload byte by byte looking for markers,
            # and would report any GUID inside that opaque blob as a
            # top-level record the file does not contain.
            offset = payload_end
            continue
        out.append((idx, data[payload_start:payload_end]))
        extracted += cb_length
        if len(out) >= max_blobs:
            break
        offset = payload_end
    return out


def has_encrypted_section(data: bytes) -> bool:
    """Heuristic detection of password-protected OneNote sections.

    Args:
        data: The whole file in memory.

    Returns:
        Whether either marker is present.

    The ONESTORE spec emits ``jcidEncryptedData`` and references the
    CryptoAPI provider string when a section is password-locked. Hitting
    either marker is a strong enough signal for triage; a clean file
    contains neither.

    It scores only 8. An encrypted section is a statement about what
    static analysis *cannot* see rather than evidence of what is there —
    legitimate users password-protect notebooks — so it is worth saying
    in the report and not worth a verdict on its own.
    """
    return any(marker in data for marker in _ENCRYPTION_MARKERS)
