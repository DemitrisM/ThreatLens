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
"""

from __future__ import annotations

from pathlib import Path

# {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3} — first 16 bytes of every .one file.
ONESTORE_HEADER_GUID: bytes = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")

# {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC} — FileDataStoreObject marker.
FILE_DATA_STORE_GUID: bytes = bytes.fromhex("E716E3BD65261145A4C48D4D0B7A9EAC")

# Header layout: GUID(16) | cbLength(8) | unused(4) | reserved(8) | payload(cbLength)
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

    Preferred check is the 16-byte header GUID. ``.onepkg`` bundle
    files are also accepted so the skip message can be descriptive —
    the CAB unpacking itself is delegated to ``archive_analysis``.
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
    data: bytes, max_blobs: int = 200,
) -> list[tuple[int, bytes]]:
    """Return ``[(offset, payload_bytes), …]`` for every well-formed FDSO.

    Malformed records (``cbLength`` overruns end-of-file) are skipped,
    not raised. ``max_blobs`` caps output so a crafted file cannot
    exhaust memory.
    """
    out: list[tuple[int, bytes]] = []
    file_len = len(data)
    offset = 0
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
        if cb_length == 0 or payload_end > file_len:
            offset = payload_start
            continue
        out.append((idx, data[payload_start:payload_end]))
        if len(out) >= max_blobs:
            break
        offset = payload_end
    return out


def has_encrypted_section(data: bytes) -> bool:
    """Heuristic detection of password-protected OneNote sections.

    The ONESTORE spec emits ``jcidEncryptedData`` and references the
    CryptoAPI provider string when a section is password-locked. Hitting
    either marker is a strong enough signal for triage; a clean file
    contains neither.
    """
    return any(marker in data for marker in _ENCRYPTION_MARKERS)
