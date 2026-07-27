"""Windows Shell Item decoding — the LECmd-depth half of the IDList.

[MS-SHLLINK] defers the ItemID payload format entirely, so the working
reference is libfwsi's "Windows Shell Item format" documentation, with
``EricZimmerman/Lnk`` as the cross-check oracle.

Only the file-entry item (class type ``0x3x``) is decoded in depth, and
deliberately so: it is the one that carries the **NTFS file reference** —
a 6-byte MFT entry number plus a 2-byte sequence number, tucked inside a
``0xBEEF0004`` extension block. That pair ties a shortcut to a specific
file on a specific volume, and it is the single biggest thing Python LNK
tooling omits (LnkParse3 does not surface it; LECmd does).

The extension blocks also carry a **second, independent set of
timestamps** in FAT/DOS form. Builders typically populate either the
header FILETIMEs or these, not both consistently, so a mismatch between
the two sources is a forgery signal — see ``indicators.py``.

Malformed DOS dates are common enough in real samples that LnkParse3 has
a standing issue about them. Here a bad date yields ``None`` and never
raises.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: Class-type indicator (the first byte) -> human label. The low nibble
#: varies per item, so dispatch is on the high nibble except where the
#: full byte is meaningful.
CLASS_TYPES = {
    0x00: "unknown",
    0x10: "root folder",
    0x20: "volume",
    0x30: "file entry",
    0x40: "network location",
    0x50: "compressed folder",
    0x60: "URI",
    0x70: "control panel",
}

#: Bit 0x04 of a file-entry class type means the primary name is UTF-16.
_UNICODE_NAME_BIT = 0x04

#: Bit 0x01 means the entry is a directory rather than a file.
_DIRECTORY_BIT = 0x01

MAX_EXTENSION_BLOCKS = 32

_BEEF0004 = 0xBEEF0004


@dataclass
class ShellItem:
    """One decoded ItemID. Every field is optional — truncation is normal."""

    class_type: int = 0
    type_name: str = "unknown"
    name: str = ""
    long_name: str = ""
    size: int | None = None
    is_directory: bool = False
    guid: str | None = None
    modified: str | None = None
    created: str | None = None
    accessed: str | None = None
    mft_entry: int | None = None
    mft_sequence: int | None = None
    extension_signatures: list[str] = field(default_factory=list)
    truncated: bool = False


# ---------------------------------------------------------------------------
# Bounds-checked reads (local copies — this module must not import parser,
# which imports it)
# ---------------------------------------------------------------------------

def _u16(data: bytes, off: int) -> int | None:
    if off < 0 or off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], "little")


def _u32(data: bytes, off: int) -> int | None:
    if off < 0 or off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], "little")


def _u64(data: bytes, off: int) -> int | None:
    if off < 0 or off + 8 > len(data):
        return None
    return int.from_bytes(data[off:off + 8], "little")


def fat_timestamp(raw: bytes) -> str | None:
    """Decode a 4-byte FAT/DOS date+time pair to ISO 8601.

    Layout: uint16 date then uint16 time. Date packs day in bits 0-4,
    month in 5-8, year-1980 in 9-15; time packs 2-second units in 0-4,
    minutes in 5-10, hours in 11-15.

    Returns ``None`` for the all-zero "not set" value and for anything
    that does not form a real date — malformed DOS dates are routine in
    real samples and must never raise.
    """
    if len(raw) < 4:
        return None
    date = int.from_bytes(raw[0:2], "little")
    time = int.from_bytes(raw[2:4], "little")
    if date == 0 and time == 0:
        return None

    day = date & 0x1F
    month = (date >> 5) & 0x0F
    year = 1980 + ((date >> 9) & 0x7F)
    second = (time & 0x1F) * 2
    minute = (time >> 5) & 0x3F
    hour = (time >> 11) & 0x1F

    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24
            and minute < 60 and second < 60):
        return None
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"


def _read_nul_string(data: bytes, off: int, *, unicode: bool, codepage: str) -> tuple[str, int]:
    """Read a NUL-terminated string, returning it and the offset past it."""
    if off < 0 or off >= len(data):
        return "", off
    if unicode:
        end = off
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        text = data[off:end].decode("utf-16-le", errors="replace")
        return text, min(end + 2, len(data))
    end = data.find(b"\x00", off)
    if end == -1:
        end = len(data)
    try:
        text = data[off:end].decode(codepage, errors="replace")
    except LookupError:
        text = data[off:end].decode("cp1252", errors="replace")
    return text, min(end + 1, len(data))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def decode_shell_item(payload: bytes, *, codepage: str = "cp1252") -> ShellItem:
    """Decode one ItemID payload (the bytes after its 2-byte size field).

    Unknown or truncated items degrade to a class label plus whatever
    strings can be scraped out — still enough to recover a target path,
    which is what actually matters for triage.
    """
    item = ShellItem()
    if not payload:
        item.truncated = True
        return item

    class_type = payload[0]
    item.class_type = class_type
    item.type_name = CLASS_TYPES.get(class_type & 0x70, "unknown")

    try:
        if class_type == 0x1F:
            _decode_root_folder(payload, item)
        elif class_type & 0x70 == 0x20:
            _decode_volume(payload, item, codepage)
        elif class_type & 0x70 == 0x30:
            _decode_file_entry(payload, class_type, item, codepage)
        else:
            item.name = _scrape_name(payload, codepage)
    except Exception as exc:  # noqa: BLE001
        logger.debug("shell item decode failed (class 0x%02X): %s", class_type, exc)
        item.truncated = True

    return item


def _decode_root_folder(payload: bytes, item: ShellItem) -> None:
    """0x1F — sort index byte then a 16-byte shell folder GUID."""
    raw = payload[2:18]
    if len(raw) != 16:
        item.truncated = True
        return
    d1 = int.from_bytes(raw[0:4], "little")
    d2 = int.from_bytes(raw[4:6], "little")
    d3 = int.from_bytes(raw[6:8], "little")
    item.guid = (
        f"{d1:08x}-{d2:04x}-{d3:04x}-{raw[8]:02x}{raw[9]:02x}-{raw[10:16].hex()}"
    )
    item.name = f"{{{item.guid}}}"


def _decode_volume(payload: bytes, item: ShellItem, codepage: str) -> None:
    """0x2x — an ASCII volume name such as ``C:\\``."""
    name, _ = _read_nul_string(payload, 1, unicode=False, codepage=codepage)
    item.name = name.strip("\x00")


def _decode_file_entry(
    payload: bytes, class_type: int, item: ShellItem, codepage: str,
) -> None:
    """0x3x — file size, DOS mtime, attributes, name, extension blocks.

    Fixed layout up to the name: class type(1) unknown(1) size(4)
    FAT modified(4) attributes(2), so the primary name starts at 12.
    """
    item.is_directory = bool(class_type & _DIRECTORY_BIT)
    unicode_name = bool(class_type & _UNICODE_NAME_BIT)

    item.size = _u32(payload, 2)
    item.modified = fat_timestamp(payload[6:10])

    name, after_name = _read_nul_string(
        payload, 12, unicode=unicode_name, codepage=codepage
    )
    item.name = name

    # Extension blocks start on a 2-byte boundary after the name.
    cursor = after_name + (after_name & 1)
    _decode_extension_blocks(payload, cursor, item)


def _decode_extension_blocks(payload: bytes, cursor: int, item: ShellItem) -> None:
    """Walk the size-prefixed extension-block chain.

    Same infinite-loop trap as every other size-prefixed walk in this
    package: a size below the 8-byte minimum, or one that overruns the
    payload, ends the walk rather than spinning.
    """
    count = 0
    while cursor + 8 <= len(payload) and count < MAX_EXTENSION_BLOCKS:
        size = _u16(payload, cursor)
        if size is None or size < 8 or cursor + size > len(payload):
            return
        version = _u16(payload, cursor + 2) or 0
        signature = _u32(payload, cursor + 4) or 0
        item.extension_signatures.append(f"0x{signature:08X}")
        if signature == _BEEF0004:
            _decode_beef0004(payload[cursor:cursor + size], version, item)
        cursor += size
        count += 1


def _decode_beef0004(block: bytes, version: int, item: ShellItem) -> None:
    """The block carrying creation/access times and the NTFS file reference.

    Layout: size(2) version(2) signature(4) FAT created(4) FAT accessed(4)
    unknown(2). From version 7 onward an 8-byte NTFS file reference follows
    at offset 20 — its low 6 bytes are the MFT entry number and its high 2
    bytes the sequence number.
    """
    item.created = fat_timestamp(block[8:12])
    item.accessed = fat_timestamp(block[12:16])

    if version >= 7:
        reference = _u64(block, 20)
        if reference:
            item.mft_entry = reference & 0x0000_FFFF_FFFF_FFFF
            item.mft_sequence = (reference >> 48) & 0xFFFF

    # The long (Unicode) name follows a version-dependent run of fields.
    offset = 36 if version >= 7 else 18
    if version >= 3:
        offset += 2                     # long string size
    if version >= 9:
        offset += 4
    if version >= 8:
        offset += 4
    if version >= 3 and offset < len(block):
        long_name, _ = _read_nul_string(block, offset, unicode=True, codepage="cp1252")
        item.long_name = long_name


def _scrape_name(payload: bytes, codepage: str) -> str:
    """Last resort for item classes we do not decode.

    Prefers the longest embedded UTF-16 run, falling back to ASCII. A
    recovered path fragment beats nothing, and the target-resolution
    chain in ``command.py`` can still use it.
    """
    best = ""
    for candidate in _utf16_runs(payload):
        if len(candidate) > len(best):
            best = candidate
    if best:
        return best
    try:
        text = payload.decode(codepage, errors="replace")
    except LookupError:
        text = payload.decode("cp1252", errors="replace")
    parts = [p for p in text.split("\x00") if len(p) >= 3 and p.isprintable()]
    return max(parts, key=len) if parts else ""


def _utf16_runs(payload: bytes, min_chars: int = 3) -> list[str]:
    """Extract printable UTF-16LE runs without regex backtracking."""
    runs: list[str] = []
    current: list[str] = []
    for index in range(0, len(payload) - 1, 2):
        pair = payload[index:index + 2]
        if pair[1] == 0 and 0x20 <= pair[0] < 0x7F:
            current.append(chr(pair[0]))
        else:
            if len(current) >= min_chars:
                runs.append("".join(current))
            current = []
    if len(current) >= min_chars:
        runs.append("".join(current))
    return runs
