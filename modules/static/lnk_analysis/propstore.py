"""PropertyStoreDataBlock decoding — serialized property storage.

Structure per [MS-PROPSTORE], with values in the [MS-OLEPS]
``TypedPropertyValue`` encoding::

    PropertyStore = *SerializedPropertyStorage TERMINATOR(uint32 == 0)
    SerializedPropertyStorage = StorageSize(4) Version(4 == 0x53505331)
                                FormatID(16) *SerializedPropertyValue

Values come in two shapes, chosen by the FormatID: when it equals
``D5CDD505-2E9C-101B-9397-08002B2CF9AE`` the properties are **string-named**,
otherwise they are **integer-named** (a FMTID plus a numeric PID).

This is the capability that distinguishes the module from the available
Python tooling — LnkParse3 does not decode property values into named
properties at all, and it is where the target's original filename, its
parsing path and the owner SID live.

**On the name map:** ``_PROPERTY_NAMES`` covers only well-documented
FMTID/PID pairs. Anything unrecognised renders as its raw GUID and integer
rather than being dropped, so an unmapped property is still visible to an
analyst and still reaches the report. Extend the map against libfwps'
documentation or ``EricZimmerman/Lnk``'s property tables — never by guess.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_STORAGE_VERSION = 0x53505331          # "1SPS" little-endian, i.e. '1PS' + version

#: FormatID that selects string-named properties instead of integer PIDs.
_STRING_NAMED_FMTID = "d5cdd505-2e9c-101b-9397-08002b2cf9ae"

MAX_PROPERTY_STORAGES = 32
MAX_PROPERTIES_PER_STORAGE = 128

#: (FMTID, PID) -> canonical property name. Deliberately conservative:
#: only pairs that are widely documented appear here.
_PROPERTY_NAMES: dict[tuple[str, int], str] = {
    ("b725f130-47ef-101a-a5f1-02608c9eebac", 4): "System.ItemTypeText",
    ("b725f130-47ef-101a-a5f1-02608c9eebac", 10): "System.ItemNameDisplay",
    ("b725f130-47ef-101a-a5f1-02608c9eebac", 12): "System.Size",
    ("b725f130-47ef-101a-a5f1-02608c9eebac", 13): "System.FileAttributes",
    ("b725f130-47ef-101a-a5f1-02608c9eebac", 14): "System.DateModified",
    ("b725f130-47ef-101a-a5f1-02608c9eebac", 15): "System.DateCreated",
    ("b725f130-47ef-101a-a5f1-02608c9eebac", 16): "System.DateAccessed",
    ("446d16b1-8dad-4870-a748-402ea43d788c", 100): "System.IsPinnedToNameSpaceTree",
    ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 30): "System.ParsingName",
    ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 31): "System.SFGAOFlags",
    ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 32): "System.ParsingPath",
    ("9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3", 3): "System.AppUserModel.ID",
}

#: [MS-OLEPS] TypedPropertyValue type identifiers we decode. Anything else
#: is recorded as its type id plus a raw length, never guessed at.
VT_EMPTY = 0x0000
VT_NULL = 0x0001
VT_I2 = 0x0002
VT_I4 = 0x0003
VT_BOOL = 0x000B
VT_I8 = 0x0014
VT_UI4 = 0x0013
VT_UI8 = 0x0015
VT_LPSTR = 0x001E
VT_LPWSTR = 0x001F
VT_FILETIME = 0x0040
VT_BLOB = 0x0041
VT_CLSID = 0x0048

_FILETIME_EPOCH_DELTA = 116_444_736_000_000_000


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


def _guid(raw: bytes) -> str | None:
    if len(raw) != 16:
        return None
    d1 = int.from_bytes(raw[0:4], "little")
    d2 = int.from_bytes(raw[4:6], "little")
    d3 = int.from_bytes(raw[6:8], "little")
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{raw[8]:02x}{raw[9]:02x}-{raw[10:16].hex()}"


def parse_property_store(data: bytes, *, codepage: str = "cp1252") -> list[dict]:
    """Decode a property-store blob into a list of property dicts.

    Each entry is ``{"format_id", "name", "value"}``. Never raises: a
    malformed storage ends the walk and whatever was decoded so far is
    returned.
    """
    out: list[dict] = []
    cursor = 0
    storages = 0

    while cursor + 4 <= len(data) and storages < MAX_PROPERTY_STORAGES:
        size = _u32(data, cursor)
        if size is None or size == 0:
            break                       # terminator
        if size < 24 or cursor + size > len(data):
            logger.debug("property storage at %d has an invalid size (%s)", cursor, size)
            break

        storage = data[cursor:cursor + size]
        version = _u32(storage, 4)
        format_id = _guid(storage[8:24])
        if version != _STORAGE_VERSION or format_id is None:
            logger.debug("property storage version 0x%s is not 0x%08X",
                         f"{version:08X}" if version else "?", _STORAGE_VERSION)
            cursor += size
            storages += 1
            continue

        try:
            out.extend(_parse_values(storage, format_id, codepage))
        except Exception as exc:  # noqa: BLE001
            logger.debug("property value walk failed in %s: %s", format_id, exc)

        cursor += size
        storages += 1

    return out


def _parse_values(storage: bytes, format_id: str, codepage: str) -> list[dict]:
    """Walk the SerializedPropertyValue list inside one storage."""
    string_named = format_id.lower() == _STRING_NAMED_FMTID
    out: list[dict] = []
    cursor = 24
    count = 0

    while cursor + 4 <= len(storage) and count < MAX_PROPERTIES_PER_STORAGE:
        value_size = _u32(storage, cursor)
        if value_size is None or value_size == 0:
            break                       # end-of-values marker
        if value_size < 9 or cursor + value_size > len(storage):
            break

        entry = storage[cursor:cursor + value_size]
        if string_named:
            name_size = _u32(entry, 4) or 0
            raw_name = entry[9:9 + name_size]
            name = raw_name.decode("utf-16-le", errors="replace").rstrip("\x00")
            value_off = 9 + name_size
            identifier: int | None = None
        else:
            identifier = _u32(entry, 4)
            name = _PROPERTY_NAMES.get(
                (format_id.lower(), identifier if identifier is not None else -1),
                f"{{{format_id}}}/{identifier}",
            )
            value_off = 9

        value = _decode_typed_value(entry, value_off, codepage)
        out.append({
            "format_id": format_id,
            "property_id": identifier,
            "name": name,
            "value": value,
        })

        cursor += value_size
        count += 1

    return out


def _decode_typed_value(entry: bytes, off: int, codepage: str) -> str:
    """Decode one TypedPropertyValue to a display string.

    Unhandled types report their identifier and length rather than a
    guessed interpretation — a wrong value is worse than an honest
    ``<VT_0x1013, 24 bytes>``.
    """
    type_id = _u16(entry, off)
    if type_id is None:
        return ""
    body = off + 4                      # uint16 type + uint16 padding

    if type_id in (VT_EMPTY, VT_NULL):
        return ""

    if type_id == VT_I2:
        raw = _u16(entry, body)
        return "" if raw is None else str(int.from_bytes(
            raw.to_bytes(2, "little"), "little", signed=True))

    if type_id in (VT_I4, VT_UI4):
        raw = _u32(entry, body)
        return "" if raw is None else str(raw)

    if type_id in (VT_I8, VT_UI8):
        raw = _u64(entry, body)
        return "" if raw is None else str(raw)

    if type_id == VT_BOOL:
        raw = _u16(entry, body)
        return "" if raw is None else str(bool(raw))

    if type_id == VT_LPWSTR:
        count = _u32(entry, body) or 0
        raw = entry[body + 4:body + 4 + count * 2]
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    if type_id == VT_LPSTR:
        count = _u32(entry, body) or 0
        raw = entry[body + 4:body + 4 + count]
        try:
            return raw.decode(codepage, errors="replace").rstrip("\x00")
        except LookupError:
            return raw.decode("cp1252", errors="replace").rstrip("\x00")

    if type_id == VT_FILETIME:
        raw = _u64(entry, body)
        return _filetime(raw)

    if type_id == VT_CLSID:
        return _guid(entry[body:body + 16]) or ""

    if type_id == VT_BLOB:
        count = _u32(entry, body) or 0
        return f"<blob, {count} bytes>"

    return f"<VT_0x{type_id:04X}, {max(0, len(entry) - body)} bytes>"


def _filetime(raw: int | None) -> str:
    if not raw:
        return ""
    try:
        from datetime import datetime, timezone  # noqa: PLC0415

        seconds = (raw - _FILETIME_EPOCH_DELTA) / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""
