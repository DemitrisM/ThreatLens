"""Raw RAR header parser — recovers unsanitised filenames.

The ``rarfile`` library strips NTFS Alternate Data Stream (ADS) suffixes
from member names before exposing them. CVE-2025-8088 (WinRAR 7.x
path-traversal) hides its real drop path inside that suffix —
``fiyat teklifi.pdf:..\\..\\AppData\\...\\Startup\\Updater.exe`` — so
``rarfile.infolist()`` reports only ``fiyat teklifi.pdf`` and the
existing path-traversal indicator never sees the malicious bytes.

This module parses the RAR file headers directly (no external deps,
pure ``struct`` walking) and returns each member's raw filename
including any ADS suffix. It is best-effort: malformed bytes return
whatever was parsed up to the failure point.

RAR5 is the default format written by WinRAR 6.x / 7.x and every
sample observed in the corpus uses it. RAR4 support is included as a
fallback for older archives.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path

logger = logging.getLogger(__name__)


_RAR4_SIG = b"Rar!\x1a\x07\x00"
_RAR5_SIG = b"Rar!\x1a\x07\x01\x00"
_MAX_RAR_BYTES = 64 * 1024 * 1024  # cap memory for huge archives


def parse_rar_filenames(file_path: Path) -> list[dict]:
    """Walk RAR headers and return one entry per member.

    Returns:
        ``[{"name": str, "ads_suffix": str | None}, ...]`` in archive
        order. ``ads_suffix`` is the NTFS Alternate Data Stream name
        recovered from a sibling SERVICE record (RAR5 ``STM`` record
        type) — this is where CVE-2025-8088 hides its drop path. The
        in-name ``X:Y`` colon-split is also recognised. Empty list on
        any I/O failure or unrecognised signature.
    """
    try:
        size = file_path.stat().st_size
        if size > _MAX_RAR_BYTES:
            with file_path.open("rb") as fh:
                data = fh.read(_MAX_RAR_BYTES)
        else:
            data = file_path.read_bytes()
    except OSError as exc:
        logger.debug("rar_raw_headers: read failed for %s: %s", file_path, exc)
        return []

    try:
        if data.startswith(_RAR5_SIG):
            return _parse_rar5(data, len(_RAR5_SIG))
        if data.startswith(_RAR4_SIG):
            return _parse_rar4(data, len(_RAR4_SIG))
    except Exception as exc:  # noqa: BLE001
        logger.debug("rar_raw_headers: parser crashed on %s: %s", file_path, exc)
        return []

    return []


# ---------------------------------------------------------------------------
# RAR5 walker
# ---------------------------------------------------------------------------

def _parse_rar5(data: bytes, start: int) -> list[dict]:
    """Walk RAR5 records.

    Type 2 = FILE header. Type 3 = SERVICE header (named auxiliary
    blocks). The SERVICE record named ``STM`` carries an NTFS
    Alternate Data Stream definition for the most-recently-seen file —
    its data area contains the stream name. CVE-2025-8088 puts a
    traversal payload (``..\\..\\AppData\\...``) in that name, so we
    propagate it back onto the preceding file entry as ``ads_suffix``.
    """
    out: list[dict] = []
    pos = start
    n = len(data)
    guard = 0

    while pos + 4 < n and guard < 100_000:
        guard += 1
        # Each record: CRC32 (4 fixed bytes) + vint header_size +
        # vint header_type + vint header_flags + ...
        try:
            head_crc_end = pos + 4
            header_size, vsz = _read_vint(data, head_crc_end)
        except _VIntError:
            break

        record_start = head_crc_end + vsz
        record_end = record_start + header_size
        if record_end > n or header_size == 0:
            break

        try:
            header_type, t_sz = _read_vint(data, record_start)
            header_flags, f_sz = _read_vint(data, record_start + t_sz)
        except _VIntError:
            pos = record_end
            continue

        # Optional extra/data area sizes encoded in the record's flag
        # vint (bit 0 = has extra area, bit 1 = has data area).
        cursor = record_start + t_sz + f_sz
        data_size = 0
        try:
            if header_flags & 0x01:
                _extra_size, sz = _read_vint(data, cursor)
                cursor += sz
            if header_flags & 0x02:
                data_size, sz = _read_vint(data, cursor)
                cursor += sz
        except _VIntError:
            pos = record_end + data_size
            continue

        if header_type == 2:  # file header
            try:
                name = _parse_rar5_file_header(data, cursor, record_end)
            except (_VIntError, struct.error, IndexError, UnicodeDecodeError):
                name = None
            if name is not None:
                out.append({"name": name, "ads_suffix": _split_ads(name)})

        elif header_type == 3 and out:  # service header
            try:
                svc_name = _parse_rar5_file_header(data, cursor, record_end)
            except (_VIntError, struct.error, IndexError, UnicodeDecodeError):
                svc_name = None
            if svc_name == "STM":
                stream_name = _read_stm_stream_name(data, cursor, record_end)
                if stream_name:
                    # Attach to the most recent file entry. Two STM
                    # streams on the same file would overwrite — rare
                    # in practice and the second is just as malicious.
                    out[-1]["ads_suffix"] = stream_name

        # Advance past header + (data area if present).
        pos = record_end + data_size

    return out


def _read_stm_stream_name(data: bytes, body_cursor: int, body_end: int) -> str | None:
    """Extract the ADS stream name from an STM service record header.

    In the CVE-2025-8088 samples the stream name does NOT live in the
    record's data area — it lives inside the service record's *header*
    body as a RAR5 extra record appended after the ``file_name`` field
    (value "STM"). Layout after the name:

      vint extra_record_size | vint extra_record_type (7 = STM) |
      stream_name (runs to end of header body, NUL-padded)

    ``body_cursor`` is the position immediately after the file-header
    prefix (flags/sizes/crc/comp/os/name_len consumed) and ``body_end``
    is ``record_end`` for the service record. The caller has already
    confirmed the name is "STM", so we just look for the first ``:``
    byte in the remaining header bytes — that is the ADS separator.
    Returns ``None`` if the body yields no plausible stream name.
    """
    if body_end <= body_cursor or body_end > len(data):
        return None
    tail = data[body_cursor:body_end]
    colon = tail.find(b":")
    if colon < 0:
        return None
    raw = tail[colon:].rstrip(b"\x00")
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace")


def _parse_rar5_file_header(data: bytes, start: int, end: int) -> str | None:
    """Extract the FILE_NAME field from a RAR5 file-header record.

    Layout (relative to ``start``):
      vint file_flags | vint unp_size | vint attrs |
      [4 mtime if file_flags & 0x02] | [4 data_crc if file_flags & 0x04] |
      vint compression_info | vint host_os |
      vint name_length | name_length bytes (UTF-8)
    """
    pos = start
    file_flags, sz = _read_vint(data, pos); pos += sz
    _unp_size,  sz = _read_vint(data, pos); pos += sz
    _attrs,     sz = _read_vint(data, pos); pos += sz
    if file_flags & 0x02:
        pos += 4  # mtime (Unix epoch, fixed 32-bit)
    if file_flags & 0x04:
        pos += 4  # data crc
    _comp,      sz = _read_vint(data, pos); pos += sz
    _host_os,   sz = _read_vint(data, pos); pos += sz
    name_len,   sz = _read_vint(data, pos); pos += sz

    if name_len == 0 or pos + name_len > end:
        return None

    name_bytes = data[pos:pos + name_len]
    return name_bytes.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# RAR4 walker (fallback for legacy archives)
# ---------------------------------------------------------------------------

def _parse_rar4(data: bytes, start: int) -> list[dict]:
    out: list[dict] = []
    pos = start
    n = len(data)
    guard = 0

    while pos + 7 <= n and guard < 100_000:
        guard += 1
        try:
            _crc, head_type, head_flags, head_size = struct.unpack(
                "<HBHH", data[pos:pos + 7],
            )
        except struct.error:
            break
        if head_size < 7:
            break

        add_size = 0
        if head_flags & 0x8000:
            if pos + 11 > n:
                break
            add_size = struct.unpack("<I", data[pos + 7:pos + 11])[0]

        block_end = pos + head_size + add_size
        if block_end > n or block_end <= pos:
            break

        if head_type == 0x74:  # FILE_HEAD
            name = _parse_rar4_file_name(data, pos, head_size, head_flags)
            if name:
                out.append({"name": name, "ads_suffix": _split_ads(name)})

        pos = block_end

    return out


def _parse_rar4_file_name(
    data: bytes, block_pos: int, head_size: int, head_flags: int,
) -> str | None:
    """Pull FILE_NAME bytes out of a RAR4 FILE_HEAD block."""
    # Layout from block_pos: 7 head + 4 pack_size + 4 unp_size + 1 host_os
    # + 4 file_crc + 4 ftime + 1 unp_ver + 1 method + 2 name_size + 4 attr
    fixed_end = block_pos + 32
    if fixed_end > block_pos + head_size:
        return None

    try:
        name_size = struct.unpack("<H", data[block_pos + 26:block_pos + 28])[0]
    except struct.error:
        return None

    name_off = fixed_end
    if head_flags & 0x100:  # LHD_LARGE — 8 extra bytes for >2GB sizes
        name_off += 8
    if name_off + name_size > block_pos + head_size:
        return None

    raw = data[name_off:name_off + name_size]
    if head_flags & 0x200:  # LHD_UNICODE — ASCII portion before the null
        nul = raw.find(b"\x00")
        if nul >= 0:
            raw = raw[:nul]

    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class _VIntError(Exception):
    """Raised when a RAR5 vint exceeds its 10-byte cap."""


def _read_vint(data: bytes, pos: int) -> tuple[int, int]:
    """RAR5 variable-length integer — 7 bits/byte, MSB = continuation."""
    val = 0
    shift = 0
    n = len(data)
    consumed = 0
    while consumed < 10 and pos + consumed < n:
        b = data[pos + consumed]
        val |= (b & 0x7F) << shift
        consumed += 1
        if not (b & 0x80):
            return val, consumed
        shift += 7
    raise _VIntError("vint exceeded 10 bytes")


def _split_ads(name: str) -> str | None:
    """Return the ADS suffix, or None if the name has no ADS marker.

    A drive-letter prefix (``C:\\foo``) shares the colon syntax but is
    not an ADS — strip it off before checking.
    """
    candidate = name
    if len(candidate) >= 2 and candidate[1] == ":" and candidate[0].isalpha():
        candidate = candidate[2:]
    if ":" not in candidate:
        return None
    _, _, suffix = candidate.partition(":")
    return suffix or None
