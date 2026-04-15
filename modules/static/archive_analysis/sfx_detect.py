"""SFX-PE overlay scanner.

A self-extracting archive is a regular PE whose overlay (bytes after the
last section's RawSize boundary) contains an archive payload. AV engines
that only walk the PE structure miss it; the dropper unpacks at runtime.

We scan the overlay for archive magic bytes and, separately, sweep the
whole file for a ZIP End-Of-Central-Directory marker — Python's
``zipfile`` module indexes from the EOCD, so a ZIP appended to a PE
remains a valid ZIP even when the local-file-header magic does not appear
in the overlay window.

On a hit we dump the overlay (or the bytes from the EOCD-derived offset)
to a tempfile so the orchestrator can recurse on it.
"""

from __future__ import annotations

import logging
import struct
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


# (format_name, magic_bytes)
_OVERLAY_MAGICS: list[tuple[str, bytes]] = [
    ("zip",        b"PK\x03\x04"),
    ("rar",        b"Rar!\x1a\x07\x00"),
    ("rar5",       b"Rar!\x1a\x07\x01\x00"),
    ("7z",         b"7z\xbc\xaf\x27\x1c"),
    ("nsis",       b"\xef\xbe\xad\xdeNullsoftInst"),
    ("innosetup",  b"zlb\x1a"),
    ("cab",        b"MSCF"),
]

_ZIP_EOCD = b"PK\x05\x06"
_MAX_EOCD_LOOKBACK = 65536 + 22  # comment field is ≤ 64 KiB


def scan_pe_overlay(file_path: Path) -> dict:
    """Return overlay-scan result.

    Result shape:
        {"is_sfx": bool,
         "embedded_format": str|None,
         "offset": int|None,
         "payload_path": str|None}
    """
    result: dict = {
        "is_sfx": False,
        "embedded_format": None,
        "offset": None,
        "payload_path": None,
    }

    overlay_offset, overlay_bytes = _read_overlay(file_path)

    if overlay_bytes:
        for fmt, magic in _OVERLAY_MAGICS:
            idx = overlay_bytes.find(magic)
            if idx >= 0:
                result["is_sfx"] = True
                result["embedded_format"] = "rar" if fmt == "rar5" else fmt
                result["offset"] = overlay_offset + idx
                result["payload_path"] = _dump_payload(overlay_bytes[idx:])
                return result

    # Whole-file ZIP-EOCD sweep — covers the case where the overlay
    # region we computed is empty/short but a valid ZIP is still
    # appended to the binary.
    eocd_hit = _find_eocd_payload(file_path, overlay_offset)
    if eocd_hit is not None:
        offset, payload = eocd_hit
        result["is_sfx"] = True
        result["embedded_format"] = "zip"
        result["offset"] = offset
        result["payload_path"] = _dump_payload(payload)

    return result


def _read_overlay(file_path: Path) -> tuple[int, bytes]:
    """Compute the overlay offset via pefile and return (offset, bytes).

    Returns ``(0, b"")`` on any failure.
    """
    try:
        import pefile  # noqa: PLC0415
    except ImportError:
        logger.debug("pefile not available — cannot compute overlay")
        return 0, b""

    try:
        pe = pefile.PE(str(file_path), fast_load=True)
    except Exception as exc:  # noqa: BLE001
        logger.debug("pefile parse failed for %s: %s", file_path, exc)
        return 0, b""

    try:
        offset = pe.get_overlay_data_start_offset()
    except Exception:  # noqa: BLE001
        offset = None
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass

    if offset is None:
        return 0, b""

    try:
        with file_path.open("rb") as fh:
            fh.seek(offset)
            return offset, fh.read()
    except OSError as exc:
        logger.debug("Could not read overlay bytes from %s: %s", file_path, exc)
        return 0, b""


def _find_eocd_payload(
    file_path: Path, overlay_offset: int,
) -> tuple[int, bytes] | None:
    """Locate a ZIP EOCD anywhere in the file and return (offset, payload).

    The payload is the slice from the central-directory offset to EOF.
    """
    try:
        with file_path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - _MAX_EOCD_LOOKBACK))
            tail = fh.read()
    except OSError:
        return None

    eocd_idx = tail.rfind(_ZIP_EOCD)
    if eocd_idx < 0 or eocd_idx + 22 > len(tail):
        return None

    try:
        cd_size, cd_offset = struct.unpack(
            "<II", tail[eocd_idx + 12:eocd_idx + 20],
        )
    except struct.error:
        return None

    # If the central directory sits inside the PE structural region the
    # ZIP is the whole file (no SFX); only flag it when the CD lives
    # past the overlay boundary.
    if cd_offset == 0 or (overlay_offset and cd_offset < overlay_offset):
        return None

    try:
        with file_path.open("rb") as fh:
            fh.seek(cd_offset)
            payload = fh.read()
    except OSError:
        return None

    if not payload:
        return None
    return cd_offset, payload


def _dump_payload(payload: bytes) -> str | None:
    """Write payload bytes to a tempfile; return its path."""
    try:
        tmp = tempfile.NamedTemporaryFile(
            prefix="sfx_overlay_", delete=False,
        )
        tmp.write(payload)
        tmp.close()
        return tmp.name
    except OSError as exc:
        logger.debug("Could not dump SFX overlay payload: %s", exc)
        return None
