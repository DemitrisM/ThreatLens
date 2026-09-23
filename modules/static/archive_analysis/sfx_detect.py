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

Design notes
------------
**The caller owns the dumped file, not this module.** :func:`_dump_payload`
mints a ``delete=False`` tempfile and returns its path; deleting it is
``_analyse_pe_for_sfx``'s job, in a ``finally`` so a failed recursion
still cleans up. Those bytes are live malware, so an early return that
forgets them leaves a payload in the system temp directory after the
scan ends — which is exactly the defect that was fixed for gz/bz2/xz in
0.5.2. Any new caller inherits that obligation.

**Two detectors, because one shape is invisible to the other.** The
overlay scan searches the bytes after the last section for a
local-file-header magic. That misses a ZIP appended to a PE, because
Python's ``zipfile`` indexes from the End-Of-Central-Directory record at
the *end* of the file and will happily open such a file as a valid
archive even when no ``PK\x03\x04`` appears in the window we computed
— a real SFX shape that the structural scan alone reports as clean. The
EOCD sweep covers it, and runs second because the overlay scan is the
cheaper and more specific test.

**Detection is deliberately shallow.** Finding archive magic is all this
module does; whether the payload is a real archive, and what is in it,
is settled by re-entering the pipeline on the dumped file. That keeps
one implementation of archive parsing rather than a second weaker one
here, and it means an SFX dropper's payload gets the full indicator set.

A failure anywhere degrades to "not an SFX" rather than raising. Missing
`pefile`, an unparseable binary, an unreadable overlay and a failed
tempfile write all return the same negative result, per design rule 2.
The cost is a false negative on a damaged PE, which is the right trade
against taking down a triage run.
"""

from __future__ import annotations

import logging
import struct
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


# (format_name, magic_bytes), searched in order and anywhere within the
# overlay rather than at a fixed offset — an SFX stub writes its own
# header and padding first, so the payload's start is not predictable.
#
# The two installer entries earn their place: NSIS and Inno Setup are
# not archive formats the handlers can enumerate, but finding one still
# answers the question this module asks, which is whether an executable
# is carrying a packaged payload.
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

    Args:
        file_path: A file already known to start with ``MZ``.

    Returns:
        ``{"is_sfx": bool, "embedded_format": str|None,
        "offset": int|None, "payload_path": str|None}``.

        ``payload_path`` names a tempfile **the caller must delete** —
        see the module docstring. It can be ``None`` on a positive hit
        if the dump failed, so a caller must test it rather than assume
        ``is_sfx`` implies a path.

    ``offset`` is absolute within the file, not relative to the overlay,
    so it can be quoted straight into a report or a hex editor.
    """
    result: dict = {
        "is_sfx": False,
        "embedded_format": None,
        "offset": None,
        "payload_path": None,
    }

    overlay_offset, overlay_bytes = _read_overlay(file_path)

    # ---- Pass 1: archive magic inside the overlay ---------------------
    # Returns on the first hit. A dropper carrying two payloads is not a
    # shape worth the extra dumps — the recursion on the first one
    # reaches the same verdict, and every dump is malware written to
    # disk.
    if overlay_bytes:
        for fmt, magic in _OVERLAY_MAGICS:
            idx = overlay_bytes.find(magic)
            if idx >= 0:
                result["is_sfx"] = True
                result["embedded_format"] = "rar" if fmt == "rar5" else fmt
                result["offset"] = overlay_offset + idx
                result["payload_path"] = _dump_payload(overlay_bytes[idx:])
                return result

    # ---- Pass 2: whole-file ZIP EOCD sweep ----------------------------
    # Covers the case pass 1 cannot see: the overlay region came back
    # empty or short — because `pefile` is absent, the binary is
    # malformed, or the section table lies about where data ends — yet a
    # valid ZIP is still appended. `zipfile` finds it from the EOCD
    # regardless, so an analyst's tooling would open it even though the
    # structural scan reported nothing.
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

    Args:
        file_path: The PE to read.

    Returns:
        ``(offset, bytes)`` where offset is the absolute start of the
        overlay, or ``(0, b"")`` on any failure.

    ``(0, b"")`` conflates "no overlay" with "could not tell", and the
    caller relies on that: an offset of 0 disables the
    ``cd_offset < overlay_offset`` sanity test in
    :func:`_find_eocd_payload`, so a PE we could not parse still gets
    the EOCD sweep instead of being silently skipped. The two cases do
    not need distinguishing because the response to both is the same.

    ``pefile`` is imported inside the function, not at module scope, so
    that a missing optional dependency degrades this one check rather
    than failing the whole package's import.
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

    # The PE object holds a mapped file, so it is closed in `finally`
    # whether or not the offset lookup worked — a leaked handle per
    # sample exhausts the descriptor limit across a triage run.
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

    Args:
        file_path:      The PE being scanned.
        overlay_offset: Absolute overlay start, or 0 when unknown.

    Returns:
        ``(cd_offset, payload)`` where payload is the slice from the
        central-directory offset to EOF, or ``None`` when no appended
        ZIP was found.

    Only the tail is read. The EOCD is the last structure in a ZIP
    except for its optional comment, which the format caps at 64 KiB, so
    a fixed lookback of 64 KiB + the 22-byte record is exhaustive rather
    than a heuristic — and it keeps the check O(1) on a large binary.

    ``rfind`` rather than ``find``: the EOCD byte sequence can occur
    inside compressed data, and the real record is the last one.
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

    # ---- Reject the ZIP that is the whole file -------------------------
    # A plain `.zip` renamed to `.exe` is not an SFX dropper, and neither
    # is a PE whose central directory sits inside its structural region.
    # Requiring the CD to live past the overlay boundary is what makes
    # this "a PE carrying an archive" rather than "a file that is an
    # archive". When `overlay_offset` is 0 the test is skipped rather
    # than failed — see `_read_overlay` on why unknown must not mean no.
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
    """Write payload bytes to a tempfile; return its path.

    Args:
        payload: The carved bytes.

    Returns:
        The tempfile path, or ``None`` if it could not be written.

    ``delete=False`` because the file has to outlive this function for
    the orchestrator to re-enter the pipeline on it.

    Ownership transfers exactly when a path is returned. Up to that
    point the file is this function's, and every failure path — a
    refused write, a flush that fails at close, an exception that is not
    an OSError at all — removes it before leaving. After that point
    **the caller owns the deletion**, and nothing else will remove it.
    These are live malware bytes, so there is no third state where
    neither side is responsible. The ``sfx_overlay_`` prefix exists so a
    leak is identifiable if one ever escapes anyway.
    """
    # Structure note: the outer `finally` contains the unlink and nothing
    # else. That is the whole design of this function. Anything placed
    # before it in the same block — a close(), a log call — is another
    # statement that can raise or be interrupted, and an interrupt there
    # skips the unlink and leaks the payload. Ctrl-C is asynchronous and
    # KeyboardInterrupt derives from BaseException, so `except OSError`
    # does not contain it. Keep the outer `finally` a single guarded
    # unlink; put anything else in the inner one.
    tmp = None
    handed_over = False
    try:
        tmp = tempfile.NamedTemporaryFile(
            prefix="sfx_overlay_", delete=False,
        )
        try:
            tmp.write(payload)
            # close() is inside the try, not deferred to cleanup, because
            # write() on a buffered file can succeed with the bytes still
            # in memory — the flush that reaches disk happens here. A full
            # disk therefore surfaces at close, leaving a short or empty
            # file, and that has to fail the dump. Handing the
            # orchestrator a truncated payload to recurse into and score
            # is a wrong answer, which is worse than the missing one
            # `None` gives.
            tmp.close()
        finally:
            # Only reached when write() or close() did not complete. The
            # descriptor must be released before the unlink below, on the
            # platforms where that matters.
            if not tmp.closed:
                try:
                    tmp.close()
                except Exception:  # noqa: BLE001
                    logger.debug("Could not close SFX payload dump")
        # Set only once the bytes are on disk and the path is about to be
        # returned: this is the single point where ownership of the file
        # passes to the caller.
        handed_over = True
        return tmp.name
    except OSError as exc:
        logger.debug("Could not dump SFX overlay payload: %s", exc)
        return None
    finally:
        if tmp is not None and not handed_over:
            try:
                Path(tmp.name).unlink(missing_ok=True)
            except OSError:
                logger.debug("Could not remove partial SFX payload dump")
