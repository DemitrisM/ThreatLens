"""ZIP handler — stdlib ``zipfile`` + raw EOCD/CD parser.

Primary extraction is via :mod:`zipfile` so we inherit its decryption,
decompression, and Unicode handling for free.

The raw parser exists for exactly one reason: ZIP header discrepancy
detection. Malware packs have been observed where the Local File Header
(LFH) and Central Directory (CD) disagree on filename, size, or
compression method — AV engines that trust only the CD miss the real
payload, while Windows Explorer / 7-Zip extract using the LFH. We walk
both independently and flag any mismatch.
"""

from __future__ import annotations

import logging
import struct
import time
import zipfile
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# zipfile-based enumeration (fast path)
# ---------------------------------------------------------------------------

def enumerate_zip(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
    """Read a ZIP and return normalised entries + container metadata."""
    meta = ContainerMeta(detected_format="zip")
    entries: list[ArchiveEntry] = []

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            try:
                comment = zf.comment.decode("utf-8", errors="replace")
            except (AttributeError, UnicodeDecodeError):
                comment = ""
            meta.comment = comment

            for info in zf.infolist():
                entries.append(_to_entry(info))
    except zipfile.BadZipFile as exc:
        meta.handler_errors.append({"stage": "enumerate_zip", "error": f"BadZipFile: {exc}"})
    except OSError as exc:
        meta.handler_errors.append({"stage": "enumerate_zip", "error": f"OSError: {exc}"})
    except Exception as exc:  # noqa: BLE001
        meta.handler_errors.append({"stage": "enumerate_zip", "error": f"{type(exc).__name__}: {exc}"})

    # Raw mismatch pass (best-effort)
    try:
        meta.zip_header_mismatches = _find_header_mismatches(file_path)
    except Exception as exc:  # noqa: BLE001
        meta.handler_errors.append({"stage": "zip_header_mismatches", "error": str(exc)})

    return entries, meta


def _to_entry(info: zipfile.ZipInfo) -> ArchiveEntry:
    is_encrypted = bool(info.flag_bits & 0x1)
    # Unix symlinks: external_attr high 16 bits = stat mode; mask == S_IFLNK (0o120000 == 0xA000)
    # (Python's ZipInfo stores the mode in (external_attr >> 16).)
    mode = info.external_attr >> 16
    is_symlink = (mode & 0xF000) == 0xA000
    try:
        ts = int(time.mktime(info.date_time + (0, 0, -1)))
    except (ValueError, OverflowError):
        ts = None

    compression_map = {
        0: "stored", 8: "deflate", 9: "deflate64",
        12: "bzip2", 14: "lzma", 93: "zstd", 98: "ppmd",
    }
    method = compression_map.get(info.compress_type, str(info.compress_type))

    return ArchiveEntry(
        name=info.filename,
        size_compressed=info.compress_size,
        size_uncompressed=info.file_size,
        is_encrypted=is_encrypted,
        is_symlink=is_symlink,
        timestamp=ts,
        method=method,
        crc=info.CRC,
    )


# ---------------------------------------------------------------------------
# Raw ZIP parser for header discrepancy detection
# ---------------------------------------------------------------------------

_EOCD_SIG = b"PK\x05\x06"
_CD_SIG = b"PK\x01\x02"
_LFH_SIG = b"PK\x03\x04"
_MAX_EOCD_LOOKBACK = 65536 + 22  # EOCD comment field is ≤ 64 KiB


def _find_header_mismatches(file_path: Path) -> list[dict]:
    """Return mismatches between per-entry LFH and CD records."""
    try:
        data = file_path.read_bytes()
    except OSError:
        return []

    cd_records = _walk_central_directory(data)
    if not cd_records:
        return []

    mismatches: list[dict] = []
    seen_names: set[str] = set()
    for cd in cd_records:
        if cd["filename"] in seen_names:
            continue
        seen_names.add(cd["filename"])
        lfh = _parse_lfh_at(data, cd["local_header_offset"])
        if lfh is None:
            continue
        diff: dict = {}
        if lfh["filename"] != cd["filename"]:
            diff["filename"] = {"lfh": lfh["filename"], "cd": cd["filename"]}
        if (
            lfh["compressed_size"]
            and cd["compressed_size"]
            and lfh["compressed_size"] != cd["compressed_size"]
        ):
            diff["compressed_size"] = {"lfh": lfh["compressed_size"], "cd": cd["compressed_size"]}
        if lfh["compression_method"] != cd["compression_method"]:
            diff["compression_method"] = {
                "lfh": lfh["compression_method"], "cd": cd["compression_method"],
            }
        if diff:
            mismatches.append({"name": cd["filename"], **diff})
    return mismatches


def _walk_central_directory(data: bytes) -> list[dict]:
    """Locate EOCD and walk every Central Directory entry."""
    eocd_offset = data.rfind(_EOCD_SIG, max(0, len(data) - _MAX_EOCD_LOOKBACK))
    if eocd_offset < 0:
        return []
    if eocd_offset + 22 > len(data):
        return []
    # EOCD layout: sig(4) disk(2) disk_cd(2) cd_entries_this(2) cd_entries_total(2) cd_size(4) cd_offset(4) comment_len(2)
    cd_size, cd_offset = struct.unpack("<II", data[eocd_offset + 12:eocd_offset + 20])

    records: list[dict] = []
    pos = cd_offset
    end = min(cd_offset + cd_size, len(data))
    while pos + 46 <= end:
        if data[pos:pos + 4] != _CD_SIG:
            break
        (_, _, _, flag, method, _, _, crc,
         comp_size, uncomp_size,
         name_len, extra_len, comment_len,
         _, _, _, local_offset,
         ) = struct.unpack("<IHHHHHHIIIHHHHHII", data[pos:pos + 46])
        name = data[pos + 46:pos + 46 + name_len].decode("utf-8", errors="replace")
        records.append({
            "filename": name,
            "compressed_size": comp_size,
            "uncompressed_size": uncomp_size,
            "compression_method": method,
            "local_header_offset": local_offset,
            "flag": flag,
            "crc": crc,
        })
        pos += 46 + name_len + extra_len + comment_len
    return records


def _parse_lfh_at(data: bytes, offset: int) -> dict | None:
    if offset < 0 or offset + 30 > len(data):
        return None
    if data[offset:offset + 4] != _LFH_SIG:
        return None
    (_, _, flag, method, _, _, crc,
     comp_size, uncomp_size, name_len, extra_len,
     ) = struct.unpack("<IHHHHHIIIHH", data[offset:offset + 30])
    name = data[offset + 30:offset + 30 + name_len].decode("utf-8", errors="replace")
    return {
        "filename": name,
        "compressed_size": comp_size,
        "uncompressed_size": uncomp_size,
        "compression_method": method,
        "flag": flag,
        "crc": crc,
    }


# ---------------------------------------------------------------------------
# Bounded extraction
# ---------------------------------------------------------------------------

def extract_members_to_temp(
    file_path: Path,
    entries: list[ArchiveEntry],
    tmp_dir: Path,
    max_total_bytes: int,
) -> None:
    """Extract small, non-encrypted members into ``tmp_dir``.

    Populates ``entry.extracted_path`` in place. Skips encrypted,
    oversize, or symlink members. Enforces a cumulative byte cap.
    """
    written = 0
    try:
        zf = zipfile.ZipFile(file_path, "r")
    except (zipfile.BadZipFile, OSError):
        return

    with zf:
        for e in entries:
            if e.is_encrypted or e.is_symlink:
                continue
            if e.size_uncompressed <= 0 or e.size_uncompressed > 50 * 1024 * 1024:
                continue
            if written + e.size_uncompressed > max_total_bytes:
                break
            safe_name = f"m_{len(list(tmp_dir.iterdir())):04d}_{Path(e.name).name[:80]}"
            out_path = tmp_dir / safe_name
            try:
                with zf.open(e.name) as src, out_path.open("wb") as dst:
                    dst.write(src.read())
            except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError) as exc:
                logger.debug("zip extract skipped for %s: %s", e.name, exc)
                continue
            e.extracted_path = str(out_path)
            written += e.size_uncompressed
