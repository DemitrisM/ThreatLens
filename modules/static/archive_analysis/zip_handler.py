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

            for idx, info in enumerate(zf.infolist()):
                entry = _to_entry(info)
                entry.member_index = idx
                entries.append(entry)
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

# General-purpose bit 3: the member's sizes are unknown at local-header
# time and follow the payload in a data descriptor.
_FLAG_DATA_DESCRIPTOR = 0x08

# A 32-bit size field set to all ones is not a size. It means the real
# value did not fit and lives in the Zip64 extended-information extra
# field, so it is a redirection and comparing it against a number
# compares a value with a pointer to a value.
_ZIP64_SENTINEL = 0xFFFFFFFF

# Header ID of the Zip64 extended-information extra field, which carries
# the 64-bit values the sentinel redirects to.
_ZIP64_EXTRA_ID = 0x0001
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
        # A method disagreement means the two readers decode the same
        # bytes differently — the parser differential this module exists
        # to find — so it is compared unconditionally. No exemption
        # applies: the method is known when either header is written.
        if lfh["compression_method"] != cd["compression_method"]:
            diff["compression_method"] = {
                "lfh": lfh["compression_method"],
                "cd": cd["compression_method"],
            }

        # Sizes are compared unless BOTH headers agree the member is
        # streamed. Three rules, each closing a shape the previous one
        # let through.
        #
        # 1. A streamed member cannot know its sizes when the LFH goes
        #    out. It sets bit 3, writes zeros, and puts the real figures
        #    in a trailing data descriptor and in the CD. Legal, common,
        #    and not a mismatch.
        #
        # 2. The exemption is taken from the flag, not from the zeros,
        #    and it covers the whole member rather than each field.
        #    Excusing a zero field by field let an attacker declare a
        #    real compressed size — proving the size was known, so the
        #    member was not streamed — while zeroing only the
        #    uncompressed size, the one field every bomb threshold is
        #    measured against.
        #
        # 3. Both headers must claim it. Reading bit 3 from the LFH
        #    alone was a cleaner version of the same bypass: set it
        #    there so the size comparison is skipped, clear it in the CD
        #    and declare small sizes so the bomb guard is satisfied, and
        #    leave the real figures in the data descriptor that Explorer
        #    and 7-Zip read. Two headers disagreeing about whether a
        #    data descriptor exists is itself the anomaly, so it is
        #    reported in its own right.
        #
        # Limit worth knowing: for a genuinely streamed member the sizes
        # an extractor uses live in that data descriptor, which this
        # parser does not walk. Such a member is exempted, not verified.
        lfh_streamed = bool(lfh["flag"] & _FLAG_DATA_DESCRIPTOR)
        cd_streamed = bool(cd["flag"] & _FLAG_DATA_DESCRIPTOR)

        if lfh_streamed != cd_streamed:
            diff["data_descriptor_flag"] = {
                "lfh": lfh_streamed, "cd": cd_streamed,
            }

        if not (lfh_streamed and cd_streamed):
            # Sentinels are resolved through the Zip64 extra field, not
            # skipped. Skipping was itself an evasion primitive: declare
            # a small size in the CD so the bomb guard is satisfied, put
            # the sentinel in the LFH, and a streaming extractor follows
            # it to the 64-bit value and unpacks the real payload while
            # the comparison that should have caught the split declined
            # to look. Real files need the resolution rather than the
            # skip — APT36.docm in the sample corpus carries a proper
            # 0x0001 field for the members that use a sentinel.
            lfh_sizes = _resolve_sizes(lfh, central=False)
            cd_sizes = _resolve_sizes(cd, central=True)

            if lfh_sizes is None or cd_sizes is None:
                # A sentinel promises a value the extra field does not
                # deliver. Nothing reading this header can obtain a size,
                # which is a divergence in its own right rather than a
                # reason to stay silent.
                diff["zip64_sentinel_unresolved"] = {
                    "lfh": lfh_sizes is None, "cd": cd_sizes is None,
                }
            else:
                for idx, field in enumerate(
                    ("compressed_size", "uncompressed_size"),
                ):
                    if lfh_sizes[idx] != cd_sizes[idx]:
                        diff[field] = {
                            "lfh": lfh_sizes[idx], "cd": cd_sizes[idx],
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
        extra_start = pos + 46 + name_len
        records.append({
            "filename": name,
            "compressed_size": comp_size,
            "uncompressed_size": uncomp_size,
            "compression_method": method,
            "local_header_offset": local_offset,
            "flag": flag,
            "crc": crc,
            "extra": data[extra_start:extra_start + extra_len],
        })
        pos += 46 + name_len + extra_len + comment_len
    return records


def _zip64_extra(extra: bytes) -> bytes | None:
    """Return the payload of the Zip64 extended-information field.

    Args:
        extra: The raw extra-field area of either header.

    Returns:
        The bytes of the ``0x0001`` record, or None when it is absent or
        the extra area is malformed.

    The extra area is a sequence of ``(id, size, payload)`` records. A
    record whose declared size runs past the end of the area means the
    area cannot be trusted, so the walk stops rather than guessing — the
    same reasoning as the central-directory walk.
    """
    pos = 0
    while pos + 4 <= len(extra):
        tag, size = struct.unpack("<HH", extra[pos:pos + 4])
        payload_start = pos + 4
        payload_end = payload_start + size
        if payload_end > len(extra):
            return None
        if tag == _ZIP64_EXTRA_ID:
            return extra[payload_start:payload_end]
        pos = payload_end
    return None


def _resolve_sizes(record: dict, central: bool) -> tuple[int, int] | None:
    """Return ``(compressed, uncompressed)`` with Zip64 sentinels resolved.

    Args:
        record:  A parsed LFH or CD record.
        central: True for a central-directory record, which packs its
                 Zip64 field differently from a local header.

    Returns:
        The effective sizes, or None when a sentinel is present and the
        Zip64 extended-information field cannot supply its value.

    The two headers do not encode this the same way, which is why the
    flag exists. A local header that uses Zip64 writes **both** 8-byte
    sizes; a central-directory record writes only the fields whose
    32-bit slot holds the sentinel, in the fixed order uncompressed,
    compressed, local-header offset. Reading the central form with the
    local rule silently yields the wrong numbers rather than an error.

    Returning None is a finding, not an absence. A sentinel says "the
    real value is in the extra field", so a sentinel with no such field
    is a header that cannot be resolved by anything reading it — which
    is a divergence in itself, and the caller reports it.
    """
    comp = record["compressed_size"]
    uncomp = record["uncompressed_size"]
    if _ZIP64_SENTINEL not in (comp, uncomp):
        return comp, uncomp

    payload = _zip64_extra(record.get("extra") or b"")
    if payload is None:
        return None

    if not central:
        # Local header: both sizes, always, uncompressed first.
        if len(payload) < 16:
            return None
        uncomp64, comp64 = struct.unpack("<QQ", payload[:16])
        return comp64, uncomp64

    # Central directory: only the sentinel fields are present, in order.
    pos = 0
    if uncomp == _ZIP64_SENTINEL:
        if pos + 8 > len(payload):
            return None
        uncomp = struct.unpack("<Q", payload[pos:pos + 8])[0]
        pos += 8
    if comp == _ZIP64_SENTINEL:
        if pos + 8 > len(payload):
            return None
        comp = struct.unpack("<Q", payload[pos:pos + 8])[0]
    return comp, uncomp


def _parse_lfh_at(data: bytes, offset: int) -> dict | None:
    if offset < 0 or offset + 30 > len(data):
        return None
    if data[offset:offset + 4] != _LFH_SIG:
        return None
    (_, _, flag, method, _, _, crc,
     comp_size, uncomp_size, name_len, extra_len,
     ) = struct.unpack("<IHHHHHIIIHH", data[offset:offset + 30])
    name = data[offset + 30:offset + 30 + name_len].decode("utf-8", errors="replace")
    extra_start = offset + 30 + name_len
    return {
        "filename": name,
        "compressed_size": comp_size,
        "uncompressed_size": uncomp_size,
        "compression_method": method,
        "flag": flag,
        "crc": crc,
        "extra": data[extra_start:extra_start + extra_len],
    }


def _locate(entry: ArchiveEntry, infos: list) -> object | None:
    """Return the library record this entry describes, or None.

    Args:
        entry: The normalised member, carrying ``member_index``.
        infos: The container's record list, in its own order.

    Returns:
        The record at ``entry.member_index``, or None when the index is
        absent or out of range. Falling back to a name lookup here would
        reintroduce exactly the duplicate-name confusion the index exists
        to prevent, so an unusable index skips the member instead.
    """
    idx = entry.member_index
    if idx is None or not (0 <= idx < len(infos)):
        logger.debug("no usable member_index for %s — skipping", entry.name)
        return None
    return infos[idx]


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
        # Members are addressed by ZipInfo, not by name. A name is not
        # unique — zipfile maps one to the *last* matching record — so
        # zf.open(e.name) read that record once per duplicate and never
        # opened the others. A pair of members sharing a name meant the
        # first was never examined at all: a free way to hide a payload
        # from a scanner that extracts by name.
        #
        # _locate resolves the record from the index the enumerator stored
        # on the entry. Pairing positionally with zip() instead would
        # misalign silently the moment `entries` is filtered or reordered,
        # because zip() pairs entries[0] with infos[0] whether or not they
        # describe the same member — one dropped record shifts every
        # mapping after it, and the scanner then reads the wrong bytes
        # under the right name. Raised by Gemini.
        infos = zf.infolist()

        # Monotonic counter rather than len(list(tmp_dir.iterdir())): the
        # directory listing was re-read once per member, making naming
        # O(n^2) in member count for no benefit.
        index = 0
        for e in entries:
            if e.is_encrypted or e.is_symlink:
                continue
            info = _locate(e, infos)
            if info is None:
                continue
            if e.size_uncompressed <= 0 or e.size_uncompressed > 50 * 1024 * 1024:
                continue
            if written + e.size_uncompressed > max_total_bytes:
                break
            safe_name = f"m_{index:04d}_{Path(e.name).name[:80]}"
            out_path = tmp_dir / safe_name
            try:
                with zf.open(info) as src, out_path.open("wb") as dst:
                    dst.write(src.read())
            except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError) as exc:
                logger.debug("zip extract skipped for %s: %s", e.name, exc)
                continue
            e.extracted_path = str(out_path)
            written += e.size_uncompressed
            index += 1
