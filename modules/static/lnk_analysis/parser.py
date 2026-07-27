"""MS-SHLLINK binary walker — bounds-checked and non-raising.

Implements the Shell Link (.LNK) Binary File Format, [MS-SHLLINK] rev 10.0
(21 Nov 2025). The layout is::

    SHELL_LINK = ShellLinkHeader
                 [LinkTargetIDList]   ; iff LinkFlags.HasLinkTargetIDList
                 [LinkInfo]           ; iff LinkFlags.HasLinkInfo
                 [StringData]         ; each substructure gated by its own flag
                 *ExtraData TERMINAL_BLOCK
                 [overlay]            ; not part of the format at all

Design notes that are not obvious from the spec:

* **Nothing here raises.** Every integer read goes through the ``_u*``
  accessors, which return ``None`` past the end of the buffer rather than
  letting ``struct.error`` escape. Every section is parsed in its own
  ``try`` in :func:`parse_bytes`, because malware relies on a busted
  IDList preventing a parser from ever reaching the command line.
* **Spec violations become data, not exceptions.** ``MUST be zero`` fields
  that are not zero, out-of-range offsets and bad terminators all append
  to ``ParsedLnk.anomalies``, which feeds the score. That is free
  detection signal an exception would throw away.
* **Size-prefixed walks are the loop hazard.** ``ItemIDSize`` includes its
  own two bytes, so a value of 0 or 1 advances the cursor by <= 0 bytes
  forever — and real samples set it to 0 deliberately. Every such walk in
  this package goes through :func:`iter_sized_records`, which enforces a
  minimum size, a monotonic cursor and a record cap.
* **The terminal block is any uint32 < 4**, not four zero bytes. Parsers
  that hard-check for zero keep walking into appended data and misparse
  it as blocks; we stop, and everything after becomes ``overlay``.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .propstore import parse_property_store
from .shellitems import ShellItem, decode_shell_item

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: [MS-SHLLINK] 2.1 — HeaderSize MUST be 0x0000004C.
HEADER_SIZE = 0x4C

#: LinkCLSID 00021401-0000-0000-C000-000000000046 in GUID packet
#: representation (first three groups little-endian, last two big-endian).
LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")

#: The 8 bytes every real shell link starts with: HeaderSize + the first
#: four bytes of LinkCLSID. This is what bartblaze's ``isLNK`` YARA rule
#: matches on, and it is a far better gate than the file extension.
LNK_MAGIC = HEADER_SIZE.to_bytes(4, "little") + LINK_CLSID[:4]

_LNK_EXTENSIONS = frozenset({".lnk"})

#: [MS-SHLLINK] 2.1.1, LSB-first.
LINK_FLAGS: tuple[tuple[int, str], ...] = (
    (0x00000001, "HasLinkTargetIDList"),
    (0x00000002, "HasLinkInfo"),
    (0x00000004, "HasName"),
    (0x00000008, "HasRelativePath"),
    (0x00000010, "HasWorkingDir"),
    (0x00000020, "HasArguments"),
    (0x00000040, "HasIconLocation"),
    (0x00000080, "IsUnicode"),
    (0x00000100, "ForceNoLinkInfo"),
    (0x00000200, "HasExpString"),
    (0x00000400, "RunInSeparateProcess"),
    (0x00000800, "Unused1"),
    (0x00001000, "HasDarwinID"),
    (0x00002000, "RunAsUser"),
    (0x00004000, "HasExpIcon"),
    (0x00008000, "NoPidlAlias"),
    (0x00010000, "Unused2"),
    (0x00020000, "RunWithShimLayer"),
    (0x00040000, "ForceNoLinkTrack"),
    (0x00080000, "EnableTargetMetadata"),
    (0x00100000, "DisableLinkPathTracking"),
    (0x00200000, "DisableKnownFolderTracking"),
    (0x00400000, "DisableKnownFolderAlias"),
    (0x00800000, "AllowLinkToLink"),
    (0x01000000, "UnaliasOnSave"),
    (0x02000000, "PreferEnvironmentPath"),
    (0x04000000, "KeepLocalIDListForUNCTarget"),
)

#: Bits 27-31 MUST be zero.
_RESERVED_FLAG_MASK = 0xF8000000

#: [MS-SHLLINK] 2.1.2. Bits 15-31 MUST be zero; 0x0008 and 0x0040 are
#: reserved and MUST be zero.
FILE_ATTRIBUTES: tuple[tuple[int, str], ...] = (
    (0x0001, "READONLY"),
    (0x0002, "HIDDEN"),
    (0x0004, "SYSTEM"),
    (0x0010, "DIRECTORY"),
    (0x0020, "ARCHIVE"),
    (0x0080, "NORMAL"),
    (0x0100, "TEMPORARY"),
    (0x0200, "SPARSE_FILE"),
    (0x0400, "REPARSE_POINT"),
    (0x0800, "COMPRESSED"),
    (0x1000, "OFFLINE"),
    (0x2000, "NOT_CONTENT_INDEXED"),
    (0x4000, "ENCRYPTED"),
)
_RESERVED_ATTR_MASK = 0x0008 | 0x0040 | 0xFFFF8000

SHOW_COMMANDS = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED", 7: "SW_SHOWMINNOACTIVE"}

#: [MS-SHLLINK] 2.5. Signatures verified against EricZimmerman/Lnk
#: ``ExtraData/ExtraDataBase.cs``. The per-block *sizes* in the spec are
#: deliberately not enforced — several are unverified, and rejecting a
#: block on a size mismatch would lose real samples.
EXTRA_BLOCK_NAMES = {
    0xA0000001: "EnvironmentVariableDataBlock",
    0xA0000002: "ConsoleDataBlock",
    0xA0000003: "TrackerDataBlock",
    0xA0000004: "ConsoleFEDataBlock",
    0xA0000005: "SpecialFolderDataBlock",
    0xA0000006: "DarwinDataBlock",
    0xA0000007: "IconEnvironmentDataBlock",
    0xA0000008: "ShimDataBlock",
    0xA0000009: "PropertyStoreDataBlock",
    0xA000000B: "KnownFolderDataBlock",
    0xA000000C: "VistaAndAboveIDListDataBlock",
}

#: MAC OUIs that mean the shortcut was built inside a virtual machine.
VM_OUIS = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "00:1c:14": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:15:5d": "Hyper-V",
}

# Loop bounds. Real shortcuts sit orders of magnitude below all of these;
# they exist purely so a crafted file cannot spin.
MAX_ITEMIDS = 1024
MAX_EXTRA_BLOCKS = 64

_FILETIME_EPOCH_DELTA = 116_444_736_000_000_000  # 1601-01-01 -> 1970-01-01, in 100ns


# ---------------------------------------------------------------------------
# Bounds-checked accessors
#
# struct.unpack on a short buffer is the single most common exception to
# escape a LNK parser. These return None instead.
# ---------------------------------------------------------------------------

def _u8(data: bytes, off: int) -> int | None:
    if off < 0 or off + 1 > len(data):
        return None
    return data[off]


def _u16(data: bytes, off: int) -> int | None:
    if off < 0 or off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], "little")


def _u32(data: bytes, off: int) -> int | None:
    if off < 0 or off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], "little")


def _i32(data: bytes, off: int) -> int | None:
    if off < 0 or off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], "little", signed=True)


def _u64(data: bytes, off: int) -> int | None:
    if off < 0 or off + 8 > len(data):
        return None
    return int.from_bytes(data[off:off + 8], "little")


def _raw(data: bytes, off: int, length: int) -> bytes:
    """Slice with explicit bounds — Python would silently truncate."""
    if off < 0 or length < 0 or off + length > len(data):
        return b""
    return data[off:off + length]


def iter_sized_records(
    data: bytes,
    start: int,
    end: int,
    *,
    size_width: int,
    min_size: int,
    max_records: int,
) -> Iterator[tuple[int, int]]:
    """Walk records whose first field is their own total size.

    Yields ``(offset, size)`` per record. Used for ItemIDs, ExtraData
    blocks, shell-item extension blocks and property-store storages — four
    places with the same infinite-loop trap, so the guard lives here once.

    Stops on: a size below ``min_size`` (0 and 1 are the deliberate
    malware values), a record overrunning ``end``, or ``max_records``.
    """
    offset = start
    count = 0
    end = min(end, len(data))
    read = _u16 if size_width == 2 else _u32

    while offset < end and count < max_records:
        size = read(data, offset)
        if size is None or size < min_size or offset + size > end:
            return
        yield offset, size
        offset += size          # size >= min_size >= 1 keeps this monotonic
        count += 1


# ---------------------------------------------------------------------------
# Decoding helpers
# ---------------------------------------------------------------------------

def decode_string(raw: bytes, *, unicode: bool, codepage: str = "cp1252") -> str:
    """Decode StringData bytes, never raising.

    ``errors="replace"`` throughout: ``UnicodeDecodeError`` is the second
    most common exception to escape a LNK parser, and a mangled character
    is far more useful to an analyst than a dead parse.
    """
    if not raw:
        return ""
    if unicode:
        if len(raw) & 1:            # odd-length UTF-16 slice
            raw = raw[:-1]
        return raw.decode("utf-16-le", errors="replace")
    try:
        return raw.decode(codepage, errors="replace")
    except LookupError:             # config named a codec that does not exist
        return raw.decode("cp1252", errors="replace")


def read_nul_terminated(
    data: bytes, off: int, *, unicode: bool = False, codepage: str = "cp1252",
) -> str:
    """LinkInfo strings are NUL-terminated, unlike StringData."""
    if off < 0 or off >= len(data):
        return ""
    if unicode:
        end = off
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return decode_string(data[off:end], unicode=True)
    end = data.find(b"\x00", off)
    if end == -1:
        end = len(data)
    return decode_string(data[off:end], unicode=False, codepage=codepage)


def filetime_to_iso(raw: int | None) -> str | None:
    """FILETIME (100ns since 1601-01-01 UTC) to ISO 8601, or None.

    Zero is spec-legal and means "not set". Garbage raises
    OverflowError/OSError/ValueError depending on platform and value, so
    every path is caught — callers keep the raw integer regardless.
    """
    if not raw:
        return None
    try:
        seconds = (raw - _FILETIME_EPOCH_DELTA) / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def format_guid(raw: bytes) -> str | None:
    """GUID packet representation to the canonical string form."""
    if len(raw) != 16:
        return None
    d1 = int.from_bytes(raw[0:4], "little")
    d2 = int.from_bytes(raw[4:6], "little")
    d3 = int.from_bytes(raw[6:8], "little")
    return (
        f"{d1:08x}-{d2:04x}-{d3:04x}-"
        f"{raw[8]:02x}{raw[9]:02x}-{raw[10:16].hex()}"
    )


def mac_from_guid(raw: bytes) -> str | None:
    """Extract the NIC MAC from a version-1 (time-based) UUID.

    A v1 UUID's node ID is its last six bytes, and Windows populates it
    from the creating machine's NIC. Version lives in the high nibble of
    Data3, which is little-endian in the packet representation.
    """
    if len(raw) != 16:
        return None
    d3 = int.from_bytes(raw[6:8], "little")
    if (d3 >> 12) & 0xF != 1:       # not a v1 UUID — the node ID is meaningless
        return None
    node = raw[10:16]
    if node == b"\x00" * 6:
        return None
    return ":".join(f"{b:02x}" for b in node)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. bartblaze flags LNK files at >= 6.5."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    total = -sum(
        (c / length) * math.log2(c / length) for c in counts if c
    )
    # A single-valued buffer yields -0.0, which renders as "-0.0" in the
    # report and reads like a parse failure. PureCrypter pads with 47 KiB
    # of nulls, so this is not hypothetical.
    return total + 0.0 if total else 0.0


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ShellLinkHeader:
    link_flags: int = 0
    flag_names: list[str] = field(default_factory=list)
    file_attributes: int = 0
    attribute_names: list[str] = field(default_factory=list)
    creation_time_raw: int = 0
    access_time_raw: int = 0
    write_time_raw: int = 0
    creation_time: str | None = None
    access_time: str | None = None
    write_time: str | None = None
    target_file_size: int = 0
    icon_index: int = 0
    show_command: int = 0
    show_command_name: str = "SW_SHOWNORMAL"
    hotkey: int = 0

    def has(self, flag_name: str) -> bool:
        return flag_name in self.flag_names


@dataclass
class LinkInfoData:
    local_base_path: str = ""
    common_path_suffix: str = ""
    net_name: str = ""
    device_name: str = ""
    drive_type: int | None = None
    drive_serial: str | None = None
    volume_label: str = ""

    @property
    def full_path(self) -> str:
        return f"{self.local_base_path}{self.common_path_suffix}"


@dataclass
class ParsedLnk:
    """Everything recovered from one shortcut. Partial results are normal."""

    valid_magic: bool = False
    file_size: int = 0
    entropy: float = 0.0
    header: ShellLinkHeader = field(default_factory=ShellLinkHeader)
    shell_items: list[ShellItem] = field(default_factory=list)
    idlist_target: str = ""
    link_info: LinkInfoData | None = None
    name_string: str = ""
    relative_path: str = ""
    working_dir: str = ""
    arguments: str = ""
    icon_location: str = ""
    extra_blocks: list[str] = field(default_factory=list)
    machine_id: str = ""
    mac_address: str | None = None
    mac_vendor: str | None = None
    droid_volume_guid: str | None = None
    droid_file_guid: str | None = None
    droid_birth_differs: bool = False
    env_target: str = ""
    icon_env_target: str = ""
    darwin_id: str = ""
    shim_layer: str = ""
    known_folder_id: str | None = None
    special_folder_id: int | None = None
    property_store: list[dict] = field(default_factory=list)
    parsed_end: int = 0
    overlay_offset: int | None = None
    overlay_size: int = 0
    anomalies: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# File-type gate
# ---------------------------------------------------------------------------

def is_lnk_file(file_path: Path) -> bool:
    """True if this is a shell link, by magic bytes with extension fallback."""
    try:
        with file_path.open("rb") as fh:
            head = fh.read(20)
    except OSError:
        return file_path.suffix.lower() in _LNK_EXTENSIONS

    if head[:8] == LNK_MAGIC:
        return True
    return file_path.suffix.lower() in _LNK_EXTENSIONS


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_bytes(data: bytes, *, codepage: str = "cp1252") -> ParsedLnk:
    """Parse a shell link from memory.

    This is the public seam: ``__init__`` calls it with file bytes, and a
    future container handoff (LNK inside a RAR or a OneNote blob) can call
    it with a payload slice without touching the filesystem.

    Each section is independent — a failure in one appends an anomaly and
    leaves the rest intact, because malformed-by-design is the norm here
    and partial recovery is the whole point.
    """
    out = ParsedLnk(file_size=len(data), entropy=shannon_entropy(data))

    if len(data) < HEADER_SIZE:
        out.anomalies.append(f"File shorter than the 76-byte header ({len(data)} bytes)")
        return out

    out.valid_magic = data[:4] == HEADER_SIZE.to_bytes(4, "little") and \
        data[4:20] == LINK_CLSID
    if not out.valid_magic:
        if data[:4] != HEADER_SIZE.to_bytes(4, "little"):
            out.anomalies.append("HeaderSize is not 0x4C — spec violation")
        if data[4:20] != LINK_CLSID:
            out.anomalies.append("LinkCLSID does not match 00021401-0000-0000-C000-000000000046")

    offset = HEADER_SIZE

    try:
        _parse_header(data, out)
    except Exception as exc:  # noqa: BLE001
        logger.debug("LNK header parse failed: %s", exc)
        out.anomalies.append(f"Header parse failed: {exc}")

    unicode_strings = out.header.has("IsUnicode")

    if out.header.has("HasLinkTargetIDList"):
        try:
            offset = _parse_idlist(data, offset, out, codepage)
        except Exception as exc:  # noqa: BLE001
            logger.debug("LNK IDList parse failed: %s", exc)
            out.anomalies.append(f"LinkTargetIDList parse failed: {exc}")
            return _finalise(data, out, offset)

    if out.header.has("HasLinkInfo"):
        try:
            offset = _parse_link_info(data, offset, out, codepage)
        except Exception as exc:  # noqa: BLE001
            logger.debug("LNK LinkInfo parse failed: %s", exc)
            out.anomalies.append(f"LinkInfo parse failed: {exc}")
            return _finalise(data, out, offset)

    try:
        offset = _parse_string_data(data, offset, out, unicode_strings, codepage)
    except Exception as exc:  # noqa: BLE001
        logger.debug("LNK StringData parse failed: %s", exc)
        out.anomalies.append(f"StringData parse failed: {exc}")
        return _finalise(data, out, offset)

    try:
        offset = _parse_extra_data(data, offset, out, codepage)
    except Exception as exc:  # noqa: BLE001
        logger.debug("LNK ExtraData parse failed: %s", exc)
        out.anomalies.append(f"ExtraData parse failed: {exc}")

    return _finalise(data, out, offset)


def _finalise(data: bytes, out: ParsedLnk, offset: int) -> ParsedLnk:
    """Record where parsing stopped and carve anything after it."""
    out.parsed_end = min(offset, len(data))
    trailing = len(data) - out.parsed_end
    if trailing > 0:
        out.overlay_offset = out.parsed_end
        out.overlay_size = trailing
    _check_flag_consistency(out)
    return out


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _parse_header(data: bytes, out: ParsedLnk) -> None:
    hdr = out.header
    hdr.link_flags = _u32(data, 0x14) or 0
    hdr.flag_names = [name for mask, name in LINK_FLAGS if hdr.link_flags & mask]
    if hdr.link_flags & _RESERVED_FLAG_MASK:
        out.anomalies.append("LinkFlags bits 27-31 set — MUST be zero per spec")
    for unused in ("Unused1", "Unused2"):
        if unused in hdr.flag_names:
            out.anomalies.append(f"LinkFlags.{unused} set — MUST be ignored per spec")

    hdr.file_attributes = _u32(data, 0x18) or 0
    hdr.attribute_names = [
        name for mask, name in FILE_ATTRIBUTES if hdr.file_attributes & mask
    ]
    if hdr.file_attributes & _RESERVED_ATTR_MASK:
        out.anomalies.append("FileAttributes reserved bits set — MUST be zero per spec")
    if "NORMAL" in hdr.attribute_names and len(hdr.attribute_names) > 1:
        out.anomalies.append("FileAttributes NORMAL set alongside other bits")

    hdr.creation_time_raw = _u64(data, 0x1C) or 0
    hdr.access_time_raw = _u64(data, 0x24) or 0
    hdr.write_time_raw = _u64(data, 0x2C) or 0
    hdr.creation_time = filetime_to_iso(hdr.creation_time_raw)
    hdr.access_time = filetime_to_iso(hdr.access_time_raw)
    hdr.write_time = filetime_to_iso(hdr.write_time_raw)

    hdr.target_file_size = _u32(data, 0x34) or 0
    hdr.icon_index = _i32(data, 0x38) or 0      # signed — negative is a resource ID
    hdr.show_command = _u32(data, 0x3C) or 0
    hdr.show_command_name = SHOW_COMMANDS.get(hdr.show_command, "SW_SHOWNORMAL")
    hdr.hotkey = _u16(data, 0x40) or 0

    # Reserved1/2/3 MUST be zero. Builders that hand-assemble a header
    # routinely leave garbage here.
    if (_u16(data, 0x42) or 0) or (_u32(data, 0x44) or 0) or (_u32(data, 0x48) or 0):
        out.anomalies.append("Header Reserved1/2/3 non-zero — MUST be zero per spec")


def _parse_idlist(data: bytes, offset: int, out: ParsedLnk, codepage: str) -> int:
    """LinkTargetIDList: a size, then ItemIDs, then a 0x0000 terminator."""
    idlist_size = _u16(data, offset)
    if idlist_size is None:
        out.anomalies.append("LinkTargetIDList truncated at its size field")
        return offset + 2

    list_start = offset + 2
    declared_end = list_start + idlist_size
    if declared_end > len(data):
        out.anomalies.append("IDListSize overruns the file — clamped")
        declared_end = len(data)

    for item_off, item_size in iter_sized_records(
        data, list_start, declared_end,
        size_width=2, min_size=3, max_records=MAX_ITEMIDS,
    ):
        # min_size=3 rejects both the 0x0000 terminator and the
        # ItemIDSize<2 infinite-loop trap in one condition.
        payload = _raw(data, item_off + 2, item_size - 2)
        if not payload:
            continue
        item = decode_shell_item(payload, codepage=codepage)
        out.shell_items.append(item)

    out.idlist_target = _join_shell_path(out.shell_items)

    # Advance past the declared list regardless of how far the walk got —
    # trusting the cursor would let a truncated ItemID desynchronise
    # everything downstream.
    return list_start + idlist_size


def _join_shell_path(items: list[ShellItem]) -> str:
    """Rebuild a filesystem path from decoded shell items.

    Leading root-folder items are dropped when a real path follows: every
    shortcut to a local file begins with the "This PC" GUID, and carrying
    ``{20d04fe0-...}\\`` into the target string would be noise that also
    breaks basename and directory checks downstream. The GUID is still
    kept on the ShellItem itself for forensics.

    A root folder with nothing after it is kept — for a shortcut to a
    namespace extension, the GUID *is* the target.
    """
    names = [item.name for item in items if item.name]
    if not names:
        return ""

    while len(names) > 1 and names[0].startswith("{") and names[0].endswith("}"):
        names.pop(0)

    path = ""
    for part in names:
        if not path:
            path = part
        elif path.endswith("\\"):
            path += part
        else:
            path += "\\" + part
    return path


def _parse_link_info(data: bytes, offset: int, out: ParsedLnk, codepage: str) -> int:
    """LinkInfo. Every offset inside is relative to the structure start."""
    size = _u32(data, offset)
    if size is None or size < 0x1C:
        out.anomalies.append("LinkInfo truncated or smaller than its own header")
        return offset + (size or 4)

    end = offset + size
    if end > len(data):
        out.anomalies.append("LinkInfoSize overruns the file")
        end = len(data)

    header_size = _u32(data, offset + 4) or 0
    flags = _u32(data, offset + 8) or 0
    info = LinkInfoData()

    def rel(field_off: int) -> int | None:
        """Resolve a LinkInfo-relative offset, rejecting out-of-range values.

        Python slicing does not raise on nonsense offsets — it hands back
        the wrong bytes, which is worse than a crash. Validate first.
        """
        value = _u32(data, field_off)
        if value is None or value == 0 or value >= size:
            return None
        return offset + value

    volume_off = rel(offset + 12)
    local_path_off = rel(offset + 16)
    net_rel_off = rel(offset + 20)
    suffix_off = rel(offset + 24)

    # Unicode offsets only exist when the header is >= 0x24 bytes.
    local_path_uni_off = rel(offset + 28) if header_size >= 0x24 else None
    suffix_uni_off = rel(offset + 32) if header_size >= 0x24 else None
    if header_size not in (0x1C,) and header_size < 0x24:
        out.anomalies.append(f"LinkInfoHeaderSize is 0x{header_size:X} — neither 0x1C nor >= 0x24")

    if flags & 0x00000001:
        if local_path_uni_off is not None:
            info.local_base_path = read_nul_terminated(data, local_path_uni_off, unicode=True)
        elif local_path_off is not None:
            info.local_base_path = read_nul_terminated(data, local_path_off, codepage=codepage)

        if volume_off is not None:
            info.drive_type = _u32(data, volume_off + 4)
            serial = _u32(data, volume_off + 8)
            info.drive_serial = f"{serial:08X}" if serial else None
            label_off = _u32(data, volume_off + 12)
            if label_off is not None and 0 < label_off < (_u32(data, volume_off) or 0):
                info.volume_label = read_nul_terminated(
                    data, volume_off + label_off, codepage=codepage
                )

    if flags & 0x00000002 and net_rel_off is not None:
        net_size = _u32(data, net_rel_off) or 0
        net_name_off = _u32(data, net_rel_off + 8)
        device_off = _u32(data, net_rel_off + 12)
        if net_name_off and net_name_off < net_size:
            info.net_name = read_nul_terminated(
                data, net_rel_off + net_name_off, codepage=codepage
            )
        if device_off and device_off < net_size:
            info.device_name = read_nul_terminated(
                data, net_rel_off + device_off, codepage=codepage
            )

    if suffix_uni_off is not None:
        info.common_path_suffix = read_nul_terminated(data, suffix_uni_off, unicode=True)
    elif suffix_off is not None:
        info.common_path_suffix = read_nul_terminated(data, suffix_off, codepage=codepage)

    out.link_info = info
    return offset + size


def _parse_string_data(
    data: bytes, offset: int, out: ParsedLnk, unicode: bool, codepage: str,
) -> int:
    """The five optional strings, in spec order, each gated by its flag.

    CountCharacters counts *characters*, not bytes, and the strings are
    not NUL-terminated. The spec caps every structure at 260 characters
    **except** COMMAND_LINE_ARGUMENTS, which it explicitly exempts — that
    carve-out is what ZDI-CAN-25373 abuses, so nothing here validates
    against 260 or the widely-repeated-but-unsourced 4096. The real
    ceiling is the uint16 itself.
    """
    width = 2 if unicode else 1
    order = (
        ("HasName", "name_string"),
        ("HasRelativePath", "relative_path"),
        ("HasWorkingDir", "working_dir"),
        ("HasArguments", "arguments"),
        ("HasIconLocation", "icon_location"),
    )

    for flag_name, attr in order:
        if not out.header.has(flag_name):
            continue
        count = _u16(data, offset)
        if count is None:
            out.anomalies.append(f"StringData truncated before {flag_name}")
            return offset
        offset += 2
        byte_len = count * width
        if offset + byte_len > len(data):
            out.anomalies.append(
                f"{flag_name} claims {count} characters but the file ends first"
            )
            byte_len = max(0, len(data) - offset)
        setattr(
            out, attr,
            decode_string(data[offset:offset + byte_len], unicode=unicode, codepage=codepage),
        )
        offset += byte_len

    return offset


def _parse_extra_data(data: bytes, offset: int, out: ParsedLnk, codepage: str) -> int:
    """ExtraData blocks until a terminal uint32 < 4.

    The terminal block is *any* value below 4, not four zero bytes. A
    parser that insists on zero walks straight into appended payload and
    parses it as blocks — which is exactly the overlay we want to isolate.
    """
    cursor = offset
    count = 0
    while cursor + 4 <= len(data) and count < MAX_EXTRA_BLOCKS:
        block_size = _u32(data, cursor)
        if block_size is None or block_size < 4:
            return cursor + 4               # terminal block consumed
        if block_size < 8 or cursor + block_size > len(data):
            out.anomalies.append(
                f"ExtraData block at 0x{cursor:X} has an invalid size ({block_size})"
            )
            return cursor
        signature = _u32(data, cursor + 4) or 0

        # Real builders emit stray bytes between StringData and ExtraData.
        # MustangPanda samples carry six, which desynchronises the walk and
        # throws away the TrackerDataBlock and PropertyStore behind it —
        # LnkParse3 loses them too, reporting a single UNKNOWN_BLOCK. A
        # bounded forward scan for a recognised signature recovers them.
        if signature not in EXTRA_BLOCK_NAMES:
            resynced = _resync_extra_data(data, cursor)
            if resynced is not None:
                out.anomalies.append(
                    f"{resynced - cursor} stray byte(s) before ExtraData at "
                    f"0x{cursor:X} — resynchronised"
                )
                cursor = resynced
                block_size = _u32(data, cursor) or 0
                signature = _u32(data, cursor + 4) or 0
                if block_size < 8 or cursor + block_size > len(data):
                    return cursor

        name = EXTRA_BLOCK_NAMES.get(signature, f"Unknown(0x{signature:08X})")
        out.extra_blocks.append(name)
        block = data[cursor:cursor + block_size]
        try:
            _decode_extra_block(signature, block, out, codepage)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ExtraData block %s decode failed: %s", name, exc)
            out.anomalies.append(f"{name} decode failed: {exc}")
        cursor += block_size
        count += 1

    if count >= MAX_EXTRA_BLOCKS:
        out.anomalies.append(f"ExtraData block cap ({MAX_EXTRA_BLOCKS}) reached")
    return cursor


#: How far past a bad ExtraData header to look for a real one. Generous
#: enough for observed builder padding, small enough that it can never
#: wander into an appended payload and invent structure there.
_RESYNC_WINDOW = 64


def _resync_extra_data(data: bytes, cursor: int) -> int | None:
    """Find the next well-formed ExtraData header within a small window.

    Requires *both* a recognised block signature and a self-consistent
    size, so a coincidental four-byte match inside an overlay cannot pull
    the walk off course. Returns the new offset, or ``None`` to leave the
    caller's behaviour unchanged.
    """
    limit = min(cursor + _RESYNC_WINDOW, len(data) - 8)
    for pos in range(cursor + 1, limit + 1):
        signature = _u32(data, pos + 4)
        if signature not in EXTRA_BLOCK_NAMES:
            continue
        size = _u32(data, pos)
        if size is not None and 8 <= size <= len(data) - pos:
            return pos
    return None


def _decode_extra_block(signature: int, block: bytes, out: ParsedLnk, codepage: str) -> None:
    """Pull the fields that carry analytic weight out of a known block."""
    if signature == 0xA0000001:                     # EnvironmentVariableDataBlock
        out.env_target = _fixed_env_string(block, codepage)

    elif signature == 0xA0000007:                   # IconEnvironmentDataBlock
        out.icon_env_target = _fixed_env_string(block, codepage)

    elif signature == 0xA0000006:                   # DarwinDataBlock
        out.darwin_id = _fixed_env_string(block, codepage)

    elif signature == 0xA0000003:                   # TrackerDataBlock
        _decode_tracker(block, out, codepage)

    elif signature == 0xA0000005:                   # SpecialFolderDataBlock
        out.special_folder_id = _u32(block, 8)

    elif signature == 0xA000000B:                   # KnownFolderDataBlock
        out.known_folder_id = format_guid(_raw(block, 8, 16))

    elif signature == 0xA0000008:                   # ShimDataBlock
        out.shim_layer = decode_string(block[8:], unicode=True).rstrip("\x00")

    elif signature == 0xA0000009:                   # PropertyStoreDataBlock
        out.property_store = parse_property_store(block[8:], codepage=codepage)


def _fixed_env_string(block: bytes, codepage: str) -> str:
    """The 260-byte ANSI + 520-byte Unicode pair these blocks all share.

    Both fields are fixed-size regardless of content, which is why
    Quarkslab call them "720 bytes of free space" for hiding URLs and
    payloads — Explorer never renders them in full.
    """
    unicode_part = decode_string(_raw(block, 268, 520), unicode=True).split("\x00")[0]
    if unicode_part:
        return unicode_part
    return decode_string(
        _raw(block, 8, 260), unicode=False, codepage=codepage
    ).split("\x00")[0]


def _decode_tracker(block: bytes, out: ParsedLnk, codepage: str) -> None:
    """TrackerDataBlock — the attribution goldmine.

    Layout: BlockSize(4) Signature(4) Length(4) Version(4) MachineID(16)
    Droid(32) DroidBirth(32). MachineID is the NetBIOS name of the machine
    the shortcut was *built* on; the second GUID of each Droid pair is a
    version-1 UUID whose node ID is that machine's NIC MAC.
    """
    machine = _raw(block, 16, 16)
    out.machine_id = decode_string(
        machine, unicode=False, codepage=codepage
    ).split("\x00")[0].strip()

    droid_volume = _raw(block, 32, 16)
    droid_file = _raw(block, 48, 16)
    birth_volume = _raw(block, 64, 16)
    birth_file = _raw(block, 80, 16)

    out.droid_volume_guid = format_guid(droid_volume)
    out.droid_file_guid = format_guid(droid_file)

    mac = mac_from_guid(droid_file) or mac_from_guid(birth_file)
    if mac:
        out.mac_address = mac
        out.mac_vendor = VM_OUIS.get(mac[:8])

    # Differing droid/birth pairs mean the target was moved or copied
    # after creation — a behavioural detail worth surfacing.
    if birth_file and droid_file and birth_file != droid_file:
        out.droid_birth_differs = True
    elif birth_volume and droid_volume and birth_volume != droid_volume:
        out.droid_birth_differs = True


def _check_flag_consistency(out: ParsedLnk) -> None:
    """Flags promising a block that is not there, and vice versa.

    Explorer keeps these in sync; hand-rolled builders frequently do not.
    """
    pairs = (
        ("HasExpString", "EnvironmentVariableDataBlock"),
        ("HasExpIcon", "IconEnvironmentDataBlock"),
        ("HasDarwinID", "DarwinDataBlock"),
        ("RunWithShimLayer", "ShimDataBlock"),
    )
    for flag_name, block_name in pairs:
        has_flag = out.header.has(flag_name)
        has_block = block_name in out.extra_blocks
        if has_flag != has_block:
            state = "set without" if has_flag else "clear despite"
            out.anomalies.append(
                f"LinkFlags.{flag_name} {state} a {block_name}"
            )

    if out.header.has("ForceNoLinkInfo") and out.link_info is not None:
        out.anomalies.append("ForceNoLinkInfo set while LinkInfo is present")
