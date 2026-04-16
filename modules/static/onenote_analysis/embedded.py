"""Classify and hash each raw ``FileDataStoreObject`` payload.

OneNote stores blobs without filenames, so the payload is typed in two
steps:

1. **libmagic MIME** — catches native executables (PE/ELF/Mach-O), MSI,
   CHM, and common image/document containers.
2. **Content heuristics** — scripts (.bat/.ps1/.vbs/.js/.wsf), HTA, and
   LNK cannot be reliably identified by MIME alone, so we sniff the
   leading bytes for format-specific markers.

The ``EmbeddedBlob`` dataclass is JSON-serialisable via ``asdict`` and
is what the reporter surfaces to the user.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ── Magic-byte signatures ──

_LNK_SIGNATURE: bytes = bytes.fromhex(
    "4C00000001140200000000000000000000000046"
)  # Windows LNK header (HeaderSize + CLSID Shell.Link)
_CHM_MAGIC: bytes = b"ITSF"
_PE_MAGIC: bytes = b"MZ"
_ELF_MAGIC: bytes = b"\x7fELF"
_MACHO_MAGICS: tuple[bytes, ...] = (
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
)
_OLE_CFB_MAGIC: bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# ── Dangerous kinds (for indicators + VT forward-lookup) ──

DANGEROUS_KINDS: frozenset[str] = frozenset({
    "pe", "msi", "lnk", "hta", "script", "chm", "elf", "macho",
})

# Map kind → VT type label (only kinds VT indexes well).
_VT_FORWARD_TYPES: dict[str, str] = {
    "pe": "PE",
    "elf": "ELF",
    "macho": "MachO",
    "msi": "MSI",
}


@dataclass
class EmbeddedBlob:
    offset: int
    size: int
    md5: str
    sha256: str
    mime: str
    kind: str   # see DANGEROUS_KINDS + {"image", "ole", "other"}
    label: str  # human-readable (e.g. "PE32+ x86-64")


def classify_blob(offset: int, payload: bytes) -> EmbeddedBlob:
    """Type + hash a single FDSO payload."""
    md5 = hashlib.md5(payload).hexdigest()
    sha256 = hashlib.sha256(payload).hexdigest()

    mime = _sniff_mime(payload)
    kind, label = _categorise(payload, mime)

    return EmbeddedBlob(
        offset=offset,
        size=len(payload),
        md5=md5,
        sha256=sha256,
        mime=mime or "application/octet-stream",
        kind=kind,
        label=label,
    )


def to_vt_forward_entry(blob: EmbeddedBlob) -> dict | None:
    """Return the VT forward-lookup entry for blobs VT indexes, else None.

    Matches the ``embedded_executables`` shape produced by
    ``archive_analysis`` — the VT module reads it verbatim.
    """
    vt_type = _VT_FORWARD_TYPES.get(blob.kind)
    if vt_type is None:
        return None
    return {
        "name": f"onenote_blob_0x{blob.offset:08x}",
        "md5": blob.md5,
        "sha256": blob.sha256,
        "size": blob.size,
        "type": vt_type if blob.kind != "pe" else blob.label or "PE",
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _sniff_mime(payload: bytes) -> str | None:
    try:
        import magic  # noqa: PLC0415
    except ImportError:
        logger.debug("python-magic not available — MIME sniffing skipped")
        return None
    try:
        return magic.from_buffer(payload[: 8 * 1024], mime=True)
    except Exception as exc:  # noqa: BLE001
        logger.debug("magic.from_buffer failed: %s", exc)
        return None


def _categorise(payload: bytes, mime: str | None) -> tuple[str, str]:
    """Return (kind, human_label) for an FDSO payload."""
    if not payload:
        return "other", "empty"

    if payload.startswith(_PE_MAGIC):
        return "pe", _pe_label(payload)

    if payload.startswith(_ELF_MAGIC):
        return "elf", "ELF"

    if payload[:4] in _MACHO_MAGICS:
        return "macho", "Mach-O"

    if payload.startswith(_OLE_CFB_MAGIC) and _looks_like_msi(payload):
        return "msi", "MSI"

    if payload.startswith(_LNK_SIGNATURE[:4]) and _looks_like_lnk(payload):
        return "lnk", "Windows shortcut"

    if payload.startswith(_CHM_MAGIC):
        return "chm", "CHM"

    if _looks_like_hta(payload):
        return "hta", "HTA application"

    script_label = _sniff_script(payload)
    if script_label is not None:
        return "script", script_label

    if mime:
        if mime.startswith("image/"):
            return "image", mime
        if mime == "application/vnd.ms-office" or "ole" in mime.lower():
            return "ole", mime
        return "other", mime

    return "other", "unknown"


def _pe_label(payload: bytes) -> str:
    """Refine a PE header into PE32 / PE32+ by reading the optional header."""
    if len(payload) < 0x40:
        return "PE"
    try:
        e_lfanew = int.from_bytes(payload[0x3c:0x40], "little")
    except ValueError:
        return "PE"
    opt_off = e_lfanew + 0x18
    if len(payload) < opt_off + 2 or payload[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return "PE"
    opt_magic = int.from_bytes(payload[opt_off:opt_off + 2], "little")
    if opt_magic == 0x10b:
        return "PE32"
    if opt_magic == 0x20b:
        return "PE32+"
    return "PE"


def _looks_like_msi(payload: bytes) -> bool:
    """MSI is an OLE CFB storage with MSI-specific streams and properties.

    Rather than parse CFB, we cheat: MSI-only markers (``MSI``,
    ``SummaryInformation``, ``Product_Code``) appear inside every real
    MSI within the first ~64 KiB. A bare OLE CFB file without those
    markers is a generic compound document (e.g. legacy .doc, .xls).
    64 KiB is wide enough to cover OLE sector fragmentation while still
    bounding work on large payloads.
    """
    sample = payload[: 64 * 1024]
    sample_lc = sample.lower()
    has_summary = b"summaryinformation" in sample_lc
    has_msi_marker = (
        b"installer" in sample_lc
        or b"msi " in sample_lc
        or b"product_code" in sample_lc
        or b".msi" in sample_lc
    )
    return has_summary and has_msi_marker


def _looks_like_lnk(payload: bytes) -> bool:
    if len(payload) < 20:
        return False
    return payload[:20] == _LNK_SIGNATURE


def _looks_like_hta(payload: bytes) -> bool:
    """HTA detection for OneNote-carrier droppers.

    Includes the explicit ``<hta:application>`` tag (ideal case) and the
    common IcedID/Qakbot pattern: an ``<html>`` page with either a
    VBScript block, a WScript/Shell object, or an ActiveXObject call.
    OneNote launches embedded HTML with ``mshta.exe``, so an HTML
    payload with any of those signals is functionally an HTA regardless
    of whether the literal ``<hta:application>`` tag is present.
    """
    sample = payload[: 8 * 1024].lower()
    if b"<hta:application" in sample:
        return True
    if b"<html" not in sample:
        return False
    return any(marker in sample for marker in (
        b"activexobject",
        b'<script language="vbscript"',
        b"<script language='vbscript'",
        b"wscript.shell",
        b"wscript.createobject",
        b"createobject(",
    ))


def _sniff_script(payload: bytes) -> str | None:
    """Detect embedded .bat/.ps1/.vbs/.js/.wsf by textual content."""
    try:
        text = payload[: 8 * 1024].decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return None
    lower = text.lower()

    if text.startswith("@echo") or " cmd /c " in lower or " cmd.exe /" in lower:
        return "batch script"
    if "powershell" in lower and (
        "invoke-" in lower or "-encodedcommand" in lower or "iex " in lower
    ):
        return "PowerShell script"
    if "createobject(" in lower and (
        "wscript.shell" in lower or "shell.application" in lower
    ):
        return "VBS / JScript"
    if "<job" in lower or "<script language=" in lower:
        return "WSF script"
    return None
