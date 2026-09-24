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

#: HeaderSize 0x0000004C followed by the Shell.Link CLSID
#: 00021401-0000-0000-C000-000000000046 in packet byte order.
#:
#: The byte at offset 12 is 0xC0 and was 0x00 until this was checked
#: against a real shortcut. That single byte meant `_looks_like_lnk`
#: could never return True: every embedded LNK typed as "other", so
#: `contains_embedded_lnk` never fired, and with it the
#: {contains_embedded_lnk, contains_embedded_script} rule at weight 30 —
#: the rule the table calls the classic IcedID / Qakbot OneNote TTP, and
#: the reason this module exists.
_LNK_SIGNATURE: bytes = bytes.fromhex(
    "4C0000000114020000000000C000000000000046"
)
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

    # Two independent signals, because one was silently wrong for the
    # module's entire life. libmagic had been typing the corpus blob
    # correctly as application/x-ms-shortcut throughout, and the byte
    # comparison overruled it.
    if _looks_like_lnk(payload) or (mime or "") == "application/x-ms-shortcut":
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
    """True if the payload opens with the [MS-SHLLINK] header.

    Args:
        payload: A blob's bytes.

    Returns:
        Whether the first 20 bytes are the fixed HeaderSize and CLSID.

    Both fields are constant for every shell link ever written, so an
    exact comparison is the right test — there is nothing to tolerate.
    That also makes it unforgiving of a typo in the constant, which is
    exactly what went wrong: see :data:`_LNK_SIGNATURE`.
    """
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


#: PowerShell tokens that, alongside the interpreter's name, mean the
#: blob is a command rather than a mention of one. Written as prefixes
#: because PowerShell accepts any unambiguous abbreviation of a
#: parameter name — the corpus uses ``-enc``, ``-noP`` and ``-w 1``, none
#: of which match the full spellings.
_PS_TOKENS: tuple[str, ...] = (
    "-enc", "-e ", "-nop", "-noni", "-windowstyle",
    # -WindowStyle takes the enum name or its integer. `-w 1` is Hidden
    # and is what the corpus actually uses; `-w hidden` is the spelled
    # form. Listing only one of them would miss the other.
    "-w 1", "-w hidden",
    "-executionpolicy", "-ep bypass", "-sta", "-command ", "-file ",
    "invoke-", "iex ", "downloadstring", "downloadfile",
    "frombase64string", "[system.convert]::", "[convert]::",
    "webclient", "start-process",
)

#: COM objects a dropper instantiates. Specific, but a document *about*
#: malware can name them in prose, so they are never sufficient alone.
_VBS_OBJECTS: tuple[str, ...] = (
    "wscript.shell", "shell.application", "scripting.filesystemobject",
    "adodb.stream", "msxml2.xmlhttp", "winhttp.winhttprequest",
)

#: The constructs that turn naming an object into using one. One of
#: these plus one of the above is the two-signal rule; either alone is
#: prose.
_VBS_CONSTRUCTS: tuple[str, ...] = (
    "createobject(", "getobject(", "new activexobject",
    "execute(", "executeglobal(", ".run(", ".exec(",
)


def _sniff_script(payload: bytes) -> str | None:
    """Detect embedded .bat/.ps1/.vbs/.js/.wsf by textual content.

    Args:
        payload: A blob's bytes. Only the first 8 KiB are examined.

    Returns:
        A human-readable script label, or None.

    Every rule needs **two** signals — because this runs on every blob
    including images and decoy prose. Quakbot3 in the corpus carries
    blobs of generated junk words as camouflage, and those must stay
    untyped. Naming a COM object is not enough on its own: a document
    *about* malware mentions ``WScript.Shell`` in prose, so it has to be
    paired with a construct that instantiates or runs something.

    Three narrownesses were removed after reading what the corpus
    actually contains, each of which had cost a real sample:

    * ``@echo`` was anchored to offset 0, so the decoy banner line that
      IcedID and Gozi print before it defeated the check entirely.
    * ``-encodedcommand`` was matched in full, although PowerShell
      accepts any unambiguous prefix and every sample uses ``-enc``.
    * A PowerShell blob had to carry ``invoke-``, ``-encodedcommand`` or
      ``iex`` as well, which a plain download-and-run command line —
      the Downloader.one shape — does not.

    Order matters only in that batch is tested first: a batch file that
    launches PowerShell is a batch file, and reporting it as PowerShell
    would describe the payload rather than the dropper.
    """
    text = payload[: 8 * 1024].decode("utf-8", errors="ignore")
    lower = text.lower()

    # Batch. `@echo off` is the near-universal opener and survives a
    # decoy banner in front of it, which is why it is searched rather
    # than anchored.
    if "@echo off" in lower or " cmd /c " in lower or " cmd.exe /" in lower:
        return "batch script"

    if "powershell" in lower and any(tok in lower for tok in _PS_TOKENS):
        return "PowerShell script"

    if any(obj in lower for obj in _VBS_OBJECTS) and any(
        con in lower for con in _VBS_CONSTRUCTS
    ):
        return "VBS / JScript"

    # Obfuscated VBScript assembles its command from character
    # arithmetic. `Execute(` alone is too common; paired with `chr(` it
    # is the construct and nothing else.
    if "execute(" in lower and "chr(" in lower:
        return "VBS / JScript"

    if "<job" in lower or "<script language=" in lower:
        return "WSF script"
    return None
