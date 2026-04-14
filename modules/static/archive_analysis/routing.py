"""Archive format detection + applicability gating.

Detects archive type by magic bytes (with extension fallback), and
filters out ZIPs that are actually Office OOXML containers —
``doc_analysis`` owns those.

PE inputs are accepted by :func:`is_archive_target` because
``archive_analysis`` also runs the SFX overlay scan on `.exe` / `.dll`
files.
"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Magic bytes
# ---------------------------------------------------------------------------

# Maps format name → list of (offset, magic) pairs. First match wins.
_MAGIC_SIGNATURES: list[tuple[str, int, bytes]] = [
    ("zip",  0, b"PK\x03\x04"),
    ("zip",  0, b"PK\x05\x06"),       # empty archive
    ("zip",  0, b"PK\x07\x08"),       # spanned
    ("rar",  0, b"Rar!\x1a\x07\x00"),  # RAR4
    ("rar",  0, b"Rar!\x1a\x07\x01\x00"),  # RAR5
    ("7z",   0, b"7z\xbc\xaf\x27\x1c"),
    ("gz",   0, b"\x1f\x8b"),
    ("bz2",  0, b"BZh"),
    ("xz",   0, b"\xfd7zXZ\x00"),
    ("tar", 257, b"ustar"),            # POSIX tar magic
    ("cab",  0, b"MSCF"),
    ("iso", 32769, b"CD001"),          # ISO 9660 volume descriptor
    ("ace",  7, b"**ACE**"),
    ("pe",   0, b"MZ"),
]


# Extensions we treat as archive candidates even when magic is ambiguous
# (e.g. single-stream .gz whose bytes are just 1f8b).
_ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({
    ".zip", ".jar", ".apk", ".xap", ".war", ".ear",
    ".rar",
    ".7z",
    ".tar", ".tgz", ".tbz2", ".txz",
    ".gz", ".bz2", ".xz",
    ".cab",
    ".iso", ".img",
    ".ace",
})


def detect_format(file_path: Path) -> str | None:
    """Return the detected archive format or ``None``.

    Magic-byte detection first, extension fallback second. PE files are
    returned as ``"pe"`` so the orchestrator knows to run the SFX path.
    """
    try:
        with file_path.open("rb") as fh:
            head = fh.read(32768 + 16)
    except OSError as exc:
        logger.warning("Could not read %s for format detection: %s", file_path, exc)
        return None

    for fmt, offset, magic in _MAGIC_SIGNATURES:
        if offset + len(magic) <= len(head) and head[offset:offset + len(magic)] == magic:
            return fmt

    # Extension fallback for tarball wrappers that don't have stdlib magic
    # (tar header starts at offset 257 and may be short).
    ext = file_path.suffix.lower()
    suffixes = [s.lower() for s in file_path.suffixes]
    if ext in (".tgz", ".tbz2", ".txz") or suffixes[-2:] in (
        [".tar", ".gz"], [".tar", ".bz2"], [".tar", ".xz"]
    ):
        return "tar"
    if ext == ".gz":
        return "gz"
    if ext == ".bz2":
        return "bz2"
    if ext == ".xz":
        return "xz"
    if ext == ".zip":
        return "zip"
    return None


def is_archive_target(file_path: Path) -> bool:
    """True if ``archive_analysis`` should run on this file."""
    if file_path.suffix.lower() in _ARCHIVE_EXTENSIONS:
        return True
    fmt = detect_format(file_path)
    # PE handled separately as SFX candidate
    return fmt is not None and fmt != "pe"


def is_pe(file_path: Path) -> bool:
    """Fast DOS-header check — avoids importing pefile up front."""
    try:
        with file_path.open("rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


# ---------------------------------------------------------------------------
# OOXML guard — prevent double-counting with doc_analysis
# ---------------------------------------------------------------------------

# Office containers we should defer to doc_analysis on. .jar / .apk /
# .xap are ZIPs too but doc_analysis does not touch them.
_OFFICE_OOXML_PARTS: tuple[str, ...] = (
    "word/", "xl/", "ppt/", "visio/",
    "[Content_Types].xml",
)


def is_office_ooxml_zip(file_path: Path) -> bool:
    """True if this ZIP is a legit OOXML Office container.

    Opens the ZIP read-only and peeks at member names. A real Office
    document contains ``[Content_Types].xml`` + one of the standard
    package roots. Returns ``False`` on malformed ZIPs.
    """
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return False

    has_content_types = "[Content_Types].xml" in names
    has_office_root = any(
        n.startswith(("word/", "xl/", "ppt/", "visio/")) for n in names
    )
    return has_content_types and has_office_root
