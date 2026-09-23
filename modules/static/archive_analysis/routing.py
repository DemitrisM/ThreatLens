"""Archive format detection + applicability gating.

Detects archive type by magic bytes (with extension fallback), and
filters out ZIPs that are actually Office OOXML containers —
``doc_analysis`` owns those.

PE inputs are accepted by :func:`is_archive_target` because
``archive_analysis`` also runs the SFX overlay scan on `.exe` / `.dll`
files.

Design notes
------------
This module answers two different questions and the difference matters.
:func:`detect_format` says *what a file is* and may answer ``"pe"``;
:func:`is_archive_target` says *whether this module should run* and
deliberately answers ``False`` for a PE, because the orchestrator routes
PEs down the SFX path instead of the archive path. Conflating them would
send every executable in a triage run through archive enumeration.

Detection is magic-first, extension-second, and never extension-only for
a format that has a usable magic. An extension is attacker-controlled
and a malicious archive is routinely misnamed; the fallback exists for
the genuine ambiguities — a `.gz` is two bytes of magic that appear
inside unrelated files, and a tar's magic sits at offset 257 in a header
that a short or truncated file may not even contain.

The OOXML guard is a boundary, not an optimisation. An Office document
*is* a ZIP, so without it both this module and `doc_analysis` would
score the same file and the aggregate would double-count a single
document. `doc_analysis` owns them because it can read what is inside;
all this module could add is that the ZIP exists.
"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Magic bytes
# ---------------------------------------------------------------------------

# (format, offset, magic), tested in order — first match wins.
#
# Most entries test a fixed offset that no other entry claims, so they
# cannot compete. The ones that can are the entries at a non-zero
# offset: "ustar" at 257 and "CD001" at 32769 are ordinary byte strings
# that may occur by coincidence inside a file whose real magic is at 0.
# Keeping every offset-0 signature ahead of them means a real ZIP that
# happens to contain "ustar" 257 bytes in still types as a ZIP.
#
# The ISO entry is why :func:`detect_format` reads as far as it does.
# A volume descriptor sits at 0x8001 = 32769, so the read has to cover
# 32769 + 5 bytes; 32768 + 16 does, with nothing to spare but the
# arithmetic. Shortening that read silently stops ISO detection
# working — magic-byte tests fail closed, with no error.
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

    Args:
        file_path: The file to type. Read-only; nothing is extracted.

    Returns:
        A format key the orchestrator dispatches on (``"zip"``,
        ``"rar"``, ``"7z"``, ``"tar"``, ``"gz"``, ``"bz2"``, ``"xz"``,
        ``"cab"``, ``"iso"``, ``"ace"``, ``"pe"``), or ``None`` when
        neither magic nor extension identifies one.

    An unreadable file returns ``None`` rather than raising, per design
    rule 2 — a permission error on one file in a triage run must not
    take the pipeline down with it.
    """
    try:
        with file_path.open("rb") as fh:
            head = fh.read(32768 + 16)
    except OSError as exc:
        logger.warning("Could not read %s for format detection: %s", file_path, exc)
        return None

    # ---- Magic first --------------------------------------------------
    # The length guard is what makes a short file safe: a slice past the
    # end of `head` returns fewer bytes rather than raising, so without
    # it a 4-byte file could match a zero-length comparison.
    for fmt, offset, magic in _MAGIC_SIGNATURES:
        if offset + len(magic) <= len(head) and head[offset:offset + len(magic)] == magic:
            return fmt

    # ---- Extension fallback --------------------------------------------
    # Only reached when no magic matched, so this cannot override a
    # positive identification — it recovers the cases where the magic is
    # genuinely absent from the bytes read. A `.tgz` is checked both by
    # its own suffix and by the `.tar.gz` two-suffix spelling, since the
    # gzip magic that wraps it was already tried above and, had it
    # matched, would have typed the file as "gz" and lost the tar.
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
    """True if ``archive_analysis`` should run on this file.

    Args:
        file_path: The candidate input.

    Returns:
        ``True`` for anything the archive handlers can enumerate.
        ``False`` for a PE — deliberately, see below — and for anything
        unrecognised.

    The extension test comes first and short-circuits, so it is the one
    place an extension can win over the bytes. That is intended: it
    makes the module *more* willing to look, and a file that turns out
    not to be an archive is refused by the handler a moment later at no
    cost. Being wrong in this direction wastes a parse; being wrong in
    the other misses a payload.
    """
    if file_path.suffix.lower() in _ARCHIVE_EXTENSIONS:
        return True
    fmt = detect_format(file_path)
    # A PE is excluded here even though `detect_format` types it, because
    # "should archive_analysis run" and "is this an archive" are separate
    # questions for an executable. The orchestrator sends PEs to the SFX
    # overlay scan instead; answering True would enumerate every binary
    # in a triage run as though it were a container.
    return fmt is not None and fmt != "pe"


def is_pe(file_path: Path) -> bool:
    """Fast DOS-header check — avoids importing pefile up front.

    Args:
        file_path: The file to test.

    Returns:
        ``True`` if the file opens with ``MZ``.

    Two bytes, no parse. `pefile` is the authority on whether a PE is
    well formed, but importing and constructing it costs far more than
    this module needs to decide which path to take, and a malformed PE
    still has to reach the SFX scan — its overlay is the interesting
    part precisely when the structure is damaged.
    """
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
#
# NOTE: this tuple is currently unread — :func:`is_office_ooxml_zip`
# repeats the four package roots inline. Do not "fix" that by wiring
# this constant into the `startswith` test. It holds
# `[Content_Types].xml` as well as the roots, and that string is also
# what the function's first condition tests for, so a single
# `startswith` over this tuple would be satisfied by
# `[Content_Types].xml` alone. The two-condition check would then be
# one condition wearing a disguise, and any ZIP carrying a dummy
# `[Content_Types].xml` would route away from this module entirely.
# If the duplication is ever removed, split the roots into their own
# tuple first.
_OFFICE_OOXML_PARTS: tuple[str, ...] = (
    "word/", "xl/", "ppt/", "visio/",
    "[Content_Types].xml",
)


def is_office_ooxml_zip(file_path: Path) -> bool:
    """True if this ZIP is a legit OOXML Office container.

    Opens the ZIP read-only and peeks at member names. A real Office
    document contains ``[Content_Types].xml`` + one of the standard
    package roots.

    Args:
        file_path: A file already typed as ``"zip"``.

    Returns:
        ``True`` only when both markers are present.

    Both conditions are required, and that asymmetry is the point. A
    malicious ZIP can trivially add a ``[Content_Types].xml``, or a
    directory called ``word/``, to claim to be a document and duck this
    module entirely — demanding both, in a file that also parses as a
    ZIP, is a much harder decoy to build. The cost of being too strict
    is only that a real document gets archive-scanned as well.

    A malformed ZIP returns ``False``, so it stays with
    ``archive_analysis``. That is the safe direction: a broken ZIP is
    interesting to this module and useless to `doc_analysis`.
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
