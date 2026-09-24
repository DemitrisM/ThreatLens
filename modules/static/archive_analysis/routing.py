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


# The package roots, separate from _OFFICE_OOXML_PARTS above precisely
# because that tuple also holds `[Content_Types].xml` and must not be
# used for a prefix test.
_OFFICE_PACKAGE_ROOTS: tuple[str, ...] = ("word/", "xl/", "ppt/", "visio/")

# Every top-level component a genuine OOXML package may contain. A
# document is a closed structure: parts live under these and nowhere
# else. Measured across the sample corpus — of 57 real OOXML packages,
# exactly one carries anything outside this set, and that one is a
# malware sample with a `[trash]` component.
_OFFICE_ALLOWED_COMPONENTS: frozenset[str] = frozenset({
    "[content_types].xml",
    "_rels",
    "docprops",
    "docmetadata",
    "customxml",
    "customui",
    # Digitally signed packages carry their signature parts here. Absent
    # it a signed document is merely analysed twice rather than missed,
    # but the extra rows are noise worth avoiding.
    "_xmlsignatures",
    "word",
    "xl",
    "ppt",
    "visio",
})


# Part extensions seen across the 57 real OOXML packages in the sample
# corpus, plus the common image and media types Office can embed that the
# corpus happens not to contain. Anything outside this set stops the file
# being deferred, which costs an unusual-but-benign document a second
# analysis and costs an attacker the gap.
# Markup, metadata and images only. Nothing here can execute, and that
# is the selection rule rather than "what the corpus contained" — an
# unreferenced `word/payload.xls` would otherwise defer, be ignored by
# doc_analysis as unreferenced, and still run when a user unpacked the
# ZIP and opened it.
#
# Measured: 13 of the 57 real packages carry an embedded .rtf, .xls or
# .xlsx and therefore stop deferring. All 13 are malware samples using
# the embedded-object delivery shape, and doc_analysis still analyses
# them; they simply gain archive analysis as well.
_OFFICE_ALLOWED_PART_EXTENSIONS: frozenset[str] = frozenset({
    ".xml", ".rels", ".bin", ".vml", ".dat",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff",
    ".emf", ".wmf", ".webp",
})


def _top_level_component(member_name: str) -> str:
    """Return the first path component of a package member, folded.

    Args:
        member_name: A ZIP member name as stored.

    Returns:
        The lowercased first component, with separators normalised.

    Real documents store some parts with backslashes —
    ``word\\embeddings\\oleObject1.bin`` appears in the sample corpus —
    so splitting on forward slashes alone would read the whole string as
    one component and disqualify every document that embeds an object.
    """
    return member_name.replace("\\", "/").split("/")[0].lower()


def is_office_ooxml_zip(file_path: Path) -> bool:
    """True if this ZIP is a legit OOXML Office container.

    Opens the ZIP read-only and peeks at member names. A real Office
    document contains ``[Content_Types].xml`` + one of the standard
    package roots.

    Args:
        file_path: A file already typed as ``"zip"``.

    Returns:
        ``True`` only when both markers are present.

    Five conditions, and the direction they fail in is the design. This
    predicate decides only whether ``archive_analysis`` *adds* its own
    analysis; it does not route anything away from ``doc_analysis``,
    which is a separate pipeline entry applying its own test. So a
    false negative here means a document is analysed by both modules —
    extra rows — while a false positive means a ZIP is analysed by this
    one and possibly by neither. Every condition is therefore written to
    fail towards "analyse it".

    That asymmetry is what the conditions are for. Two name checks alone
    were a costume: adding ``[Content_Types].xml`` and a ``word/`` entry
    to any ZIP made this module defer while ``doc_analysis`` declined
    the file as not an Office document, so a payload beside them was
    examined by nothing at all.

    A malformed ZIP returns ``False``, so it stays with
    ``archive_analysis``. That is the safe direction: a broken ZIP is
    interesting to this module and useless to `doc_analysis`.
    """
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return False

    # Matched case-insensitively, and the matched spelling is kept: part
    # names are case-insensitive per ECMA-376, but zipfile's open() is
    # not, so opening a hardcoded spelling would raise KeyError on a
    # document that spells it differently.
    content_types_name = next(
        (n for n in names if n.lower() == "[content_types].xml"), None,
    )
    has_content_types = content_types_name is not None
    # Separators normalised first: real packages in the corpus store
    # some parts with backslashes, so a document whose only root
    # spelling used them would fail this test and be analysed twice.
    # Lowercased as well as separator-normalised: ECMA-376 part names are
    # case-insensitive, so `WORD/document.xml` is a valid document that a
    # case-sensitive test would decline to defer.
    has_office_root = any(
        n.replace("\\", "/").lower().startswith(_OFFICE_PACKAGE_ROOTS)
        for n in names
    )
    if not (has_content_types and has_office_root):
        return False

    # Third condition: the package must contain nothing else. Without it
    # the two tests above were a costume an attacker could put on — add
    # `[Content_Types].xml` and a `word/` entry to any ZIP and this
    # module defers to doc_analysis, which then declines it as not an
    # Office document. Verified: both modules returned "skipped" and a PE
    # sitting beside those two parts was examined by nothing at all.
    #
    # Structural on purpose. The rule cannot depend on recognising the
    # foreign member, or an unrecognised payload walks back through the
    # same gap; it asks only whether the archive is a closed OOXML
    # package. Measured on the corpus: 1 of 57 real packages is
    # disqualified, and that one carries a `[trash]` component.
    if not all(
        _top_level_component(n) in _OFFICE_ALLOWED_COMPONENTS for n in names
    ):
        return False

    # Fourth: no member may carry an executable extension, at any depth.
    # The component test alone only kept a payload out of the root —
    # `word/malware.exe` satisfies it perfectly, and doc_analysis ignores
    # an unreferenced part, so the costume still worked with the payload
    # moved inside it. Measured: none of 57 real OOXML packages in the
    # corpus contains a member with a dangerous extension, so refusing to
    # defer on one costs nothing. Binary parts are untouched — a
    # `vbaProject.bin` must still reach doc_analysis, which is the only
    # module that can read its macros.
    from .indicators import _DANGEROUS_EXTENSIONS  # noqa: PLC0415

    # Matched on the stripped name's ending rather than via
    # `PurePosixPath.suffix`, which is the wrong tool for a blocklist:
    # the suffix of `word/.exe` is the empty string, and a trailing space
    # or dot yields ".exe " or "" — none of which match. Windows strips
    # trailing spaces and dots on extraction and treats a bare `.exe` as
    # executable, so all three of those run.
    # An allow-list, not a blocklist, and the difference is the point. A
    # blocklist of executable and archive extensions was complete right
    # up until the payload was named `word/payload` with no extension at
    # all — doc_analysis ignores an unreferenced part, so that deferred
    # and was examined by nothing. No enumeration of dangerous
    # extensions can close that, because the attacker picks the name.
    #
    # Inverting it is safe here only because of the asymmetry above: an
    # unfamiliar part type means a second module also looks at the file,
    # never that none does. Measured against the corpus, which is what
    # the list is drawn from.
    for name in names:
        # No legitimate part name contains a NUL, and one truncates the
        # name for whatever writes the file out — `payload.exe\x00.png`
        # ends with an allowed extension here and lands as `payload.exe`
        # on Windows.
        if "\x00" in name:
            return False
        leaf = name.replace("\\", "/").rstrip(" .\t").lower()
        if not leaf or leaf.endswith("/"):
            continue  # directory record
        basename = leaf.rsplit("/", 1)[-1]
        # `.rels` reads as a dotfile with no suffix, and every package
        # contains one, so the extension is taken from the last dot
        # rather than from pathlib's notion of a suffix.
        ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
        if ext not in _OFFICE_ALLOWED_PART_EXTENSIONS:
            return False

    # Fifth: the content-types part must actually be XML. Renaming the
    # payload to a required part name satisfies every name-based test
    # above, and doc_analysis then fails to parse it and skips — so the
    # file is examined by nothing. All 57 corpus packages open this part
    # with `<?xml `, so requiring a leading `<` after any BOM is free.
    # Streamed, never `zf.read()`. That call decompresses the whole
    # member before anything can slice it, and this runs during routing —
    # before the decompression-bomb guard has seen a single number. A
    # content-types part that inflates to gigabytes would exhaust memory
    # while the tool was still deciding which module owns the file.
    try:
        with zipfile.ZipFile(file_path, "r") as zf, \
                zf.open(content_types_name) as part:
            # More than the four bytes strictly needed: XML permits
            # whitespace before the root element when the `<?xml ?>`
            # declaration is omitted, so a small read could see only
            # spaces and misjudge a valid part.
            head = part.read(64)
    except Exception:  # noqa: BLE001
        # Broad on purpose. zipfile raises NotImplementedError for an
        # unsupported compression method, and zlib its own errors for
        # corrupt data — neither is an OSError. A narrow clause let that
        # escape and, through run()'s last-resort handler, turned a
        # crafted compression method on one part into "this archive was
        # not analysed". Design rule 2 wants a decision here.
        return False

    # removeprefix, not lstrip: lstrip would strip any of those three
    # bytes in any order and any number, which is not what a BOM is.
    return head.removeprefix(b"\xef\xbb\xbf").lstrip().startswith(b"<")
