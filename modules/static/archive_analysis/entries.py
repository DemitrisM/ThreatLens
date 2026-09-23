"""Normalised archive entry representation.

Every handler (`zip_handler`, `rar_handler`, `sevenzip_handler`,
`tarball_handler`, `other_handlers`) returns a list of ``ArchiveEntry``
plus a container-level metadata dict. The cross-format indicators in
``indicators.py`` operate purely on ``ArchiveEntry`` so they don't need
to know which format produced the listing.

Design notes
------------
This module is the package's only leaf: it imports nothing from
``archive_analysis`` and everything else imports it. That is deliberate —
it is the vocabulary the handlers and the indicators agree on, so it must
not acquire a dependency on either side.

A member's **identity is its index, not its name**. ``name`` is
attacker-controlled and is not unique within a container, and every
archive library resolves a duplicate name to exactly one record. Code
that addresses a member by name therefore reads that one record once per
duplicate and never opens its siblings, which is how a payload hides
behind a decoy. ``member_index`` exists so that cannot happen.

Canonicalisation lives here rather than at the two call sites that need
it. The extractor's path mapper has to find the file a member produced;
the duplicate-name indicator has to know when two members produce the
same one. They are the same question asked twice, and while the two
carried separate copies they drifted four times during review — every
drift a hole, because a destination the mapper could not resolve was
also a collision the indicator failed to report.

``member_destinations`` returns *candidates*, not an answer. Extractors
disagree about what they do with a traversing or absolute name, so the
list is ordered by likelihood and the caller takes the first one that
exists on disk. Its ordering is load-bearing; see that function.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath


@dataclass
class ArchiveEntry:
    """A single member of an archive, normalised across formats."""

    name: str                       # full in-archive path
    size_compressed: int = 0
    size_uncompressed: int = 0
    is_encrypted: bool = False
    is_symlink: bool = False
    symlink_target: str | None = None
    timestamp: int | None = None    # epoch seconds, or None if not provided
    method: str | None = None       # compression method identifier
    # Present when the handler has already dumped the member to disk
    # (bomb guard did not trip, size was within limits). Populated by
    # ``extract_to_temp_bounded`` helpers; used for MIME / embedded-PE
    # checks. ``None`` = not materialised.
    extracted_path: str | None = None
    crc: int | None = None
    # Position of this member in the container's own record order, set by
    # the enumerator. Extraction addresses members by this index rather
    # than by name: a name is attacker-controlled and is not unique, and
    # every archive library resolves a duplicate name to exactly one
    # record, so extracting by name reads that record repeatedly and never
    # opens its siblings. Carrying the index explicitly means a filtered
    # or reordered ``entries`` list still addresses the right record —
    # positional zip() against a freshly read listing would not.
    member_index: int | None = None
    # Unsanitised filename recovered from a raw header walk — currently
    # populated only by the RAR handler to expose NTFS Alternate Data
    # Stream suffixes that ``rarfile`` strips (CVE-2025-8088). ``None``
    # when the sanitised ``name`` is already the full story.
    raw_name: str | None = None


@dataclass
class ContainerMeta:
    """Container-level metadata not tied to any single member."""

    detected_format: str | None = None
    comment: str = ""               # archive global comment (ZIP EOCD, RAR)
    header_encrypted: bool = False  # RAR5 / 7z header encryption
    handler_errors: list[dict] = field(default_factory=list)
    # ZIP-only: list of per-entry mismatches between local-file-header
    # and central-directory metadata.
    zip_header_mismatches: list[dict] = field(default_factory=list)


def entry_to_dict(entry: ArchiveEntry) -> dict:
    """Serialise an entry to the plain dict that lands in module data.

    Three fields are deliberately withheld from the report.
    ``extracted_path`` points into a tempdir that is removed before the
    scan returns, so it would be a dead path that also discloses the
    analyst's filesystem layout. ``crc`` and ``member_index`` are
    internal plumbing — the index is how extraction addresses a record,
    which is meaningless to a reader of the report.

    ``raw_name`` is conditional rather than always present: it is only
    set when the sanitised ``name`` is not the full story (currently the
    RAR handler recovering NTFS ADS suffixes), so emitting it
    unconditionally would put a null beside every member of every other
    format.

    Args:
        entry: The normalised member to serialise.

    Returns:
        A JSON-safe dict of the member's reportable fields.
    """
    out = {
        "name": entry.name,
        "size_compressed": entry.size_compressed,
        "size_uncompressed": entry.size_uncompressed,
        "is_encrypted": entry.is_encrypted,
        "is_symlink": entry.is_symlink,
        "symlink_target": entry.symlink_target,
        "timestamp": entry.timestamp,
        "method": entry.method,
    }
    if entry.raw_name:
        out["raw_name"] = entry.raw_name
    return out


# ---------------------------------------------------------------------------
# Member-name canonicalisation
#
# Two places need to know where a member called X will end up on disk: the
# extractor's path mapper, which has to find the file, and the duplicate-name
# indicator, which has to know when two members target the same one. Keeping
# separate copies let them drift — each drift was a silent hole, because a
# payload the mapper could not place was also a collision the indicator did
# not report. One implementation, used by both.
# ---------------------------------------------------------------------------

_DRIVE_LETTER_PREFIX = re.compile(r"^[A-Za-z]:[\\/]*")


def normalise_member_name(name: str) -> str:
    """Separators unified, drive letter and absolute root removed.

    Sanitising extractors refuse to write outside their destination, so
    ``C:\\evil.exe`` and ``/evil.exe`` are both written as ``evil.exe``.
    Leaving the drive letter on meant those never matched a plain
    ``evil.exe``, so a payload could occupy the same destination as a decoy
    without the collision being noticed.

    Backslashes are unified to forward slashes first, and unconditionally:
    a ZIP written by a Windows packer uses them as separators even though
    the format specifies forward slashes, and a backslash is a legal
    character in a POSIX filename. Treating it as a separator either way
    is the safe direction — it can merge two names that a POSIX extractor
    would keep apart, which over-reports a collision, whereas the reverse
    lets a Windows-style path escape the check entirely.

    Args:
        name: The raw in-archive member name.

    Returns:
        The name with separators unified and any drive letter or leading
        root stripped. Traversal segments are left intact — that is
        :func:`strip_traversal` and :func:`collapse_traversal`.
    """
    unified = name.replace("\\", "/")
    return _DRIVE_LETTER_PREFIX.sub("", unified).lstrip("/")


def strip_traversal(normalised: str) -> str:
    """Drop ``.`` and ``..`` segments, keeping the rest of the tree.

    What a sanitising extractor writes: ``nested/../evil.exe`` becomes
    ``nested/evil.exe``, not ``evil.exe``. The ``..`` is deleted rather
    than applied, so the surrounding directory survives. That is the
    difference from :func:`collapse_traversal`, and it is why both exist
    — the two disagree on exactly the names an attacker chooses, so
    :func:`member_destinations` offers both and lets the disk decide.

    Args:
        normalised: A name already through :func:`normalise_member_name`.

    Returns:
        The name with every empty, ``.`` and ``..`` segment removed.
    """
    return "/".join(
        seg for seg in normalised.split("/") if seg not in ("", ".", "..")
    )


def collapse_traversal(normalised: str) -> str:
    """Resolve ``..`` lexically, as ``Path.resolve()`` would on disk.

    ``nested/../evil.exe`` becomes ``evil.exe``: the ``..`` consumes the
    segment before it. A ``..`` with nothing left to pop is discarded
    rather than allowed to walk above the root, which is what keeps the
    result inside the destination tree.

    Args:
        normalised: A name already through :func:`normalise_member_name`.

    Returns:
        The lexically resolved path, never escaping its own root.
    """
    out: list[str] = []
    for seg in normalised.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return "/".join(out)


def member_destinations(name: str, include_basename: bool = False) -> list[str]:
    """Ordered list of paths a member called ``name`` may occupy.

    Args:
        name:             The in-archive member name.
        include_basename: Add the bare basename as a last resort. True for
                          locating a file (the mapper), False for deciding
                          whether two members collide — a shared basename
                          across directories is ordinary and extractors
                          preserve the tree, so counting it as a collision
                          would fire across a large benign population.

    Returns:
        Candidates ordered by how likely an extractor produced them, most
        likely first, with duplicates removed and order preserved.
    """
    # ---- Candidate order is the contract -----------------------------
    # The caller takes the first candidate that exists on disk, so this
    # ordering decides which file a member is credited with. Sanitising
    # extractors are the common case and they delete traversal segments,
    # so that spelling leads. The raw `name` comes last of the four
    # because trusting it is what a traversal attack wants; by the time
    # it is reached the three safe spellings have already missed.
    normalised = normalise_member_name(name)
    ordered = [
        strip_traversal(normalised),
        normalised,
        collapse_traversal(normalised),
        name,
    ]
    if include_basename:
        ordered.append(PurePosixPath(normalised).name)

    # ---- De-duplicate without reordering -----------------------------
    # A name with no separators and no traversal produces the same string
    # four times over. Order must survive de-duplication, so this cannot
    # be a set comprehension.
    seen: set[str] = set()
    out: list[str] = []
    for candidate in ordered:
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out
