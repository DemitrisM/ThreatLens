"""Normalised archive entry representation.

Every handler (`zip_handler`, `rar_handler`, `sevenzip_handler`,
`tarball_handler`, `other_handlers`) returns a list of ``ArchiveEntry``
plus a container-level metadata dict. The cross-format indicators in
``indicators.py`` operate purely on ``ArchiveEntry`` so they don't need
to know which format produced the listing.
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
    """Serialise an entry to the plain dict that lands in module data."""
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
    """
    unified = name.replace("\\", "/")
    return _DRIVE_LETTER_PREFIX.sub("", unified).lstrip("/")


def strip_traversal(normalised: str) -> str:
    """Drop ``.`` and ``..`` segments, keeping the rest of the tree.

    What a sanitising extractor writes: ``nested/../evil.exe`` becomes
    ``nested/evil.exe``, not ``evil.exe``.
    """
    return "/".join(
        seg for seg in normalised.split("/") if seg not in ("", ".", "..")
    )


def collapse_traversal(normalised: str) -> str:
    """Resolve ``..`` lexically, as ``Path.resolve()`` would on disk."""
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
    normalised = normalise_member_name(name)
    ordered = [
        strip_traversal(normalised),
        normalised,
        collapse_traversal(normalised),
        name,
    ]
    if include_basename:
        ordered.append(PurePosixPath(normalised).name)

    seen: set[str] = set()
    out: list[str] = []
    for candidate in ordered:
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out
