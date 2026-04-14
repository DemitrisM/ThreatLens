"""Normalised archive entry representation.

Every handler (`zip_handler`, `rar_handler`, `sevenzip_handler`,
`tarball_handler`, `other_handlers`) returns a list of ``ArchiveEntry``
plus a container-level metadata dict. The cross-format indicators in
``indicators.py`` operate purely on ``ArchiveEntry`` so they don't need
to know which format produced the listing.
"""

from __future__ import annotations

from dataclasses import dataclass, field


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
    return {
        "name": entry.name,
        "size_compressed": entry.size_compressed,
        "size_uncompressed": entry.size_uncompressed,
        "is_encrypted": entry.is_encrypted,
        "is_symlink": entry.is_symlink,
        "symlink_target": entry.symlink_target,
        "timestamp": entry.timestamp,
        "method": entry.method,
    }
