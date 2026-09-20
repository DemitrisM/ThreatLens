"""Cross-format archive indicators.

Pure functions that operate on the normalised ``ArchiveEntry`` list plus
the container metadata. No archive-library imports here — handlers have
already done the format-specific work.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from pathlib import Path

from .entries import ArchiveEntry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dangerous extensions (spec list)
# ---------------------------------------------------------------------------

_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
    ".ps1", ".ps2", ".psc1", ".psc2",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".lnk", ".pif", ".url",
    ".msi", ".msp", ".mst",
    ".reg", ".inf", ".cpl", ".ocx", ".sys", ".drv",
    ".jar", ".xll", ".xlam",
    ".docm", ".xlsm", ".xlsb", ".pptm", ".dotm", ".xltm",
    ".iso", ".img", ".one", ".ace",
})

# Extensions commonly used for double-extension tricks: `photo.jpg.exe`.
_DOUBLE_EXT_EXEC: frozenset[str] = frozenset({
    "exe", "dll", "scr", "bat", "cmd", "com", "pif",
    "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta",
    "lnk", "msi", "jar", "xll",
})

_DOUBLE_EXT_RE = re.compile(
    rf"\.[a-z]{{2,5}}\.({'|'.join(_DOUBLE_EXT_EXEC)})$",
    re.IGNORECASE,
)

# RTLO and other invisible direction-override / bidi chars. Single
# characters — if any appear in a filename it is almost certainly an
# attempt to hide the real extension.
_RTLO_CHARS = {
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
}

# Persistence-path substrings, matched case-insensitively against a member
# name whose separators have been normalised to forward slashes.
#
# They are written in POSIX form on purpose. Archive members use either
# separator — a RAR built on Windows stores backslashes, a tar stores forward
# slashes, and the CVE-2025-8088 ADS suffix stores backslashes — so the
# matcher normalises once and the table is written one way. The previous
# table carried both forms and the backslash half was unreachable: those
# entries were raw strings ending in `\\`, which is two literal backslash
# characters, while a real member path has one. Every Windows form was
# therefore dead. `test_every_persistence_marker_is_reachable` now proves
# each entry can fire.
_PERSISTENCE_PATH_MARKERS: tuple[str, ...] = (
    "appdata/roaming/",
    "appdata/local/",
    "/startup/",
    "start menu/programs/startup/",
    "system32/",
    "syswow64/",
    "/temp/",
    "%appdata%",
    "%temp%",
    "%systemroot%",
)


# Any run of one or more separators, of either kind. Used to canonicalise a
# member name before marker matching — see detect_persistence_paths.
_SEPARATOR_RUN_RE = re.compile(r"[\\/]+")


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------

_DRIVE_LETTER_RE = re.compile(r"^[A-Za-z]:[\\/]")


def detect_path_traversal(entries: list[ArchiveEntry]) -> list[str]:
    """Return names of entries that attempt directory traversal / absolute drop.

    Inspects both the sanitised ``name`` and the handler-recovered
    ``raw_name``. The latter carries the CVE-2025-8088 NTFS ADS
    suffix that ``rarfile`` strips — without it the traversal hides
    behind a benign decoy filename.
    """
    offenders: list[str] = []
    for e in entries:
        for candidate in (e.name, e.raw_name):
            if not candidate:
                continue
            if (
                candidate.startswith(("/", "\\"))
                or "../" in candidate.replace("\\", "/")
                or _DRIVE_LETTER_RE.match(candidate)
            ):
                offenders.append(candidate)
                break
    return offenders


def detect_symlink_attacks(entries: list[ArchiveEntry]) -> list[dict]:
    """Symlinks whose target is absolute, traversing, or pointing at sensitive paths."""
    suspicious_targets = ("/etc/", "/root/", "/home/", "C:\\Windows", "/var/")
    out: list[dict] = []
    for e in entries:
        if not e.is_symlink:
            continue
        target = e.symlink_target or ""
        if (
            target.startswith(("/", "\\"))
            or "../" in target.replace("\\", "/")
            or any(s.lower() in target.lower() for s in suspicious_targets)
        ):
            out.append({"name": e.name, "target": target})
    return out


# ---------------------------------------------------------------------------
# Extension-based checks
# ---------------------------------------------------------------------------

def detect_dangerous_members(entries: list[ArchiveEntry]) -> list[dict]:
    out: list[dict] = []
    for e in entries:
        ext = Path(e.name).suffix.lower()
        if ext in _DANGEROUS_EXTENSIONS:
            out.append({
                "name": e.name,
                "extension": ext,
                "size": e.size_uncompressed,
            })
    return out


def detect_double_extension(entries: list[ArchiveEntry]) -> list[str]:
    out: list[str] = []
    for e in entries:
        base = Path(e.name).name.lower()
        if _DOUBLE_EXT_RE.search(base):
            out.append(e.name)
    return out


def detect_rtlo_filenames(entries: list[ArchiveEntry]) -> list[str]:
    out: list[str] = []
    for e in entries:
        if any(ch in e.name for ch in _RTLO_CHARS):
            out.append(e.name)
    return out


def detect_null_byte_filenames(entries: list[ArchiveEntry]) -> list[str]:
    return [e.name for e in entries if "\x00" in e.name]


def detect_persistence_paths(entries: list[ArchiveEntry]) -> list[str]:
    """Return members whose path targets a known persistence location.

    Both the sanitised ``name`` and the handler-recovered ``raw_name`` are
    inspected, because the CVE-2025-8088 Startup drop lives entirely in the
    NTFS ADS suffix that ``rarfile`` strips from ``name``.

    Args:
        entries: Normalised archive members.

    Returns:
        The matching path strings, at most one per entry — whichever of the
        two candidates matched first. Empty when nothing matches.
    """
    out: list[str] = []
    for e in entries:
        for candidate in (e.name, e.raw_name):
            if not candidate:
                continue
            # Collapse every run of separators, of either kind, to a
            # single forward slash. Sequential replaces are not enough:
            # `appdata//roaming/x.exe` and `appdata\\\\\\roaming\\x.exe`
            # both survive them and then fail the substring match, while
            # Windows canonicalises the redundant separators away and drops
            # the file exactly where the marker says. That made padding a
            # separator a one-character evasion primitive.
            normalised = _SEPARATOR_RUN_RE.sub("/", candidate.lower())
            if any(marker in normalised for marker in _PERSISTENCE_PATH_MARKERS):
                out.append(candidate)
                break
    return out


def detect_autorun_desktop(entries: list[ArchiveEntry]) -> tuple[dict | None, bool]:
    """Return (autorun_info, has_desktop_ini). autorun_info has raw + target_exec."""
    autorun: dict | None = None
    desktop_ini = False
    for e in entries:
        bn = Path(e.name).name.lower()
        parts = e.name.replace("\\", "/").strip("/").split("/")
        at_root = len(parts) == 1
        if at_root and bn == "autorun.inf":
            autorun = {"name": e.name, "target_exec": None, "raw": None}
        if at_root and bn == "desktop.ini":
            desktop_ini = True
    return autorun, desktop_ini


# ---------------------------------------------------------------------------
# Filename entropy (Shannon over basename, excluding extension)
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def detect_high_entropy_filenames(entries: list[ArchiveEntry]) -> list[str]:
    out: list[str] = []
    for e in entries:
        stem = Path(e.name).stem
        if len(stem) > 8 and _shannon_entropy(stem) > 4.5:
            out.append(e.name)
    return out


# ---------------------------------------------------------------------------
# Timestamp anomaly
# ---------------------------------------------------------------------------

import time


def detect_timestamp_anomaly(entries: list[ArchiveEntry]) -> dict:
    timestamps = [e.timestamp for e in entries if e.timestamp is not None]
    if not timestamps:
        return {"triggered": False, "reason": None}

    # All-identical
    unique = set(timestamps)
    if len(unique) == 1 and len(timestamps) > 1:
        return {
            "triggered": True,
            "reason": f"All {len(timestamps)} entries share identical timestamp",
        }

    # DOS epoch (1980-01-01)
    dos_epoch = 315532800  # 1980-01-01 00:00:00 UTC
    if len(timestamps) > 1 and all(abs(t - dos_epoch) < 86400 for t in timestamps):
        return {"triggered": True, "reason": "All entries use DOS-zero (1980-01-01) timestamp"}

    # Out-of-range
    now = time.time()
    pre_1989 = 599616000      # 1989-01-01
    future_cutoff = now + 365 * 86400
    offending = [t for t in timestamps if t < pre_1989 or t > future_cutoff]
    if offending:
        return {
            "triggered": True,
            "reason": f"{len(offending)} timestamp(s) out of plausible range (pre-1989 or future)",
        }

    return {"triggered": False, "reason": None}


# ---------------------------------------------------------------------------
# MIME mismatch — declared extension vs libmagic-detected actual type
# ---------------------------------------------------------------------------

_DECLARED_TO_EXPECTED_TYPES: dict[str, tuple[str, ...]] = {
    ".jpg":  ("image/jpeg", "image/pjpeg"),
    ".jpeg": ("image/jpeg", "image/pjpeg"),
    ".png":  ("image/png",),
    ".gif":  ("image/gif",),
    ".bmp":  ("image/bmp", "image/x-ms-bmp"),
    ".pdf":  ("application/pdf",),
    ".txt":  ("text/plain",),
    ".json": ("application/json", "text/plain"),
    ".xml":  ("application/xml", "text/xml", "text/plain"),
    ".html": ("text/html", "text/plain"),
    ".htm":  ("text/html", "text/plain"),
    ".csv":  ("text/csv", "text/plain"),
    ".mp3":  ("audio/mpeg",),
    ".mp4":  ("video/mp4",),
    ".wav":  ("audio/wav", "audio/x-wav"),
}

_EXECUTABLE_MIME_TYPES = (
    "application/x-dosexec",     # PE
    "application/x-executable",  # ELF
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/vnd.microsoft.portable-executable",
)


def detect_mime_mismatches(entries: list[ArchiveEntry], max_bytes: int) -> list[dict]:
    """Flag members whose extension doesn't match libmagic's read of their bytes.

    Only checks entries that were materialised to disk (``extracted_path``
    populated) AND smaller than ``max_bytes`` — see the spec's 10 MiB cap.
    """
    try:
        import magic  # noqa: PLC0415
    except ImportError:
        logger.debug("python-magic not available — MIME mismatch detection skipped")
        return []

    out: list[dict] = []
    for e in entries:
        if not e.extracted_path or e.size_uncompressed > max_bytes:
            continue
        ext = Path(e.name).suffix.lower()
        if ext not in _DECLARED_TO_EXPECTED_TYPES and ext in _DANGEROUS_EXTENSIONS:
            # Don't bother checking members that already declare a
            # dangerous extension — nothing to mismatch against.
            continue
        try:
            actual = magic.from_file(e.extracted_path, mime=True)
        except (OSError, Exception):  # noqa: BLE001
            continue

        # Highest-signal case: declared-safe extension resolves to an executable.
        if ext in _DECLARED_TO_EXPECTED_TYPES and actual in _EXECUTABLE_MIME_TYPES:
            out.append({
                "name": e.name,
                "declared_ext": ext,
                "actual_magic_type": actual,
            })
            continue

        # Declared-benign type but libmagic says otherwise (e.g. .jpg is not image/jpeg).
        expected = _DECLARED_TO_EXPECTED_TYPES.get(ext)
        if expected and actual and actual not in expected:
            # Only flag if the actual type is an executable or archive.
            if (
                actual in _EXECUTABLE_MIME_TYPES
                or actual.startswith("application/x-")
            ):
                out.append({
                    "name": e.name,
                    "declared_ext": ext,
                    "actual_magic_type": actual,
                })
    return out


# ---------------------------------------------------------------------------
# Comment IOC scan — reuses ioc_extractor's compiled regexes
# ---------------------------------------------------------------------------

def scan_comments_for_iocs(comment_blobs: list[str]) -> list[str]:
    """Feed archive-comment text through ioc_extractor's full pipeline.

    Both halves of that pipeline are needed, not just the regexes. The raw
    domain pattern matches anything shaped ``word.word``, so a comment
    reading "see readme.txt and setup.exe" yields two "domains" and sets the
    ``comment_ioc`` flag for +3 — a benign WinRAR comment scoring as an
    indicator. ``_filter_fps`` is what knows ``.txt`` is not a TLD and that
    192.168.0.0/16 is not a C2, so it is applied here exactly as
    ``ioc_extractor.run()`` applies it.

    Args:
        comment_blobs: Container comment strings; empty entries are ignored.

    Returns:
        Sorted surviving IOC strings across the reported categories. Empty
        when nothing survives, or when ``ioc_extractor`` cannot be imported.
    """
    if not comment_blobs:
        return []
    try:
        from modules.static import ioc_extractor  # noqa: PLC0415
    except ImportError:
        # A genuinely absent module is a graceful skip (design rule 2).
        logger.debug("ioc_extractor unavailable — comment IOC scan skipped")
        return []

    # Resolved by attribute rather than by `from ... import name`, so a
    # renamed or deleted helper raises AttributeError here instead of being
    # swallowed by the ImportError arm above. Every negative test in this
    # area asserts an empty list, so a silently-empty result would look
    # exactly like correct filtering — the failure has to be loud.
    patterns = ioc_extractor._IOC_PATTERNS
    filter_fps = ioc_extractor._filter_fps

    found: set[str] = set()
    blob = "\n".join(b for b in comment_blobs if b)
    for ioc_type, pattern in patterns.items():
        # windows_path is deliberately absent: an archive comment naming a
        # local build path is noise, not an indicator.
        if ioc_type in ("ipv4", "url", "domain", "email", "registry_key"):
            found.update(filter_fps(ioc_type, set(pattern.findall(blob))))
    return sorted(found)
