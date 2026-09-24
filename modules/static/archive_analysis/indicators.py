"""Cross-format archive indicators.

Pure functions that operate on the normalised ``ArchiveEntry`` list plus
the container metadata. No archive-library imports here — handlers have
already done the format-specific work.

Design notes
------------
The absence of format knowledge is the design, not an accident of
layering. One ZIP-shaped attack and the same attack in a RAR are the
same finding, and an indicator that knew which library produced the
listing would have to be written eleven times and would drift ten of
them. Everything here reads ``ArchiveEntry`` and nothing else, which is
also what makes these functions testable without building an archive.

**Every path check reads ``raw_name`` as well as ``name``.** The handlers
expose the library's sanitised view in ``name`` and, where they recovered
one, the unsanitised bytes in ``raw_name``. CVE-2025-8088 lives entirely
in the difference: ``rarfile`` reports ``fiyat teklifi.pdf`` while the
archive says ``fiyat teklifi.pdf:..\\..\\AppData\\...\\Startup\\Updater.exe``.
An indicator that reads only ``name`` sees a PDF.

Indicators report, they do not score. Each returns evidence — the
offending names, the matched paths, a triggered/reason pair — and the
orchestrator turns a non-empty result into a flag for the combo engine.
That split is what lets the report show *which* member was dangerous
rather than only that something was, and it keeps the weights in one
file instead of scattered through thirteen functions.

Nothing here raises. These run after enumeration on input that is
malicious by assumption, so a member name that breaks an assumption has
to cost that member, never the scan.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from pathlib import Path

from .entries import ArchiveEntry, member_destinations

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dangerous extensions (spec list)
# ---------------------------------------------------------------------------

# Extensions that execute, or that carry something that does. The list
# deliberately includes container formats — `.iso`, `.one`, `.ace`,
# `.msi` — because a container inside an archive is a delivery vehicle,
# and the mark-of-the-web stripping that makes ISO and OneNote attractive
# to droppers is the reason they are here rather than treated as data.
#
# `.lnk` and `.msi` are also listed as dangerous *strings* in
# `doc_analysis/ole_objects.py`. That duplication is intentional: the two
# modules answer for different containers and neither should depend on
# the other's table.
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

# Requires a plausible inner extension of 2–5 characters before the
# executable one, so `photo.jpg.exe` fires and `setup.exe` does not. The
# length bound is what keeps ordinary dotted names — `v1.2.exe`,
# `archive.tar.exe` aside — from being read as a decoy: a single-character
# or very long middle segment is more often part of a version or a hash
# than a mimicked file type.
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

    Args:
        entries: Normalised archive members.

    Returns:
        The offending path strings, at most one per entry — whichever
        candidate matched first. Empty when nothing traverses.

    Three shapes count, and all three are ways to write outside the
    destination: a leading separator (absolute POSIX drop), a ``../``
    segment anywhere, and a drive-letter prefix (absolute Windows drop).
    The traversal test normalises backslashes first because a Windows-built
    archive spells the same attack ``..\\``.

    The ``break`` matters. Reporting both ``name`` and ``raw_name`` for one
    member would double-count a single finding, and the two are the same
    file — so the first match is the evidence and the rest is duplication.
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
    """Symlinks whose target escapes the archive or names a sensitive path.

    Args:
        entries: Normalised archive members.

    Returns:
        ``[{"name", "target"}, ...]`` for each offending link.

    A symlink is the traversal attack the member *name* check cannot see:
    the name is innocuous and the payload is the target. Extraction skips
    symlinks entirely for that reason, so this indicator is how the
    attempt still reaches the report rather than being silently dropped.

    Absolute and traversing targets are structural; the sensitive-path
    list is a judgement about what an archive has no business linking to.
    The list is POSIX-heavy because that is where a symlink in an archive
    usually lands — Windows extractors mostly refuse them.
    """
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

def _name_candidates(entry: ArchiveEntry):
    """Yield every spelling of a member's name worth inspecting.

    Args:
        entry: A normalised member.

    Yields:
        ``entry.name``, then ``entry.raw_name`` when the handler recovered
        one and it differs. Empty values are skipped.

    The path indicators have always read both. The extension indicators
    did not, and that was the gap: in the CVE-2025-8088 sample the
    sanitised name is a ``.pdf`` and the payload dropped through the ADS
    suffix is a ``.lnk``, so the archive's entire purpose was invisible to
    `detect_dangerous_members`. It cost the report a row and the scoring
    engine the ``dangerous_member`` flag that ``persistence_path`` and
    ``embedded_pe`` both combine with.

    Callers break after the first match so one member yields one finding,
    however many of its spellings implicate it.
    """
    seen: set[str] = set()
    for candidate in (entry.name, entry.raw_name):
        if candidate and candidate not in seen:
            seen.add(candidate)
            yield candidate


def detect_dangerous_members(entries: list[ArchiveEntry]) -> list[dict]:
    """Members whose final extension is one that executes or delivers.

    Args:
        entries: Normalised archive members.

    Returns:
        ``[{"name", "extension", "size"}, ...]``, one per match.

    Only the final extension is considered; ``photo.jpg.exe`` matches on
    ``.exe`` here and is separately reported as a double-extension trick.
    The size travels with the finding because "a 2 KB .exe" and "a 4 MB
    .exe" are different claims about what the archive is for.

    This is the broadest indicator in the file and its weight is
    correspondingly low — a `.exe` in an archive is common. It earns its
    place by combining: the scoring engine pairs it with embedded PEs,
    persistence paths and encryption, and those combinations are what
    reach MALICIOUS.
    """
    out: list[dict] = []
    for e in entries:
        for candidate in _name_candidates(e):
            ext = Path(candidate).suffix.lower()
            if ext in _DANGEROUS_EXTENSIONS:
                out.append({
                    "name": candidate,
                    "extension": ext,
                    "size": e.size_uncompressed,
                })
                break
    return out


def detect_double_extension(entries: list[ArchiveEntry]) -> list[str]:
    """Members named to look like a document and run like a program.

    Args:
        entries: Normalised archive members.

    Returns:
        The offending member names.

    Matched against the basename, not the full path, so a directory
    component containing a dot cannot produce a false hit. The trick works
    because Windows hides known extensions by default, so ``photo.jpg.exe``
    is displayed as ``photo.jpg`` — which is why this is scored well above
    a plain dangerous extension despite being the same file.
    """
    out: list[str] = []
    for e in entries:
        for candidate in _name_candidates(e):
            base = Path(candidate).name.lower()
            if _DOUBLE_EXT_RE.search(base):
                out.append(candidate)
                break
    return out


def detect_rtlo_filenames(entries: list[ArchiveEntry]) -> list[str]:
    """Members carrying a bidirectional-override character.

    Args:
        entries: Normalised archive members.

    Returns:
        The offending member names.

    ``invoice\u202egnp.exe`` renders as ``invoiceexe.png``. The set covers
    the left-to-right controls as well as the right-to-left ones, because
    the detection is not "is this text Arabic or Hebrew" — a legitimate
    filename in either script needs no override character at all. Any of
    them in a filename is an attempt to make it display as something other
    than what it is, so presence alone is the finding.
    """
    out: list[str] = []
    for e in entries:
        for candidate in _name_candidates(e):
            if any(ch in candidate for ch in _RTLO_CHARS):
                out.append(candidate)
                break
    return out


def detect_null_byte_filenames(entries: list[ArchiveEntry]) -> list[str]:
    """Members with an embedded NUL in the name.

    Args:
        entries: Normalised archive members.

    Returns:
        The offending member names.

    A NUL cannot occur in a filename any tool legitimately produced. It is
    there to truncate the name for a C-string consumer while a
    length-prefixed one — Python, Java, the archive format itself — sees
    the whole thing, so ``safe.txt\x00.exe`` reads two ways. Presence is
    the entire finding; no further inspection is warranted or safe.
    """
    out: list[str] = []
    for e in entries:
        for candidate in _name_candidates(e):
            if "\x00" in candidate:
                out.append(candidate)
                break
    return out


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


# Container formats where a shadowed member cannot be recovered.
#
# 7z and CAB are unpacked wholesale by an external tool, which writes one
# duplicate-named member over the other before ThreatLens ever sees the disk.
# ISO is read member-by-member, but pycdlib addresses records by path with no
# index-based API, so a repeated path resolves to one record and its sibling
# is unreachable just the same.
_OVERWRITING_FORMATS: frozenset[str] = frozenset({"7z", "cab", "iso"})


def detect_duplicate_member_names(
    entries: list[ArchiveEntry], fmt: str | None = None,
) -> list[dict]:
    """Return members whose name is shared by another record.

    Args:
        entries: Normalised archive members.
        fmt:     Detected container format. Decides ``recoverable``: the
                 formats read member-by-member here recover both records,
                 the ones unpacked by an external tool do not.

    Returns:
        One dict per repeated name — ``{"name", "count", "recoverable"}`` —
        sorted by name. Empty when every name is unique.

    Design notes:
        A repeated name is not a formatting quirk. Every archive library
        resolves a name to exactly one record, so a duplicate is a way to
        show a scanner one file while a different one occupies the same
        name. ZIP, RAR and TAR are read member-by-member here and address
        records by index, so both are recovered and ``recoverable`` is True.

        7z and CAB are not. Those formats are unpacked wholesale by an
        external tool (``py7zr.extractall``, ``cabextract``) which writes
        one member over the other on disk, so by the time ThreatLens looks
        only the survivor exists. The hidden bytes are genuinely gone —
        which is exactly why this has to be reported rather than passed
        over: a crafted 7z would otherwise come back as fully analysed.
    """
    recoverable = fmt not in _OVERWRITING_FORMATS

    # Collisions are counted over every spelling a member could be written
    # under, not over the raw name. "a.exe", "./a.exe" and "nested/../a.exe"
    # are three distinct strings that resolve onto the same file, so counting
    # raw names reported no duplicates at all while one member still
    # overwrote another — the indicator missed the very case it exists for.
    # The spellings mirror sevenzip_handler._candidate_paths so the indicator
    # and the mapper agree on what "the same file" means. Raised by Gemini.
    by_target: dict[str, set[int]] = {}
    for i, e in enumerate(entries):
        # include_basename=False: a shared basename across directories
        # is ordinary and extractors preserve the tree, so counting it
        # as a collision would fire across a large benign population.
        for spelling in member_destinations(e.name):
            by_target.setdefault(spelling, set()).add(i)

    # One row per colliding group, not per shared spelling. Two members both
    # named "nested/../a.exe" agree on all three of their spellings, which
    # would otherwise render as three identical findings in the report. The
    # group is keyed by the members involved; the shortest spelling is the
    # canonical destination and the one worth showing. Raised by Gemini.
    groups: dict[frozenset[int], str] = {}
    for target, owners in sorted(by_target.items()):
        if len(owners) < 2:
            continue
        key = frozenset(owners)
        current = groups.get(key)
        if current is None or (len(target), target) < (len(current), current):
            groups[key] = target

    return sorted(
        (
            {
                "name": target,
                "count": len(owners),
                "recoverable": recoverable,
            }
            for owners, target in groups.items()
        ),
        key=lambda d: d["name"],
    )


def detect_autorun_desktop(entries: list[ArchiveEntry]) -> tuple[dict | None, bool]:
    """Find a root-level ``autorun.inf`` or ``desktop.ini``.

    Args:
        entries: Normalised archive members.

    Returns:
        ``(autorun_info, has_desktop_ini)``. ``autorun_info`` is
        ``{"name", "target_exec", "raw"}`` or None.

    **Root level only, and that is the whole test.** Windows reads
    ``autorun.inf`` from the root of a mounted volume and nowhere else, so
    a copy three directories deep is inert and flagging it would fire on
    any archive that happens to contain an old CD image's contents. The
    same reasoning applies to ``desktop.ini``, which controls folder
    appearance and is ordinary inside a tree but is a spoofing attempt at
    the root.

    This pairs with the ISO and IMG entries in the dangerous-extension
    list: the shape being detected is an archive that unpacks into
    something Windows will treat as a mountable volume.

    ``target_exec`` and ``raw`` are always None — the fields exist so the
    reporters have a stable shape, but the ``[autorun]`` body is not
    parsed, so the executable the file points at is not yet extracted.
    """
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
    """Shannon entropy of a string, in bits per character.

    Args:
        text: The string to measure.

    Returns:
        Entropy in bits per character; 0.0 for an empty string.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def detect_high_entropy_filenames(entries: list[ArchiveEntry]) -> list[str]:
    """Members whose name looks generated rather than chosen.

    Args:
        entries: Normalised archive members.

    Returns:
        The offending member names.

    Measured over the stem, with the extension excluded: the extension is
    a fixed low-entropy string that would drag every short name below the
    threshold and is the part deliberately chosen to look ordinary.

    The two conditions do different jobs. The 8-character minimum excludes
    short names, where entropy is unstable — a 4-character name of
    distinct letters scores 2.0 simply because nothing repeats. The 4.5
    bits/char threshold is then roughly what a random alphanumeric string
    reaches and roughly double an English word, so it separates
    ``a7Fq2xR9mK`` from ``quarterly-report``.

    On its own this means little — a hash-named file is normal in a
    software archive — which is why the scoring engine only pays for it
    alongside a dangerous extension.

    Separators are normalised before the stem is taken, and that step is
    load-bearing here in a way it is not for the extension indicators.
    ``.suffix`` and the double-extension regex both anchor to the end of
    the string, so a Windows-style ADS path gives them the right answer
    regardless. Entropy is an average over the whole stem, and on POSIX
    ``pathlib`` does not split on backslashes — so without normalising,
    the "stem" of
    ``decoy.pdf:..\\..\\Windows\\Start Menu\\a7Fq2xR9mK.exe`` is the
    entire string. Measured: 4.728, above the threshold, firing on the
    length and variety of the path itself rather than on the payload.
    Normalised, the stem is ``a7Fq2xR9mK`` at 3.322, which is the
    honest answer.

    That also bounds what this indicator can detect. 4.5 bits/char needs
    about 2**4.5 ~ 23 distinct characters, so a stem shorter than that
    cannot reach the threshold however random it is — a 10-character
    stem tops out at log2(10) = 3.32. The indicator fires on long
    generated names and is blind to short ones by construction.
    """
    out: list[str] = []
    for e in entries:
        for candidate in _name_candidates(e):
            # Separators normalised before the stem is taken. On POSIX
            # pathlib does not split on backslashes, so a Windows-built
            # ADS path would otherwise yield the whole string as its
            # "stem" — measured at 4.728, above the threshold, firing on
            # the variety of the path rather than on the payload name.
            stem = Path(candidate.replace("\\", "/")).stem
            if len(stem) > 8 and _shannon_entropy(stem) > 4.5:
                out.append(candidate)
                break
    return out


# ---------------------------------------------------------------------------
# Timestamp anomaly
# ---------------------------------------------------------------------------

# Imported here rather than at the top of the file, which is the only
# such import in the package. Left where it is deliberately: moving it is
# a code change, and this module's own history is the argument for not
# mixing those into a documentation pass.
import time


def detect_timestamp_anomaly(entries: list[ArchiveEntry]) -> dict:
    """Decide whether the member timestamps look machine-produced.

    Args:
        entries: Normalised archive members. Those without a timestamp
                 are ignored rather than counted as zero.

    Returns:
        ``{"triggered": bool, "reason": str | None}``.

    Three tests, ordered most specific first, and the first to match wins
    — an archive that is both all-identical and all-1980 is described by
    the more precise of the two rather than by both.

    All-identical means the archive was assembled programmatically: a
    packer writing every member in one pass, not a user collecting files.
    It needs more than one timestamp to mean anything, hence the length
    check — a single-member archive trivially has one distinct value.

    The DOS epoch is what a ZIP writes when it has no real date, and
    1989 is the out-of-range floor rather than 1980 precisely so the
    DOS-epoch case reaches its own more informative test first.

    A year of future tolerance absorbs clock skew and timezone error
    without absorbing the timestamps malware actually carries, which tend
    to be far-future or zero rather than slightly ahead.

    Note this is a property of the *set*: it says the archive was built
    oddly, not that any one member is malicious. Its weight is 1.
    """
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

# Declared extension -> the MIME types libmagic legitimately reports for
# it. Several map to more than one because libmagic's answer depends on
# its version and on the file's own content: a .json holding a bare
# string is text/plain, a .html fragment without a doctype likewise. The
# alternatives are listed so an ordinary file cannot be flagged by the
# host's libmagic build.
#
# Only unambiguous, high-traffic document and media types are listed. An
# extension absent from this table is simply not checked, which is the
# right default — the cost of a missing entry is a missed detection,
# while the cost of a loose entry is a false positive on every benign
# file of that type.
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
    """Flag members whose extension disagrees with their actual bytes.

    Args:
        entries:   Normalised archive members. Only those materialised to
                   disk are examined — the check reads content, so a
                   member that was never extracted cannot be tested.
        max_bytes: Per-member ceiling, from
                   ``archive_member_mime_check_max_mb``.

    Returns:
        ``[{"name", "declared_ext", "actual_magic_type"}, ...]``.

    Two cases are reported and the first is the one that matters: a
    member declaring a safe extension whose bytes are an executable.
    ``invoice.pdf`` that is really a PE is the shape this indicator
    exists for.

    The second is narrower — a declared-benign type whose real type is
    neither expected nor ordinary. It is deliberately restricted to
    executables and ``application/x-*``, because a ``.txt`` that libmagic
    calls ``text/x-c`` or a ``.png`` it calls ``image/webp`` is a
    mislabelled file, not an attack, and reporting those would bury the
    first case in noise.

    Members already declaring a dangerous extension are skipped: a
    ``.exe`` that contains an executable is not a mismatch, and one that
    does not is already scored for its extension.

    Absent python-magic this returns empty — a skip, not an error, per
    design rule 2.
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
        # The `(OSError, Exception)` tuple is redundant — Exception
        # already covers OSError — but it is deliberate as documentation
        # of the two cases meant: the file vanished, or libmagic itself
        # failed on it. Either way one member is skipped rather than the
        # scan being lost.
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
