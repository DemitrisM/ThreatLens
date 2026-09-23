"""7z handler — ``py7zr`` (pure-Python).

7z archives can encrypt the central header so member listings are
unavailable without the password. We flag that as ``header_encrypted``
and return early.

Design notes
------------
**py7zr extracts all or nothing, and that one constraint shapes the
rest of this file.** It exposes no per-member read, so bounding the
extraction has to happen *before* the call — hence the pre-flight sum
rather than the running counter every other handler uses — and the
members land wherever the library decided to put them rather than where
this module asked. Working out which file on disk is which member is
therefore a search, which is what `_map_extracted_paths` is, and why
that function is shared with the CAB handler rather than living here as
a private detail.

It also means a duplicate member name is genuinely unrecoverable for
this format. ``extractall`` writes the second over the first, so the
earlier member's bytes are gone before this module looks. That is
reported as ``shadowed_member_unrecoverable`` rather than passed over —
7z is in ``_OVERWRITING_FORMATS`` for exactly this reason, unlike ZIP,
RAR and TAR where the member can still be addressed by index.

Encryption is recorded at archive level, because that is the only level
py7zr describes it at. It reports whether the archive is
password-protected and offers nothing per-member to refine that with.
Measured against py7zr 1.1.0: an encrypted member carries the *same*
crc32 as the same bytes stored unencrypted, and the only entries
reporting no crc32 are directories — so CRC presence says nothing about
encryption, and using it would flag every folder while missing every
encrypted payload.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta, member_destinations

logger = logging.getLogger(__name__)


def enumerate_7z(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
    """Read a 7z archive and return normalised entries + metadata.

    Args:
        file_path: The archive. Opened read-only; nothing is extracted.

    Returns:
        ``(entries, meta)``. An empty entry list with
        ``meta.header_encrypted`` set is a result rather than a failure:
        a 7z archive can encrypt its central header, so the member list
        itself is unavailable without the password.

    ``PasswordRequired`` is caught separately from the other failures
    precisely so that distinction survives. Folding it into the general
    handler would record "could not open" for an archive whose refusal
    to open is itself the finding.
    """
    meta = ContainerMeta(detected_format="7z")
    entries: list[ArchiveEntry] = []

    try:
        import py7zr  # noqa: PLC0415
    except ImportError:
        meta.handler_errors.append({"stage": "enumerate_7z", "error": "py7zr not installed"})
        return entries, meta

    try:
        sz = py7zr.SevenZipFile(file_path, mode="r")
    except py7zr.PasswordRequired:
        meta.header_encrypted = True
        return entries, meta
    except (py7zr.Bad7zFile, OSError) as exc:
        meta.handler_errors.append({"stage": "enumerate_7z", "error": f"{type(exc).__name__}: {exc}"})
        return entries, meta
    except Exception as exc:  # noqa: BLE001
        meta.handler_errors.append({"stage": "enumerate_7z", "error": f"{type(exc).__name__}: {exc}"})
        return entries, meta

    try:
        infos = sz.list()
    except Exception as exc:  # noqa: BLE001
        meta.handler_errors.append({"stage": "enumerate_7z", "error": f"list failed: {exc}"})
        sz.close()
        return entries, meta

    try:
        needs_pw = bool(sz.password_protected)
    except Exception:  # noqa: BLE001
        needs_pw = False

    for info in infos:
        entries.append(_to_entry(info, needs_pw))

    sz.close()
    return entries, meta


def _to_entry(info, encrypted_fallback: bool) -> ArchiveEntry:
    """Normalise one py7zr file-info record into an :class:`ArchiveEntry`.

    Args:
        info:               The record as py7zr parsed it. Untyped
                            because py7zr is an optional import.
        encrypted_fallback: Whether the archive as a whole is
                            password-protected.

    Returns:
        The normalised entry. ``member_index`` is left unset — nothing
        in the 7z path can address a member by index anyway, since
        extraction goes through ``extractall``.

    ``is_encrypted`` is the conjunction described in the module
    docstring: a missing CRC only means encrypted in an archive that is
    password-protected, and password protection only implicates the
    members whose CRC is absent.

    ``timestamp`` comes from ``creationtime``, which is the field py7zr
    populates as a datetime — on 1.1.0 ``lastwritetime`` comes back as a
    string. It is converted with ``datetime.timestamp()`` rather than
    ``time.mktime(...timetuple())``: py7zr returns an aware UTC value,
    ``timetuple()`` throws the tzinfo away, and ``mktime`` then reads the
    result as local time. That silently shifted every 7z member by the
    host's offset.
    """
    # datetime.timestamp(), not time.mktime(timetuple()). py7zr hands back
    # an aware UTC datetime; timetuple() discards the tzinfo and mktime
    # then reads the naive result as local time, so every member's time
    # was wrong by the host's offset — measured at exactly 32400s under
    # TZ=Asia/Tokyo. A report's timestamps are evidence, and being
    # uniformly wrong is worse than being absent because nothing in the
    # output says so.
    try:
        ts = int(info.creationtime.timestamp()) if info.creationtime else None
    except (ValueError, TypeError, OverflowError, AttributeError, OSError):
        ts = None
    return ArchiveEntry(
        name=info.filename,
        size_compressed=getattr(info, "compressed", 0) or 0,
        size_uncompressed=getattr(info, "uncompressed", 0) or 0,
        # Archive-level, because py7zr gives nothing per-member to refine
        # it with. The previous test also required a missing CRC, which
        # was vacuous twice over: the attribute is spelled `crc32`, so
        # `crc` was always absent and the condition always held. Reading
        # the real field would have inverted the test rather than fixed
        # it — measured against py7zr 1.1.0, an encrypted member carries
        # the same crc32 as the same bytes stored unencrypted, and the
        # entries that report None are the directories.
        is_encrypted=bool(encrypted_fallback),
        is_symlink=False,
        timestamp=ts,
        method=None,
        crc=getattr(info, "crc32", None),
    )


def extract_members_to_temp(
    file_path: Path,
    entries: list[ArchiveEntry],
    tmp_dir: Path,
    max_total_bytes: int,
) -> None:
    """Extract the whole archive into ``tmp_dir``, or none of it.

    Args:
        file_path:       The archive.
        entries:         Members, used for the pre-flight sum and then
                         mapped to their extracted files.
        tmp_dir:         Destination, owned and removed by the caller.
        max_total_bytes: Ceiling for the archive's total uncompressed
                         size.

    Returns:
        None. ``entry.extracted_path`` is populated by
        :func:`_map_extracted_paths` afterwards.

    py7zr offers no per-member read, so the usual running counter is
    impossible — by the time a member could be counted it is already on
    disk. The budget is therefore enforced as a single decision before
    the call, and an archive over it yields no extracted bytes at all
    rather than a partial set. Metadata analysis is unaffected, which is
    what keeps that acceptable.

    Every member counts toward the sum, encrypted ones included. Since
    py7zr reports encryption only for the archive as a whole, excluding
    them made the sum 0 for any password-protected archive and let it
    past the budget entirely.
    """
    try:
        import py7zr  # noqa: PLC0415
    except ImportError:
        return

    # Pre-flight check — abort if total uncompressed would exceed the
    # budget. Every member counts, including the encrypted ones.
    # Excluding them looked harmless and was a bypass: py7zr describes
    # encryption only at archive level, so every member of a
    # password-protected archive reads as encrypted and the sum collapsed
    # to 0, which passes any budget. extractall then ran unbounded and
    # decompressed whatever was not actually encrypted before failing on
    # whatever was. Nothing here can tell the two apart, so refusing a
    # fully-encrypted archive on its declared size is the right trade —
    # extracting it without the password would have failed regardless.
    total = sum(e.size_uncompressed for e in entries)
    if total > max_total_bytes:
        return

    try:
        sz = py7zr.SevenZipFile(file_path, mode="r")
    except Exception:  # noqa: BLE001
        return

    try:
        sz.extractall(path=str(tmp_dir))
    except Exception as exc:  # noqa: BLE001
        logger.debug("7z extractall failed: %s", exc)
        sz.close()
        return
    sz.close()

    _map_extracted_paths(entries, tmp_dir)


_MAX_MAPPED_MEMBER_BYTES = 50 * 1024 * 1024


def _map_extracted_paths(entries: list[ArchiveEntry], tmp_dir: Path) -> None:
    """Point each entry at its extracted file, refusing anything outside.

    Used by the extractors that hand the whole archive to an external tool
    (py7zr's ``extractall``, ``cabextract``) and then have to work out where
    each member landed.

    Args:
        entries: Members to map. ``extracted_path`` is set in place.
        tmp_dir: The scratch directory the extractor wrote into.

    Design notes:
        ``tmp_dir / e.name`` is not safe on its own. The member name is
        attacker-controlled, so ``../secret`` resolves outside the scratch
        directory entirely, and the file it then names is not the extracted
        member but whatever happens to sit at that path.

        Refusing such a name outright is not the answer either, and was a
        bug in the first version of this function: py7zr and cabextract
        *sanitise* traversal on write, so ``../malware.exe`` is really
        extracted as ``tmp_dir/malware.exe``. Refusing to map it left the
        payload on disk and unexamined — prefixing ``../`` would have been
        a one-token way to skip 7z and CAB scanning entirely. Raised by
        Gemini.

        So each candidate is tried in the order the extractor might have
        written it — the full relative path first, then the flattened
        basename the sanitiser would produce — and every candidate must
        still resolve inside ``tmp_dir``. Containment is enforced on the
        resolved path, not on the name, so a symlink planted in the scratch
        directory cannot redirect the read either.
    """
    try:
        root = tmp_dir.resolve(strict=False)
    except (OSError, RuntimeError):
        return

    # One on-disk file may be claimed by one entry only. extractall writes a
    # duplicate name over its predecessor, so without this both entries would
    # point at the survivor and the report would show the overwritten member
    # as analysed when its bytes no longer exist.
    claimed: set[str] = set()

    # Two passes, and the split matters. Every member first tries only its
    # most likely destination; the fallback spellings are tried afterwards,
    # for members still unplaced.
    #
    # Mixing the two in one pass let a fallback outrank a primary. With
    # members `evil.exe` and `nested/../evil.exe`, the latter's third
    # candidate resolves to tmp_dir/evil.exe — which is the former's *only*
    # candidate. Whichever ran first took it, so the payload was attributed
    # to the wrong member and the other was orphaned and falsely reported as
    # overwritten. Raised by Gemini.
    #
    # Within each pass the walk is reversed: when two members genuinely
    # share a destination the extractor wrote the later one last, so the
    # bytes on disk are the last writer's and the earlier record is the one
    # that was really lost.
    for primary_only in (True, False):
        for e in reversed(entries):
            if e.is_encrypted or e.extracted_path:
                continue
            candidates = list(_candidate_paths(tmp_dir, e.name))
            for candidate in candidates[:1] if primary_only else candidates[1:]:
                try:
                    resolved = candidate.resolve(strict=False)
                    resolved.relative_to(root)
                except (ValueError, OSError, RuntimeError):
                    # ValueError from relative_to means the path left
                    # tmp_dir. RuntimeError is resolve() hitting a symlink
                    # loop before Python 3.13 — an archive can plant one,
                    # and leaving it uncaught would kill the pipeline
                    # against design rule 2.
                    continue
                if not (
                    resolved.is_file()
                    and resolved.stat().st_size <= _MAX_MAPPED_MEMBER_BYTES
                ):
                    continue
                key = str(resolved)
                if key in claimed:
                    # continue, not break: a claimed candidate means this
                    # spelling collided, not that the member is gone. The
                    # real file may still sit at a later candidate.
                    continue
                claimed.add(key)
                e.extracted_path = key
                break

    for e in entries:
        if not e.is_encrypted and not e.extracted_path:
            logger.debug("no unclaimed extracted file found for %s", e.name)


def _candidate_paths(tmp_dir: Path, name: str):
    """Yield the places an extractor may have written ``name``, in order.

    Ordered by what the extractor most likely produced, not by how the name
    was spelled: py7zr and cabextract strip the drive letter, the absolute
    root and any traversal while keeping the rest of the tree, so
    ``nested/../evil.exe`` really lands at ``nested/evil.exe``. Probing the
    raw name first got that backwards — it resolves out to
    ``tmp_dir/evil.exe``, a different and possibly unrelated file. For an
    ordinary member every form is identical, so the ordering costs nothing.

    The basename is included here, unlike in the collision indicator: this
    function has to *find* a file whose tree may have been rewritten, while
    the indicator would be asserting that two members target the same one.

    Shares its canonicalisation with ``detect_duplicate_member_names`` via
    ``entries.member_destinations``. They were separate once and drifted
    repeatedly, and every drift was a hole: a payload the mapper could not
    place was also a collision the indicator failed to report.
    """
    for rel in member_destinations(name, include_basename=True):
        yield tmp_dir / rel
