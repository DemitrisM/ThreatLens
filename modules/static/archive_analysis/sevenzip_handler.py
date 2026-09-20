"""7z handler — ``py7zr`` (pure-Python).

7z archives can encrypt the central header so member listings are
unavailable without the password. We flag that as ``header_encrypted``
and return early.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta, member_destinations

logger = logging.getLogger(__name__)


def enumerate_7z(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
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
    try:
        ts = int(time.mktime(info.creationtime.timetuple())) if info.creationtime else None
    except (ValueError, TypeError, OverflowError, AttributeError):
        ts = None
    return ArchiveEntry(
        name=info.filename,
        size_compressed=getattr(info, "compressed", 0) or 0,
        size_uncompressed=getattr(info, "uncompressed", 0) or 0,
        is_encrypted=bool(getattr(info, "crc", None) is None and encrypted_fallback),
        is_symlink=False,
        timestamp=ts,
        method=None,
        crc=getattr(info, "crc", None),
    )


def extract_members_to_temp(
    file_path: Path,
    entries: list[ArchiveEntry],
    tmp_dir: Path,
    max_total_bytes: int,
) -> None:
    """py7zr requires extracting the whole archive at once; we do so into
    ``tmp_dir`` but cap the total via a pre-flight size sum."""
    try:
        import py7zr  # noqa: PLC0415
    except ImportError:
        return

    # Pre-flight check — abort if total uncompressed would exceed the budget.
    total = sum(e.size_uncompressed for e in entries if not e.is_encrypted)
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
