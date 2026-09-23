"""RAR handler — ``rarfile`` library + system ``unrar`` binary.

``rarfile`` is a thin Python wrapper around the system ``unrar`` tool.
Without ``unrar`` on PATH we can still enumerate header-level metadata
(names, sizes, encryption flags) but cannot extract.

Design notes
------------
Two capabilities with different dependencies, and the split matters.
Enumeration needs only ``rarfile`` reading headers; extraction needs the
``unrar`` binary as well. A host with the library and no binary still
produces names, sizes, encryption flags and the ADS recovery below —
which is most of what scores a RAR — so the module degrades to
metadata-only rather than skipping, per design rule 2.

Every member name is read twice, by ``rarfile`` and again by
`rar_raw_headers`. That is not redundancy: ``rarfile`` strips NTFS
Alternate Data Stream suffixes before exposing a name, and CVE-2025-8088
hides its entire drop path in one. The library's sanitised view and the
raw view are both needed — the first to extract with, the second to
judge.

The enrichment is all-or-nothing. If the raw walk and ``rarfile`` report
different member counts, every suffix is discarded rather than paired by
position, because a suffix attached to the wrong member is a false
accusation against one file and a clean bill for the real payload.

Header encryption is decided twice because RAR5 can express it two ways:
an archive that lists members but refuses their contents, and one that
refuses the listing itself. The second only surfaces as an exception
from ``infolist()``, so the flag is set there too.

The broad ``except Exception`` clauses are required rather than lazy.
``rarfile`` raises its own exception hierarchy, ``unrar`` failures
surface as subprocess errors, and a malformed archive can produce either
— design rule 2 forbids any of it reaching the pipeline.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta
from .rar_raw_headers import parse_rar_filenames
from .zip_handler import _locate

logger = logging.getLogger(__name__)


def enumerate_rar(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
    """Read a RAR and return normalised entries + container metadata.

    Args:
        file_path: The archive. Opened read-only; nothing is extracted.

    Returns:
        ``(entries, meta)``. An entry list may be empty with
        ``meta.header_encrypted`` set — that is a result, not a failure,
        and the scoring engine treats it as one.

    A missing ``rarfile`` is a recorded handler error rather than a
    raise, as is a multi-volume archive whose first volume is absent:
    both mean this file cannot be listed, which the report should say
    rather than the pipeline discovering it.

    Raw-name enrichment runs last, after the entry list is final, since
    it pairs against that list by position and by count.
    """
    meta = ContainerMeta(detected_format="rar")
    entries: list[ArchiveEntry] = []

    try:
        import rarfile  # noqa: PLC0415
    except ImportError:
        meta.handler_errors.append({"stage": "enumerate_rar", "error": "rarfile not installed"})
        return entries, meta

    try:
        rf = rarfile.RarFile(file_path)
    except rarfile.NeedFirstVolume as exc:
        meta.handler_errors.append({"stage": "enumerate_rar", "error": f"need first volume: {exc}"})
        return entries, meta
    except rarfile.BadRarFile as exc:
        meta.handler_errors.append({"stage": "enumerate_rar", "error": f"BadRarFile: {exc}"})
        return entries, meta
    except Exception as exc:  # noqa: BLE001
        meta.handler_errors.append({"stage": "enumerate_rar", "error": f"{type(exc).__name__}: {exc}"})
        return entries, meta

    # First of the two header-encryption tests: the archive admits it
    # needs a password AND yields no members. Both halves are required —
    # `needs_password()` alone is also true for an archive whose *names*
    # are readable and whose contents are not, which is ordinary
    # encryption and already covered by the per-entry flag.
    try:
        # Header encryption: whole-archive listing requires a password.
        meta.header_encrypted = bool(getattr(rf, "needs_password", lambda: False)()) and \
                                not rf.infolist()
    except Exception:  # noqa: BLE001
        meta.header_encrypted = False

    try:
        comment = getattr(rf, "comment", "") or ""
        if isinstance(comment, bytes):
            comment = comment.decode("utf-8", errors="replace")
        meta.comment = comment
    except Exception:  # noqa: BLE001
        meta.comment = ""

    # Second test. A RAR5 archive with encrypted headers cannot be listed
    # at all and raises here instead of returning an empty list, so the
    # flag has to be set on this path too or a header-encrypted archive
    # would be reported as merely unreadable.
    try:
        infos = rf.infolist()
    except Exception as exc:  # noqa: BLE001
        # Header-encrypted RAR5 raises on infolist() without a password.
        meta.header_encrypted = True
        meta.handler_errors.append({"stage": "enumerate_rar", "error": f"infolist failed: {exc}"})
        return entries, meta

    for idx, info in enumerate(infos):
        entry = _to_entry(info)
        entry.member_index = idx
        entries.append(entry)

    # CVE-2025-8088 recovery: ``rarfile`` strips NTFS ADS suffixes from
    # member names. Walk the raw headers and re-attach the unsanitised
    # form so downstream indicators see the traversal payload.
    _attach_raw_names(file_path, entries)

    return entries, meta


def _attach_raw_names(file_path: Path, entries: list[ArchiveEntry]) -> None:
    """Re-attach the unsanitised member names ``rarfile`` stripped.

    Args:
        file_path: The archive, re-read by the raw header walker.
        entries:   The entry list from ``rarfile``, modified in place.

    Returns:
        None. ``entry.raw_name`` is populated where the two views differ.

    This is the CVE-2025-8088 recovery path. ``rarfile`` reports
    ``fiyat teklifi.pdf``; the archive actually says
    ``fiyat teklifi.pdf:..\\..\\AppData\\...\\Startup\\Updater.exe``,
    and the traversal indicator can only fire on the second. Both
    ``detect_path_traversal`` and ``detect_persistence_paths`` inspect
    ``name`` and ``raw_name``, which is what makes attaching it enough.

    Pairing is positional, so a count disagreement between the two
    parsers abandons the whole enrichment. That is deliberate and it is
    not conservatism for its own sake: a mismatch means the raw walker
    and ``rarfile`` disagree about what the records *are*, and pairing
    across that disagreement would attach a traversal payload to an
    innocent member while leaving the real one clean. The common cause
    is an archive past the raw parser's 64 MiB read cap.
    """
    raw = parse_rar_filenames(file_path)
    if not raw or len(raw) != len(entries):
        # Index-mismatch means the raw parser saw a different record
        # count than ``rarfile`` — safer to skip enrichment entirely
        # than to attach the wrong suffix.
        if raw and len(raw) != len(entries):
            logger.debug(
                "rar raw/rarfile count mismatch for %s (raw=%d, rarfile=%d) — skipping ADS attach",
                file_path, len(raw), len(entries),
            )
        return
    for entry, rec in zip(entries, raw):
        suffix = rec.get("ads_suffix")
        raw_name = rec.get("name")
        if suffix:
            # Compose so the path-traversal check sees the full string
            # (the leading colon plus traversal sequence is what fires
            # the indicator). Keep the benign base name in ``.name``.
            entry.raw_name = f"{raw_name}{suffix if suffix.startswith(':') else ':' + suffix}"
        elif raw_name and raw_name != entry.name:
            entry.raw_name = raw_name


def _to_entry(info) -> ArchiveEntry:  # RarInfo
    """Normalise one ``RarInfo`` into an :class:`ArchiveEntry`.

    Args:
        info: The record as ``rarfile`` parsed it. Untyped because
              ``rarfile`` is an optional import and annotating it here
              would make the module fail to load without it.

    Returns:
        The normalised entry, with ``member_index`` left for the caller.

    Almost every field is read through ``getattr`` with a default. That
    is not defensive habit: ``RarInfo`` genuinely differs between RAR4
    and RAR5 archives and across ``rarfile`` versions — ``is_symlink``
    and ``needs_password`` are methods on some and absent on others —
    so an attribute that exists for one sample is missing for the next.
    The encryption fallback reads the RAR4 header flag directly for the
    same reason.
    """
    try:
        ts = int(time.mktime(info.date_time + (0, 0, -1)))
    except (ValueError, TypeError, OverflowError, AttributeError):
        ts = None
    # rarfile exposes .needs_password() on individual members (RAR5).
    try:
        encrypted = bool(info.needs_password())
    except Exception:  # noqa: BLE001
        encrypted = bool(getattr(info, "flags", 0) & 0x04)
    return ArchiveEntry(
        name=info.filename,
        size_compressed=getattr(info, "compress_size", 0) or 0,
        size_uncompressed=getattr(info, "file_size", 0) or 0,
        is_encrypted=encrypted,
        is_symlink=bool(getattr(info, "is_symlink", lambda: False)()) if callable(getattr(info, "is_symlink", None)) else False,
        timestamp=ts,
        method=str(getattr(info, "compress_type", "")) or None,
        crc=getattr(info, "CRC", None),
    )


def extract_members_to_temp(
    file_path: Path,
    entries: list[ArchiveEntry],
    tmp_dir: Path,
    max_total_bytes: int,
) -> None:
    """Extract bounded, non-encrypted members into ``tmp_dir``.

    Args:
        file_path:       The archive.
        entries:         Members to consider, carrying ``member_index``.
        tmp_dir:         Destination, owned and removed by the caller.
        max_total_bytes: Cumulative ceiling for this call.

    Returns:
        None. ``entry.extracted_path`` is populated in place.

    Unlike enumeration this needs the ``unrar`` binary, since ``rarfile``
    shells out to it to decompress. Its absence is a silent return: the
    entries keep their metadata and simply gain no extracted bytes,
    which the downstream checks already treat as "nothing to look at".

    Member names are rewritten to ``m_NNNN_<basename>``. For this format
    that is doing more work than elsewhere — a RAR member name here may
    carry a traversal payload in an ADS suffix, and reducing it to an
    indexed leaf under ``tmp_dir`` is what keeps the analysis from
    performing the attack it is trying to detect.
    """
    try:
        import rarfile  # noqa: PLC0415
    except ImportError:
        return

    try:
        rf = rarfile.RarFile(file_path)
    except Exception:  # noqa: BLE001
        return

    written = 0

    # Addressed by RarInfo rather than by name, for the same reason as the
    # ZIP and TAR extractors: a name resolves to one record, so duplicates
    # were read repeatedly while their siblings were never opened. The
    # record is found via the index the enumerator stored, not by position
    # in this loop — a filtered entries list would misalign a positional
    # pairing without any error.
    # Monotonic counter, not a directory listing per member: the old form
    # re-read tmp_dir once per entry, making naming O(n^2) in member count.
    index = 0
    with rf:
        # Inside the with-block: returning from a failed infolist() before
        # entering it skipped rf.close() and leaked the handle, which over a
        # triage run across malformed archives exhausts the descriptor limit.
        # Raised by Gemini.
        try:
            infos = rf.infolist()
        except Exception as exc:  # noqa: BLE001
            logger.debug("rar infolist failed during extract: %s", exc)
            return

        for e in entries:
            if e.is_encrypted or e.is_symlink:
                continue
            info = _locate(e, infos)
            if info is None:
                continue
            if e.size_uncompressed <= 0 or e.size_uncompressed > 50 * 1024 * 1024:
                continue
            if written + e.size_uncompressed > max_total_bytes:
                break
            safe_name = f"m_{index:04d}_{Path(e.name).name[:80]}"
            out_path = tmp_dir / safe_name
            try:
                with rf.open(info) as src, out_path.open("wb") as dst:
                    dst.write(src.read())
            except Exception as exc:  # noqa: BLE001
                logger.debug("rar extract skipped for %s: %s", e.name, exc)
                continue
            e.extracted_path = str(out_path)
            written += e.size_uncompressed
            index += 1
