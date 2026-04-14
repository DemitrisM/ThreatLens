"""RAR handler — ``rarfile`` library + system ``unrar`` binary.

``rarfile`` is a thin Python wrapper around the system ``unrar`` tool.
Without ``unrar`` on PATH we can still enumerate header-level metadata
(names, sizes, encryption flags) but cannot extract.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta

logger = logging.getLogger(__name__)


def enumerate_rar(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
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

    try:
        infos = rf.infolist()
    except Exception as exc:  # noqa: BLE001
        # Header-encrypted RAR5 raises on infolist() without a password.
        meta.header_encrypted = True
        meta.handler_errors.append({"stage": "enumerate_rar", "error": f"infolist failed: {exc}"})
        return entries, meta

    for info in infos:
        entries.append(_to_entry(info))
    return entries, meta


def _to_entry(info) -> ArchiveEntry:  # RarInfo
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
    try:
        import rarfile  # noqa: PLC0415
    except ImportError:
        return

    try:
        rf = rarfile.RarFile(file_path)
    except Exception:  # noqa: BLE001
        return

    written = 0
    with rf:
        for e in entries:
            if e.is_encrypted or e.is_symlink:
                continue
            if e.size_uncompressed <= 0 or e.size_uncompressed > 50 * 1024 * 1024:
                continue
            if written + e.size_uncompressed > max_total_bytes:
                break
            safe_name = f"m_{len(list(tmp_dir.iterdir())):04d}_{Path(e.name).name[:80]}"
            out_path = tmp_dir / safe_name
            try:
                with rf.open(e.name) as src, out_path.open("wb") as dst:
                    dst.write(src.read())
            except Exception as exc:  # noqa: BLE001
                logger.debug("rar extract skipped for %s: %s", e.name, exc)
                continue
            e.extracted_path = str(out_path)
            written += e.size_uncompressed
