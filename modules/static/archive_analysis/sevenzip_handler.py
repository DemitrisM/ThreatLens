"""7z handler — ``py7zr`` (pure-Python).

7z archives can encrypt the central header so member listings are
unavailable without the password. We flag that as ``header_encrypted``
and return early.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta

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

    # Map extracted paths back onto entries.
    for e in entries:
        if e.is_encrypted:
            continue
        candidate = tmp_dir / e.name
        if candidate.is_file() and candidate.stat().st_size <= 50 * 1024 * 1024:
            e.extracted_path = str(candidate)
