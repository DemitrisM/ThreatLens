"""TAR / GZIP / BZIP2 / XZ handler.

``tarfile.open(mode="r:*")`` auto-detects compression. Standalone
``.gz`` / ``.bz2`` / ``.xz`` (no tar inside) are treated as single-file
streams: we decompress a bounded prefix and emit one pseudo-entry so
that downstream indicators (MIME check, dangerous extension) still
fire on the inner payload.
"""

from __future__ import annotations

import bz2
import gzip
import logging
import lzma
import tarfile
import time
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta

logger = logging.getLogger(__name__)

_INNER_STREAM_CAP = 64 * 1024 * 1024  # 64 MiB peek for single-stream gz/bz2/xz


def enumerate_tar(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
    meta = ContainerMeta(detected_format="tar")
    entries: list[ArchiveEntry] = []
    try:
        with tarfile.open(file_path, mode="r:*") as tf:
            for member in tf.getmembers():
                entries.append(_to_entry(member))
    except (tarfile.TarError, OSError, EOFError) as exc:
        meta.handler_errors.append({"stage": "enumerate_tar", "error": f"{type(exc).__name__}: {exc}"})
    return entries, meta


def _to_entry(member: tarfile.TarInfo) -> ArchiveEntry:
    return ArchiveEntry(
        name=member.name,
        size_compressed=member.size,        # tar has no per-entry compression
        size_uncompressed=member.size,
        is_encrypted=False,
        is_symlink=member.issym() or member.islnk(),
        symlink_target=member.linkname or None,
        timestamp=int(member.mtime) if member.mtime else None,
        method=None,
    )


def extract_tar_members_to_temp(
    file_path: Path,
    entries: list[ArchiveEntry],
    tmp_dir: Path,
    max_total_bytes: int,
) -> None:
    written = 0
    try:
        tf = tarfile.open(file_path, mode="r:*")
    except (tarfile.TarError, OSError):
        return
    with tf:
        for e in entries:
            if e.is_symlink:
                continue
            if e.size_uncompressed <= 0 or e.size_uncompressed > 50 * 1024 * 1024:
                continue
            if written + e.size_uncompressed > max_total_bytes:
                break
            try:
                src = tf.extractfile(e.name)
                if src is None:
                    continue
                data = src.read(e.size_uncompressed)
            except (tarfile.TarError, OSError):
                continue
            safe_name = f"m_{len(list(tmp_dir.iterdir())):04d}_{Path(e.name).name[:80]}"
            out_path = tmp_dir / safe_name
            try:
                out_path.write_bytes(data)
            except OSError:
                continue
            e.extracted_path = str(out_path)
            written += e.size_uncompressed


# ---------------------------------------------------------------------------
# Single-stream gz / bz2 / xz (no tar inside)
# ---------------------------------------------------------------------------

def enumerate_single_stream(
    file_path: Path, fmt: str, tmp_dir: Path | None,
) -> tuple[list[ArchiveEntry], ContainerMeta]:
    """Emit a single pseudo-entry representing the decompressed payload.

    Writes the decompressed bytes into ``tmp_dir`` (when provided) so
    downstream MIME / embedded-PE checks can run.
    """
    meta = ContainerMeta(detected_format=fmt)
    entries: list[ArchiveEntry] = []

    opener = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}.get(fmt)
    if opener is None:
        return entries, meta

    inner_name = file_path.stem or f"inner.{fmt}"
    extracted_path: str | None = None

    try:
        with opener(file_path, "rb") as src:
            payload = src.read(_INNER_STREAM_CAP + 1)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        meta.handler_errors.append({"stage": "single_stream_read", "error": str(exc)})
        return entries, meta

    if tmp_dir is not None and payload:
        truncated = payload[:_INNER_STREAM_CAP]
        out_path = tmp_dir / f"inner_{inner_name}"
        try:
            out_path.write_bytes(truncated)
            extracted_path = str(out_path)
        except OSError as exc:
            meta.handler_errors.append({"stage": "single_stream_write", "error": str(exc)})

    try:
        ts = int(file_path.stat().st_mtime)
    except OSError:
        ts = int(time.time())

    entries.append(ArchiveEntry(
        name=inner_name,
        size_compressed=file_path.stat().st_size,
        size_uncompressed=len(payload),
        is_encrypted=False,
        is_symlink=False,
        timestamp=ts,
        method=fmt,
        extracted_path=extracted_path,
    ))
    return entries, meta
