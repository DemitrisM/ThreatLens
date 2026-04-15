"""Hash any extracted member that is itself a PE / ELF / Mach-O.

The orchestrator passes only entries that were actually materialised to
disk (``extracted_path`` populated). We use ``python-magic`` to confirm
the bytes really are an executable (extension is not enough — the
mime_mismatch indicator already covers that), then hash with MD5+SHA256.

The SHA256 is what ``virustotal.py`` later forwards to the VT API.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from .entries import ArchiveEntry

logger = logging.getLogger(__name__)


_EXEC_MIME_TO_TYPE: dict[str, str] = {
    "application/x-dosexec":     "PE",
    "application/vnd.microsoft.portable-executable": "PE",
    "application/x-executable":  "ELF",
    "application/x-sharedlib":   "ELF",
    "application/x-mach-binary": "MachO",
}

_CHUNK = 4 * 1024 * 1024


def hash_embedded_executables(
    entries: list[ArchiveEntry],
    max_member_size: int = 50 * 1024 * 1024,
) -> list[dict]:
    """Return a list of ``{name, md5, sha256, size, type}`` for each
    extracted member that libmagic identifies as a native executable."""
    try:
        import magic  # noqa: PLC0415
    except ImportError:
        logger.debug("python-magic not available — embedded-exec hashing skipped")
        return []

    out: list[dict] = []
    for e in entries:
        if not e.extracted_path:
            continue
        path = Path(e.extracted_path)
        if not path.is_file():
            continue
        try:
            stat_size = path.stat().st_size
        except OSError:
            continue
        if stat_size <= 0 or stat_size > max_member_size:
            continue

        try:
            mime = magic.from_file(str(path), mime=True)
        except Exception as exc:  # noqa: BLE001
            logger.debug("magic.from_file failed for %s: %s", path, exc)
            continue

        exec_type = _classify_exec(mime, path)
        if exec_type is None:
            continue

        digests = _hash_file(path)
        if digests is None:
            continue
        md5, sha256 = digests

        out.append({
            "name": e.name,
            "md5": md5,
            "sha256": sha256,
            "size": stat_size,
            "type": exec_type,
        })
    return out


def _classify_exec(mime: str | None, path: Path) -> str | None:
    """Return the exec type label, refining PE → PE32 / PE32+ when possible."""
    if mime is None:
        return None
    base = _EXEC_MIME_TO_TYPE.get(mime)
    if base is None:
        return None
    if base != "PE":
        return base
    return _pe_bitness(path) or "PE32"


def _pe_bitness(path: Path) -> str | None:
    """Read the PE optional-header magic to distinguish PE32 vs PE32+."""
    try:
        with path.open("rb") as fh:
            head = fh.read(0x100)
    except OSError:
        return None
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    try:
        e_lfanew = int.from_bytes(head[0x3c:0x40], "little")
    except ValueError:
        return None
    try:
        with path.open("rb") as fh:
            fh.seek(e_lfanew)
            pe_head = fh.read(0x80)
    except OSError:
        return None
    if len(pe_head) < 0x1a or pe_head[:4] != b"PE\x00\x00":
        return None
    opt_magic = int.from_bytes(pe_head[0x18:0x1a], "little")
    if opt_magic == 0x10b:
        return "PE32"
    if opt_magic == 0x20b:
        return "PE32+"
    return None


def _hash_file(path: Path) -> tuple[str, str] | None:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                md5.update(chunk)
                sha.update(chunk)
    except OSError as exc:
        logger.debug("Hash read failed for %s: %s", path, exc)
        return None
    return md5.hexdigest(), sha.hexdigest()
