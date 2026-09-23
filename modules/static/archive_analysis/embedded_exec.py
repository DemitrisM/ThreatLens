"""Hash any extracted member that is itself a PE / ELF / Mach-O.

The orchestrator passes only entries that were actually materialised to
disk (``extracted_path`` populated). We use ``python-magic`` to confirm
the bytes really are an executable (extension is not enough — the
mime_mismatch indicator already covers that), then hash with MD5+SHA256.

The SHA256 is what ``virustotal.py`` later forwards to the VT API.

Design notes
------------
This module's reach is bounded by what extraction actually wrote, not by
what the archive contains. It looks only at entries carrying an
``extracted_path``, so an encrypted, oversize or skipped member is
invisible here by construction. That is the correct coupling — hashing
something requires its bytes — but it means a gap in extraction is
silently a gap in VirusTotal coverage, and the two have to be read
together.

Identification is by content, never by extension. A member named
``invoice.pdf`` that libmagic types as a PE is hashed and forwarded; a
member named ``setup.exe`` that is really a text file is not. The
extension side of that question is already answered separately by the
``mime_mismatch`` indicator, and answering it twice here would double
the weight of one observation.

ELF and Mach-O are recognised and hashed even though the tool is
Windows-focused and does not analyse them. A hash lookup needs no
platform support and a Linux payload inside a Windows-delivered archive
is worth reporting, so the cheap half is kept and the scope exclusion
applies only to the analysis this module does not do.

Every failure is a `continue`, never a raise: one unreadable member must
not cost the scan the hashes of the others.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from .entries import ArchiveEntry

logger = logging.getLogger(__name__)


# libmagic reports two different MIME types for a PE depending on its
# version — the older `application/x-dosexec` and the IANA-registered
# `application/vnd.microsoft.portable-executable` — so both are mapped
# rather than relying on whichever the host happens to ship.
_EXEC_MIME_TO_TYPE: dict[str, str] = {
    "application/x-dosexec":     "PE",
    "application/vnd.microsoft.portable-executable": "PE",
    "application/x-executable":  "ELF",
    # Distributions have built executables position-independent by
    # default for years, and libmagic gives those their own type. Without
    # it the common case of a modern Linux binary was typed as "not an
    # executable" and never hashed. /usr/bin/ls on this machine reports
    # x-pie-executable.
    "application/x-pie-executable": "ELF",
    # A PIE executable is structurally a shared object, so older libmagic
    # builds report the same file this way instead. Both spellings map to
    # the same label because the distinction is not one a report can act
    # on.
    "application/x-sharedlib":   "ELF",
    "application/x-mach-binary": "MachO",
}

# Hashing reads in 4 MiB chunks rather than whole-file. A member can be
# up to `max_member_size`, and a triage run hashes many of them, so the
# peak matters more than the syscall count.
_CHUNK = 4 * 1024 * 1024


def hash_embedded_executables(
    entries: list[ArchiveEntry],
    max_member_size: int = 50 * 1024 * 1024,
) -> list[dict]:
    """Hash every extracted member that is really a native executable.

    Args:
        entries:         Enumerated members. Only those with an
                         ``extracted_path`` that still exists are
                         considered; the rest are skipped silently.
        max_member_size: Per-member ceiling in bytes. Defaults to 50 MiB,
                         matching the cap the extractors apply, so this
                         is a second line rather than the binding one.

    Returns:
        One ``{name, md5, sha256, size, type}`` dict per executable
        found, in entry order. An empty list when python-magic is
        missing — a skip, not an error, per design rule 2.

    ``name`` is the in-archive member name rather than the temp path, so
    the report names something the analyst can find in the original
    archive after the tempdir is gone.
    """
    # Imported inside the function so a missing optional dependency costs
    # this one capability rather than the package's import.
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
        # Size is re-read from disk rather than trusted from the entry.
        # `size_uncompressed` is what the archive *declared*; this is what
        # was actually written, and a hash of bytes that are not there is
        # worse than no hash. A zero-length file is skipped because its
        # SHA256 is a constant that matches every empty file on VT.
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
    """Return the exec type label, refining PE to PE32 / PE32+.

    Args:
        mime: The MIME string libmagic reported, or None.
        path: The extracted file, read only when the MIME says PE.

    Returns:
        ``"PE32"``, ``"PE32+"``, ``"ELF"``, ``"MachO"``, or None when the
        MIME is not an executable this module recognises.

    The bitness refinement falls back to ``"PE32"`` rather than None when
    the header cannot be read: at that point libmagic has already
    confirmed the file is a PE, so declining to label it would discard a
    confirmed identification over a cosmetic detail.
    """
    if mime is None:
        return None
    base = _EXEC_MIME_TO_TYPE.get(mime)
    if base is None:
        return None
    if base != "PE":
        return base
    return _pe_bitness(path) or "PE32"


def _pe_bitness(path: Path) -> str | None:
    """Read the PE optional-header magic to distinguish PE32 vs PE32+.

    Args:
        path: The file to inspect.

    Returns:
        ``"PE32"``, ``"PE32+"``, or None if the headers are unreadable or
        malformed.

    Hand-parsed rather than handed to `pefile`, for two reasons. This
    needs two integers out of the first few hundred bytes and `pefile`
    parses the entire structure; and a deliberately malformed PE — which
    is the interesting case in an archive — makes `pefile` raise while
    the two fields this reads are usually still intact.

    Every bounds check returns None rather than raising. `e_lfanew` is
    attacker-controlled, so a seek past EOF is expected input, not an
    error: the read simply comes back short and the length check catches
    it.
    """
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
    """Stream the file once, returning ``(md5, sha256)``.

    Args:
        path: The file to hash.

    Returns:
        The two hex digests, or None if the file could not be read.

    Both digests are computed in the same pass — the read is the
    expensive part, and doing it twice would double the cost of the
    module. SHA256 is what VirusTotal is queried with; MD5 is kept
    because most vendor reports and sandbox exports are still keyed on
    it, so an analyst pasting between tools needs both.
    """
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
