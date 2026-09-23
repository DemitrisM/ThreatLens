"""CAB / ISO / ACE handlers.

* **CAB** — shells out to the system ``cabextract`` binary. Absent
  binary → graceful metadata-only skip.
* **ISO / IMG** — uses ``pycdlib`` when available. Walks Joliet/Rock
  Ridge/ISO9660 records so names are correct under all extensions.
* **ACE** — detection only. No extraction attempted because the format
  (WinACE) is effectively abandoned and the only surviving unace port
  has a history of memory-corruption CVEs (CVE-2018-20250).

Design notes
------------
Three formats with three different dependency models, which is why they
share a file: each is too small to justify its own module and none of
them shares code with the others beyond that shape.

* CAB depends on an **external binary** and is driven by parsing its
  stdout. That makes the parser brittle by nature — it is reading a
  human-readable table, not an API — so every line that does not look
  like a record is skipped rather than treated as an error.
* ISO depends on an **optional library** and is the only format here
  addressed by path rather than by index, which has consequences for
  duplicates noted at the extractor.
* ACE depends on **nothing, deliberately.** It is detected and never
  opened.

**Not extracting ACE is a security decision, not a missing feature.**
The only public parsers have a history of memory-corruption CVEs, and
CVE-2018-20250 is a path traversal in the extraction path itself. A
malware analysis tool that ran an abandoned parser over hostile input
to satisfy a completeness goal would be creating the vulnerability it
exists to find. Detection alone scores the archive, which is the
outcome that matters.

Both shell-outs are timeout-bounded per design rule 5. That is the only
timeout enforcement available at this layer, since the orchestrator's
``module_timeout_seconds`` is still unread — so a hung subprocess here
would hang the whole scan with nothing above it to intervene.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta
from .sevenzip_handler import _map_extracted_paths

logger = logging.getLogger(__name__)

_CABEXTRACT_TIMEOUT = 10  # seconds — list + extract each capped here


# ---------------------------------------------------------------------------
# CAB
# ---------------------------------------------------------------------------

def enumerate_cab(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
    """List a CAB's members by parsing ``cabextract --list`` output.

    Args:
        file_path: The cabinet file.

    Returns:
        ``(entries, meta)``. An absent ``cabextract`` binary is a
        recorded handler error and an empty list, not a raise — the
        scan continues and the report says why the cabinet was not
        listed.

    This parses a human-readable table, so it is tolerant by design: a
    line that does not split into at least three pipe-separated fields,
    or whose first field is not an integer, is skipped rather than
    treated as corruption. The alternative — failing on the first
    unexpected line — would make a future change to cabextract's
    banner, or a member whose name contains a pipe, silently empty the
    listing.

    Sizes are recorded as equal for compressed and uncompressed because
    ``--list`` reports only one figure. The bomb guard's ratio test
    therefore reads 1:1 for every CAB and cannot fire; its size and
    count thresholds still apply.
    """
    meta = ContainerMeta(detected_format="cab")
    entries: list[ArchiveEntry] = []

    if shutil.which("cabextract") is None:
        meta.handler_errors.append({"stage": "enumerate_cab", "error": "cabextract binary not on PATH"})
        return entries, meta

    try:
        proc = subprocess.run(
            ["cabextract", "--list", str(file_path)],
            capture_output=True, text=True, timeout=_CABEXTRACT_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        meta.handler_errors.append({"stage": "enumerate_cab", "error": f"{type(exc).__name__}: {exc}"})
        return entries, meta

    if proc.returncode != 0:
        meta.handler_errors.append({"stage": "enumerate_cab", "error": f"cabextract rc={proc.returncode}: {proc.stderr.strip()[:200]}"})
        return entries, meta

    # cabextract --list output format:
    #   File size | Date       Time     | Name
    #   ----------+---------------------+-------------
    #           123 | 01.01.2024 12:00:00 | file.txt
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("-", "F", "All")) or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue
        try:
            size = int(parts[0])
        except ValueError:
            continue
        name = parts[-1]
        entries.append(ArchiveEntry(
            name=name,
            size_compressed=size,
            size_uncompressed=size,
            is_encrypted=False,
            is_symlink=False,
            method="mszip",  # CAB default
        ))
    return entries, meta


def extract_cab_members_to_temp(
    file_path: Path,
    entries: list[ArchiveEntry],
    tmp_dir: Path,
    max_total_bytes: int,
) -> None:
    """Extract a cabinet into ``tmp_dir``, or not at all.

    Args:
        file_path:       The cabinet.
        entries:         Members, used for the pre-flight sum and then
                         mapped to their extracted files.
        tmp_dir:         Destination, owned and removed by the caller.
        max_total_bytes: Ceiling for the total uncompressed size.

    Returns:
        None. ``entry.extracted_path`` is populated by
        :func:`_map_extracted_paths` afterwards.

    Same all-or-nothing shape as the 7z extractor and for the same
    reason: ``cabextract`` takes a cabinet and a destination, not a
    member, so the budget is a single decision made before the call.

    The return code is deliberately not checked. cabextract reports a
    non-zero status when *any* member fails, including a partial
    extraction that still wrote most of the cabinet, and those files are
    worth analysing. What actually landed is settled by looking at the
    directory rather than by trusting the exit status.
    """
    if shutil.which("cabextract") is None:
        return
    total = sum(e.size_uncompressed for e in entries)
    if total > max_total_bytes:
        return
    try:
        subprocess.run(
            ["cabextract", "-d", str(tmp_dir), "-q", str(file_path)],
            capture_output=True, timeout=_CABEXTRACT_TIMEOUT, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("cabextract extract failed: %s", exc)
        return
    # Same containment rule as the 7z extractor: cabextract sanitises
    # traversal on write, so rebuilding the path from the raw member name
    # would point at something other than the extracted member.
    _map_extracted_paths(entries, tmp_dir)


# ---------------------------------------------------------------------------
# ISO / IMG
# ---------------------------------------------------------------------------

def enumerate_iso(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
    """Walk an ISO 9660 image and list its files.

    Args:
        file_path: The image. ``.iso`` or ``.img``.

    Returns:
        ``(entries, meta)``. A missing ``pycdlib`` is a recorded handler
        error and an empty list.

    One extension is chosen for the whole walk and it has to be the same
    one the extractor uses later, because pycdlib addresses records by
    path and the three namespaces spell the same file differently.
    Joliet is preferred because it carries the long filenames a user
    actually sees — an ISO delivering malware names its payload for the
    victim, and the ISO 9660 8.3 form would report a truncated,
    upper-cased name that matches neither the dangerous-extension list
    nor anything an analyst could search for.

    A record whose size cannot be read contributes 0 rather than being
    dropped. The member's *name* is the part the indicators need, and a
    zero size only excludes it from extraction, which is the safe
    direction for a record the library could not describe.
    """
    meta = ContainerMeta(detected_format="iso")
    entries: list[ArchiveEntry] = []

    try:
        import pycdlib  # noqa: PLC0415
    except ImportError:
        meta.handler_errors.append({"stage": "enumerate_iso", "error": "pycdlib not installed"})
        return entries, meta

    try:
        iso = pycdlib.PyCdlib()
        iso.open(str(file_path))
    except Exception as exc:  # noqa: BLE001
        meta.handler_errors.append({"stage": "enumerate_iso", "error": f"{type(exc).__name__}: {exc}"})
        return entries, meta

    # Prefer Joliet (long filenames), fall back to Rock Ridge, then ISO9660.
    walker_kwargs = {}
    if iso.has_joliet():
        walker_kwargs = {"joliet_path": "/"}
    elif iso.has_rock_ridge():
        walker_kwargs = {"rr_path": "/"}
    else:
        walker_kwargs = {"iso_path": "/"}

    try:
        for dirname, _, files in iso.walk(**walker_kwargs):
            for fname in files:
                full = f"{dirname.rstrip('/')}/{fname}"
                try:
                    record = iso.get_record(**{list(walker_kwargs)[0]: full})
                    size = int(getattr(record, "data_length", 0) or 0)
                except Exception:  # noqa: BLE001
                    size = 0
                entries.append(ArchiveEntry(
                    name=full.lstrip("/"),
                    size_compressed=size,
                    size_uncompressed=size,
                    is_encrypted=False,
                    is_symlink=False,
                    method="iso9660",
                ))
    except Exception as exc:  # noqa: BLE001
        meta.handler_errors.append({"stage": "enumerate_iso_walk", "error": f"{type(exc).__name__}: {exc}"})

    try:
        iso.close()
    except Exception:  # noqa: BLE001
        pass
    return entries, meta


def extract_iso_members_to_temp(
    file_path: Path,
    entries: list[ArchiveEntry],
    tmp_dir: Path,
    max_total_bytes: int,
) -> None:
    """Extract bounded members from an ISO into ``tmp_dir``.

    Args:
        file_path:       The image.
        entries:         Members to consider.
        tmp_dir:         Destination, owned and removed by the caller.
        max_total_bytes: Cumulative ceiling for this call.

    Returns:
        None. ``entry.extracted_path`` is populated in place.

    Unlike 7z and CAB this extracts member by member, so the ordinary
    running counter applies and a partial extraction is normal.

    It is addressed by path, though, because pycdlib exposes no
    index-based read — which is the one thing that makes ISO different
    from ZIP, RAR and TAR here. A repeated path resolves to a single
    record, so the sibling is unreachable rather than merely awkward.
    Claiming each source path once leaves the shadowed member unmapped
    instead of extracting the same record twice under two names, which
    would report a member as analysed using another member's bytes.

    The extension chosen here must match the one
    :func:`enumerate_iso` walked with, since the names in ``entries``
    were produced in that namespace.
    """
    try:
        import pycdlib  # noqa: PLC0415
    except ImportError:
        return

    try:
        iso = pycdlib.PyCdlib()
        iso.open(str(file_path))
    except Exception:  # noqa: BLE001
        return

    use_joliet = iso.has_joliet()
    use_rr = iso.has_rock_ridge()
    written = 0

    # Monotonic counter rather than a directory listing per member — the
    # old form re-read tmp_dir once per entry, making naming O(n^2).
    index = 0
    claimed_sources: set[str] = set()
    try:
        for e in entries:
            if e.size_uncompressed <= 0 or e.size_uncompressed > 50 * 1024 * 1024:
                continue
            if written + e.size_uncompressed > max_total_bytes:
                break
            safe_name = f"m_{index:04d}_{Path(e.name).name[:80]}"
            out_path = tmp_dir / safe_name
            # pycdlib addresses records by path — it exposes no index-based
            # read — so a repeated path resolves to one record and its
            # sibling is unreachable. That is recorded by the duplicate-name
            # indicator (iso is in _OVERWRITING_FORMATS) rather than silently
            # extracting the same record twice under two entries. Raised by
            # Gemini. Claim each source path once so the shadowed member is
            # left unmapped instead of being reported as analysed.
            src_path = "/" + e.name.lstrip("/")
            if src_path in claimed_sources:
                logger.debug("iso source path already extracted: %s", src_path)
                continue
            claimed_sources.add(src_path)
            try:
                kwargs = {"local_path": str(out_path)}
                if use_joliet:
                    kwargs["joliet_path"] = src_path
                elif use_rr:
                    kwargs["rr_path"] = src_path
                else:
                    kwargs["iso_path"] = src_path
                iso.get_file_from_iso(**kwargs)
            except Exception as exc:  # noqa: BLE001
                logger.debug("iso extract skipped for %s: %s", e.name, exc)
                continue
            e.extracted_path = str(out_path)
            written += e.size_uncompressed
            index += 1
    finally:
        try:
            iso.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# ACE — detection only
# ---------------------------------------------------------------------------

_ACE_MAGIC_AT_7 = b"**ACE**"


def detect_ace(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
    """Confirm an ACE archive by signature. Deliberately does not extract.

    Args:
        file_path: The candidate archive.

    Returns:
        ``(entries, meta)`` with a single synthetic entry describing the
        archive itself, or an empty list and a recorded error if the
        signature is absent.

    The only public ACE parsers have a history of memory-corruption
    CVEs, and CVE-2018-20250 is a path traversal in the extraction path
    itself. Running an abandoned parser over hostile input to complete a
    listing would create the vulnerability this tool exists to find, so
    the archive is identified and never opened.

    The entry describes the container rather than any member, since no
    member list can be obtained without parsing. That is enough for
    scoring: ``ace_detected`` fires on the format's presence, which is
    the finding — an ACE archive arriving in 2026 is itself the signal,
    whatever is inside it.

    The signature sits at offset 7 rather than 0, which is why the
    length check guards 14 bytes and not 7.
    """
    meta = ContainerMeta(detected_format="ace")
    entries: list[ArchiveEntry] = []
    try:
        with file_path.open("rb") as fh:
            header = fh.read(32)
    except OSError as exc:
        meta.handler_errors.append({"stage": "detect_ace", "error": f"OSError: {exc}"})
        return entries, meta

    is_ace = len(header) >= 14 and header[7:14] == _ACE_MAGIC_AT_7
    if not is_ace:
        meta.handler_errors.append({"stage": "detect_ace", "error": "no **ACE** signature at offset 7"})
        return entries, meta

    meta.comment = "ACE archive — extraction skipped (CVE-2018-20250 risk)"
    try:
        ts = int(file_path.stat().st_mtime)
    except OSError:
        ts = int(time.time())
    entries.append(ArchiveEntry(
        name=file_path.name,
        size_compressed=file_path.stat().st_size,
        size_uncompressed=0,
        is_encrypted=False,
        is_symlink=False,
        timestamp=ts,
        method="ace",
    ))
    return entries, meta
