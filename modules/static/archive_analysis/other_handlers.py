"""CAB / ISO / ACE handlers.

* **CAB** — shells out to the system ``cabextract`` binary. Absent
  binary → graceful metadata-only skip.
* **ISO / IMG** — uses ``pycdlib`` when available. Walks Joliet/Rock
  Ridge/ISO9660 records so names are correct under all extensions.
* **ACE** — detection only. No extraction attempted because the format
  (WinACE) is effectively abandoned and the only surviving unace port
  has a history of memory-corruption CVEs (CVE-2018-20250).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from pathlib import Path

from .entries import ArchiveEntry, ContainerMeta

logger = logging.getLogger(__name__)

_CABEXTRACT_TIMEOUT = 10  # seconds — list + extract each capped here


# ---------------------------------------------------------------------------
# CAB
# ---------------------------------------------------------------------------

def enumerate_cab(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
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
    for e in entries:
        candidate = tmp_dir / e.name
        if candidate.is_file() and candidate.stat().st_size <= 50 * 1024 * 1024:
            e.extracted_path = str(candidate)


# ---------------------------------------------------------------------------
# ISO / IMG
# ---------------------------------------------------------------------------

def enumerate_iso(file_path: Path) -> tuple[list[ArchiveEntry], ContainerMeta]:
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

    try:
        for e in entries:
            if e.size_uncompressed <= 0 or e.size_uncompressed > 50 * 1024 * 1024:
                continue
            if written + e.size_uncompressed > max_total_bytes:
                break
            safe_name = f"m_{len(list(tmp_dir.iterdir())):04d}_{Path(e.name).name[:80]}"
            out_path = tmp_dir / safe_name
            src_path = "/" + e.name.lstrip("/")
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
    """ACE format detection. We deliberately do not extract.

    Rationale: the only public ACE parser (``acefile`` / ``unace``)
    has a history of RCE CVEs (CVE-2018-20250). Flagging alone is
    enough — downstream scoring treats presence as suspicious.
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
