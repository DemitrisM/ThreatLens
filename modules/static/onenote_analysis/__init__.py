"""OneNote `.one` container analysis — static triage.

Handles the payload-carrier threat model for Microsoft OneNote files
that became mainstream post-2022 (IcedID, Qakbot, AsyncRAT, Remcos,
MetaStealer). The full MS-ONESTORE revision-store tree is intentionally
not parsed — forensic teams triage these files by scanning for
``FileDataStoreObject`` records (the embedded-payload carriers) and
typing each blob by content. That is what this module does.

Two recursion modes, controlled by ``config["onenote_full_recursion"]``:

* **hash-only** (default) — every dangerous blob is hashed; the
  SHA256 list is surfaced under ``data["embedded_executables"]`` so
  ``modules.enrichment.virustotal`` picks it up for free forward-lookup.
* **full pipeline** (``--recurse-onenote``) — each PE / MSI / ELF blob
  is written to a tempfile and fed back through ``run_pipeline``. Child
  reports land under ``data["nested"]``.

``.onepkg`` bundles are CABs containing ``.one`` + ``.onetoc2`` — they
are left to ``archive_analysis``; we short-circuit with a descriptive
skip reason rather than re-implement CAB parsing here.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from dataclasses import asdict
from pathlib import Path

from .embedded import EmbeddedBlob, classify_blob, to_vt_forward_entry
from .indicators import derive_flags
from .parser import (
    ONESTORE_HEADER_GUID,
    has_encrypted_section,
    is_onenote_file,
    walk_file_data_store_objects,
)
from .scoring import score_onenote

logger = logging.getLogger(__name__)

_DEFAULT_MAX_SIZE_MB = 50
_DEFAULT_MAX_BLOBS = 200
_DEFAULT_MAX_DEPTH = 2

# Blob kinds that get fed back through run_pipeline when full-recursion is on.
_RECURSE_KINDS = frozenset({"pe", "elf", "macho", "msi"})


def run(file_path: Path, config: dict) -> dict:
    """Module entry point — returns the standard result dict."""
    try:
        if not file_path.exists():
            return _error("File does not exist")

        if not is_onenote_file(file_path):
            return _skipped("Not applicable — not a OneNote file")

        suffix = file_path.suffix.lower()
        if suffix == ".onepkg":
            return _skipped(
                ".onepkg bundle — extraction handled by archive_analysis"
            )

        max_size = int(config.get("max_onenote_size_mb", _DEFAULT_MAX_SIZE_MB))
        max_size_bytes = max_size * 1024 * 1024
        size = file_path.stat().st_size
        if size > max_size_bytes:
            return _skipped(
                f"File exceeds onenote_analysis size cap ({max_size} MiB)"
            )

        return _analyse(file_path, config)

    except Exception as exc:  # noqa: BLE001
        logger.error("onenote_analysis crashed on %s: %s", file_path, exc)
        return _error(f"Analysis error: {exc}")


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def _analyse(file_path: Path, config: dict) -> dict:
    data_bytes = file_path.read_bytes()

    # Defensive: if the header GUID isn't at offset 0 but the extension
    # matched (e.g. someone renamed a file to .one), still try to walk
    # FDSO records — worst case the list is empty.
    onestore_header_present = data_bytes[:16] == ONESTORE_HEADER_GUID

    max_blobs = int(config.get("max_onenote_blobs", _DEFAULT_MAX_BLOBS))
    raw_blobs = walk_file_data_store_objects(data_bytes, max_blobs=max_blobs)
    typed_blobs: list[EmbeddedBlob] = [
        classify_blob(offset, payload) for offset, payload in raw_blobs
    ]

    encrypted = has_encrypted_section(data_bytes)

    flags = derive_flags(typed_blobs, has_encrypted_section=encrypted)
    score_delta, reason, fired, classification = score_onenote(flags)

    embedded_execs = [
        entry for entry in (to_vt_forward_entry(b) for b in typed_blobs)
        if entry is not None
    ]

    nested: list[dict] = []
    if config.get("onenote_full_recursion"):
        nested = _recurse_into_embedded(typed_blobs, data_bytes, config)

    return {
        "module": "onenote_analysis",
        "status": "success",
        "data": {
            "onestore_header_present": onestore_header_present,
            "encrypted_section": encrypted,
            "blob_count": len(typed_blobs),
            "blobs": [asdict(b) for b in typed_blobs],
            "embedded_executables": embedded_execs,
            "indicator_flags": sorted(flags),
            "classification": classification,
            "fired_rules": fired,
            "nested": nested,
        },
        "score_delta": score_delta,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Recursion
# ---------------------------------------------------------------------------

def _recurse_into_embedded(
    blobs: list[EmbeddedBlob], data_bytes: bytes, config: dict,
) -> list[dict]:
    """Feed each native-executable blob back through run_pipeline.

    ``data_bytes`` is the full OneNote file — we re-slice the payload
    from it using the dataclass offset so we don't duplicate the bytes
    in memory while collecting typed blobs.
    """
    depth = int(config.get("_onenote_depth", 0))
    max_depth = int(config.get("max_onenote_recursion_depth", _DEFAULT_MAX_DEPTH))
    if depth >= max_depth:
        return []

    try:
        from core.pipeline import run_pipeline  # noqa: PLC0415
    except ImportError as exc:
        logger.debug("run_pipeline import failed — skipping recursion: %s", exc)
        return []

    tmp_dir = Path(tempfile.mkdtemp(prefix="onenote_recurse_"))
    child_reports: list[dict] = []
    try:
        for blob in blobs:
            if blob.kind not in _RECURSE_KINDS:
                continue

            # Re-slice the payload from the parent buffer.
            payload = _payload_for_blob(blob, data_bytes)
            if not payload:
                continue

            suffix = _suffix_for_kind(blob.kind)
            target = tmp_dir / f"blob_0x{blob.offset:08x}{suffix}"
            try:
                target.write_bytes(payload)
            except OSError as exc:
                logger.debug("Could not write blob to %s: %s", target, exc)
                continue

            child_cfg = dict(config)
            child_cfg["_onenote_depth"] = depth + 1

            try:
                report = run_pipeline(target, child_cfg)
            except Exception as exc:  # noqa: BLE001
                logger.debug("nested run_pipeline failed on %s: %s", target, exc)
                continue

            child_reports.append({
                "source_offset": blob.offset,
                "kind": blob.kind,
                "sha256": blob.sha256,
                "report": _summarise_child_report(report),
            })
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return child_reports


def _payload_for_blob(blob: EmbeddedBlob, data_bytes: bytes) -> bytes:
    start = blob.offset + 36  # FDSO header size — mirrors parser._FDSO_HEADER_SIZE
    end = start + blob.size
    if end > len(data_bytes):
        return b""
    return data_bytes[start:end]


def _suffix_for_kind(kind: str) -> str:
    return {
        "pe": ".bin",
        "elf": ".bin",
        "macho": ".bin",
        "msi": ".msi",
    }.get(kind, ".bin")


def _summarise_child_report(child: dict) -> dict:
    """Slim the nested pipeline report so it doesn't bloat the parent."""
    return {
        "scoring": child.get("scoring", {}),
        "module_results": [
            {
                "module": r.get("module"),
                "status": r.get("status"),
                "score_delta": r.get("score_delta"),
                "reason": r.get("reason"),
            }
            for r in child.get("module_results", [])
        ],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skipped(reason: str) -> dict:
    return {
        "module": "onenote_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    return {
        "module": "onenote_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
