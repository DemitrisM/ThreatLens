"""Archive analysis module — multi-format static triage.

Covers ZIP/RAR/7z/TAR/GZ/BZ2/XZ/CAB/ISO/ACE plus SFX-PE overlay
scanning. Each format has its own enumerator + bounded extractor in a
sibling file; this orchestrator dispatches by magic-byte format,
applies the bomb guard before extraction, runs cross-format
indicators, hashes any embedded executables, scores via the weighted
combo engine, and (within the configured depth limit) recurses on any
inner archive.

Two recursion modes are supported, controlled by
``config["archive_full_recursion"]``:

* **archive-only** (default) — nested archive members re-enter this
  module. Their results land under ``data["nested"]``.
* **full pipeline** (``--recurse-archives``) — each inner archive
  member is fed back through ``run_pipeline``. The aggregated child
  reports land under ``data["nested"]`` as full module-result dicts.

OOXML Office ZIPs short-circuit to ``status="skipped"`` so
``doc_analysis`` keeps owning ``.docx`` / ``.xlsm`` / ``.pptx``.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from .bomb_guard import evaluate_bomb_guard
from .embedded_exec import hash_embedded_executables
from .entries import ArchiveEntry, ContainerMeta, entry_to_dict
from .indicators import (
    detect_autorun_desktop,
    detect_dangerous_members,
    detect_double_extension,
    detect_high_entropy_filenames,
    detect_mime_mismatches,
    detect_null_byte_filenames,
    detect_path_traversal,
    detect_persistence_paths,
    detect_rtlo_filenames,
    detect_symlink_attacks,
    detect_timestamp_anomaly,
    scan_comments_for_iocs,
)
from .other_handlers import (
    detect_ace,
    enumerate_cab,
    enumerate_iso,
    extract_cab_members_to_temp,
    extract_iso_members_to_temp,
)
from .rar_handler import enumerate_rar
from .rar_handler import extract_members_to_temp as rar_extract
from .routing import detect_format, is_archive_target, is_office_ooxml_zip, is_pe
from .scoring import score_archive
from .sevenzip_handler import enumerate_7z
from .sevenzip_handler import extract_members_to_temp as sevenzip_extract
from .sfx_detect import scan_pe_overlay
from .tarball_handler import enumerate_single_stream, enumerate_tar, extract_tar_members_to_temp
from .zip_handler import enumerate_zip
from .zip_handler import extract_members_to_temp as zip_extract

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 3
_DEFAULT_MAX_EXTRACT_MB = 500
_DEFAULT_BOMB_RATIO = 100.0
_DEFAULT_BOMB_COUNT = 1000
_DEFAULT_MIME_CHECK_MB = 10


def run(file_path: Path, config: dict) -> dict:
    """Module entry point — returns the standard result dict."""
    try:
        if not file_path.exists():
            return _error("File does not exist")

        # PE branch — SFX overlay scan
        if is_pe(file_path):
            return _analyse_pe_for_sfx(file_path, config)

        # ZIP-that's-Office short-circuit
        if file_path.suffix.lower() in (".zip",) or detect_format(file_path) == "zip":
            if is_office_ooxml_zip(file_path):
                return _skipped("OOXML container — handled by doc_analysis")

        if not is_archive_target(file_path):
            return _skipped("Not applicable — not an archive")

        return _analyse_archive(file_path, config, depth=0)

    except Exception as exc:  # noqa: BLE001
        logger.error("archive_analysis crashed on %s: %s", file_path, exc)
        return _error(f"Analysis error: {exc}")


# ---------------------------------------------------------------------------
# PE / SFX path
# ---------------------------------------------------------------------------

def _analyse_pe_for_sfx(file_path: Path, config: dict) -> dict:
    sfx = scan_pe_overlay(file_path)
    if not sfx.get("is_sfx"):
        return _skipped("PE has no archive overlay")

    payload_path = sfx.get("payload_path")
    flags: set[str] = {"sfx_dropper"}
    nested: list[dict] = []
    nested_data: dict | None = None

    if payload_path:
        try:
            child = _analyse_archive(Path(payload_path), config, depth=1)
            nested_data = child
            if child.get("status") == "success":
                child_data = child.get("data", {}) or {}
                for f in child_data.get("indicator_flags", []) or []:
                    flags.add(f)
        finally:
            try:
                Path(payload_path).unlink(missing_ok=True)
            except OSError:
                pass

    score_delta, reason, fired, classification = score_archive(flags)

    data = _empty_data()
    data["detected_format"] = "sfx_pe"
    data["sfx"] = {
        "is_sfx": True,
        "embedded_format": sfx.get("embedded_format"),
        "offset": sfx.get("offset"),
    }
    data["indicator_flags"] = sorted(flags)
    data["classification"] = classification
    data["fired_rules"] = fired
    if nested_data is not None:
        nested.append(nested_data)
    data["nested"] = nested

    return {
        "module": "archive_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Archive path
# ---------------------------------------------------------------------------

def _analyse_archive(file_path: Path, config: dict, depth: int) -> dict:
    fmt = detect_format(file_path)
    max_depth = int(config.get("max_archive_recursion_depth", _DEFAULT_MAX_DEPTH))
    extract_budget = int(config.get(
        "max_archive_extracted_size_mb", _DEFAULT_MAX_EXTRACT_MB,
    )) * 1024 * 1024
    ratio_threshold = float(config.get(
        "archive_bomb_ratio_threshold", _DEFAULT_BOMB_RATIO,
    ))
    count_threshold = int(config.get(
        "archive_bomb_member_count_threshold", _DEFAULT_BOMB_COUNT,
    ))
    mime_check_max = int(config.get(
        "archive_member_mime_check_max_mb", _DEFAULT_MIME_CHECK_MB,
    )) * 1024 * 1024

    try:
        container_size = file_path.stat().st_size
    except OSError:
        container_size = 0

    entries, meta = _dispatch_enumerate(file_path, fmt)
    data = _empty_data()
    data["detected_format"] = fmt
    data["entry_count"] = len(entries)
    data["total_uncompressed_size"] = sum(e.size_uncompressed for e in entries)
    data["zip_header_mismatch"] = list(meta.zip_header_mismatches)
    data["encryption"]["header_encrypted"] = bool(meta.header_encrypted)
    data["errors"] = list(meta.handler_errors)

    bomb = evaluate_bomb_guard(
        entries=entries,
        container_size=container_size,
        ratio_threshold=ratio_threshold,
        size_threshold_bytes=extract_budget,
        count_threshold=count_threshold,
    )
    data["bomb_guard"] = bomb

    tmp_dir: Path | None = None
    extracted = False
    if entries and not bomb["triggered"] and fmt != "ace":
        tmp_dir = Path(tempfile.mkdtemp(prefix="archive_extract_"))
        try:
            _dispatch_extract(file_path, fmt, entries, tmp_dir, extract_budget)
            extracted = True
        except Exception as exc:  # noqa: BLE001
            meta.handler_errors.append({"stage": "extract", "error": str(exc)})

    # Cross-format indicators (always run, even without extraction)
    flags: set[str] = set()
    data["path_traversal"] = detect_path_traversal(entries)
    if data["path_traversal"]:
        flags.add("path_traversal")

    data["symlink_attack"] = detect_symlink_attacks(entries)
    if data["symlink_attack"]:
        flags.add("symlink_attack")

    data["dangerous_members"] = detect_dangerous_members(entries)
    if data["dangerous_members"]:
        flags.add("dangerous_member")

    data["double_extension"] = detect_double_extension(entries)
    if data["double_extension"]:
        flags.add("double_extension")

    data["rtlo_filenames"] = detect_rtlo_filenames(entries)
    if data["rtlo_filenames"]:
        flags.add("rtlo_filename")

    data["null_byte_filenames"] = detect_null_byte_filenames(entries)
    if data["null_byte_filenames"]:
        flags.add("null_byte_filename")

    data["high_entropy_filenames"] = detect_high_entropy_filenames(entries)
    if data["high_entropy_filenames"]:
        flags.add("high_entropy_filename")

    data["persistence_paths"] = detect_persistence_paths(entries)
    if data["persistence_paths"]:
        flags.add("persistence_path")

    autorun, desktop_ini = detect_autorun_desktop(entries)
    data["autorun_inf"] = autorun
    data["desktop_ini"] = desktop_ini
    if autorun:
        flags.add("autorun_inf")
    if desktop_ini:
        flags.add("desktop_ini")

    data["timestamp_anomaly"] = detect_timestamp_anomaly(entries)
    if data["timestamp_anomaly"]["triggered"]:
        flags.add("timestamp_anomaly")

    if extracted:
        data["mime_mismatches"] = detect_mime_mismatches(entries, mime_check_max)
        if data["mime_mismatches"]:
            flags.add("mime_mismatch")

        data["embedded_executables"] = hash_embedded_executables(entries)
        if data["embedded_executables"]:
            flags.add("embedded_pe")

    if data["zip_header_mismatch"]:
        flags.add("zip_header_mismatch")
    if meta.header_encrypted:
        flags.add("header_encrypted")
    if any(e.is_encrypted for e in entries):
        data["encryption"]["is_encrypted"] = True
        flags.add("is_encrypted")
    if bomb["triggered"]:
        flags.add("bomb_guard")
    if fmt == "ace":
        flags.add("ace_detected")
        data["ace_detected"] = True

    comment_iocs = scan_comments_for_iocs([meta.comment]) if meta.comment else []
    data["archive_comment_iocs"] = comment_iocs
    if comment_iocs:
        flags.add("comment_ioc")

    # Persist normalised entry list for reporters
    data["entries"] = [entry_to_dict(e) for e in entries]

    # ── Recursion ──────────────────────────────────────────────────────────
    nested_results: list[dict] = []
    if depth + 1 <= max_depth and extracted:
        nested_results = _recurse_into_inner_archives(
            entries=entries,
            config=config,
            depth=depth + 1,
        )
        if nested_results:
            flags.add("nested_archive")
            for child in nested_results:
                child_data = (child.get("data") or {})
                for f in child_data.get("indicator_flags", []) or []:
                    flags.add(f)
    data["nested"] = nested_results
    data["recursion_depth_reached"] = depth >= max_depth

    # ── Score ──────────────────────────────────────────────────────────────
    score_delta, reason, fired, classification = score_archive(flags)
    data["indicator_flags"] = sorted(flags)
    data["classification"] = classification
    data["fired_rules"] = fired

    # Tempdir cleanup
    if tmp_dir is not None:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except OSError:
            pass

    return {
        "module": "archive_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Dispatch helpers
# ---------------------------------------------------------------------------

def _dispatch_enumerate(
    file_path: Path, fmt: str | None,
) -> tuple[list[ArchiveEntry], ContainerMeta]:
    if fmt == "zip":
        return enumerate_zip(file_path)
    if fmt == "rar":
        return enumerate_rar(file_path)
    if fmt == "7z":
        return enumerate_7z(file_path)
    if fmt == "tar":
        return enumerate_tar(file_path)
    if fmt in ("gz", "bz2", "xz"):
        # Single-stream — we need a tmp_dir for the inner payload
        tmp = Path(tempfile.mkdtemp(prefix="single_stream_"))
        return enumerate_single_stream(file_path, fmt, tmp)
    if fmt == "cab":
        return enumerate_cab(file_path)
    if fmt == "iso":
        return enumerate_iso(file_path)
    if fmt == "ace":
        return detect_ace(file_path)
    return [], ContainerMeta(detected_format=fmt)


def _dispatch_extract(
    file_path: Path,
    fmt: str | None,
    entries: list[ArchiveEntry],
    tmp_dir: Path,
    max_total_bytes: int,
) -> None:
    if fmt == "zip":
        zip_extract(file_path, entries, tmp_dir, max_total_bytes)
    elif fmt == "rar":
        rar_extract(file_path, entries, tmp_dir, max_total_bytes)
    elif fmt == "7z":
        sevenzip_extract(file_path, entries, tmp_dir, max_total_bytes)
    elif fmt == "tar":
        extract_tar_members_to_temp(file_path, entries, tmp_dir, max_total_bytes)
    elif fmt in ("gz", "bz2", "xz"):
        # Inner payload was already written by enumerate_single_stream
        return
    elif fmt == "cab":
        extract_cab_members_to_temp(file_path, entries, tmp_dir, max_total_bytes)
    elif fmt == "iso":
        extract_iso_members_to_temp(file_path, entries, tmp_dir, max_total_bytes)


# ---------------------------------------------------------------------------
# Recursion
# ---------------------------------------------------------------------------

def _recurse_into_inner_archives(
    entries: list[ArchiveEntry],
    config: dict,
    depth: int,
) -> list[dict]:
    """For each extracted member that is itself an archive, descend.

    Mode is controlled by ``config["archive_full_recursion"]`` —
    archive-only by default, full-pipeline when True.
    """
    full_pipeline = bool(config.get("archive_full_recursion", False))
    out: list[dict] = []

    for e in entries:
        if not e.extracted_path:
            continue
        path = Path(e.extracted_path)
        if not path.is_file() or not is_archive_target(path):
            continue
        if path.suffix.lower() == ".zip" and is_office_ooxml_zip(path):
            continue

        if full_pipeline:
            try:
                from core.pipeline import run_pipeline  # noqa: PLC0415
                child_report = run_pipeline(path, dict(config))
                out.append({
                    "name": e.name,
                    "report": _summarise_child_report(child_report),
                })
            except Exception as exc:  # noqa: BLE001
                logger.debug("nested run_pipeline failed for %s: %s", e.name, exc)
        else:
            child = _analyse_archive(path, config, depth=depth)
            child["nested_member_name"] = e.name
            out.append(child)

    return out


def _summarise_child_report(child: dict) -> dict:
    """Slim a full-pipeline child report so it doesn't bloat the parent."""
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

def _empty_data() -> dict:
    return {
        "detected_format": None,
        "entries": [],
        "entry_count": 0,
        "total_uncompressed_size": 0,
        "bomb_guard": {"triggered": False, "reasons": [], "stats": {}},
        "path_traversal": [],
        "symlink_attack": [],
        "dangerous_members": [],
        "double_extension": [],
        "rtlo_filenames": [],
        "null_byte_filenames": [],
        "high_entropy_filenames": [],
        "persistence_paths": [],
        "autorun_inf": None,
        "desktop_ini": False,
        "timestamp_anomaly": {"triggered": False, "reason": None},
        "mime_mismatches": [],
        "embedded_executables": [],
        "zip_header_mismatch": [],
        "archive_comment_iocs": [],
        "encryption": {"is_encrypted": False, "header_encrypted": False},
        "sfx": {"is_sfx": False, "embedded_format": None, "offset": None},
        "ace_detected": False,
        "nested": [],
        "recursion_depth_reached": False,
        "classification": "CLEAN",
        "indicator_flags": [],
        "fired_rules": [],
        "errors": [],
    }


def _skipped(reason: str) -> dict:
    return {
        "module": "archive_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    return {
        "module": "archive_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
