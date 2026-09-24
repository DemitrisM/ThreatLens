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

Design notes
------------
**The order of the phases is the security property, not a style
choice.** Enumerate, then guard, then extract, then indicate, then
recurse, then score. Each step is only safe because the one before it
ran: the bomb guard needs the declared sizes enumeration produces, and
extraction must not begin until the guard has cleared it. Reordering any
two of them re-opens something.

``extracted`` is the gate the whole back half hangs on. It is set only
when bytes actually reached disk *and* the bomb guard did not trip, and
it controls the MIME check, the embedded-executable hashing and —
above all — the recursion. The single-stream formats are why it cannot
simply be "did extraction run": gz/bz2/xz have no member listing, so
their payload is written before the guard can see a number, and
treating that as extracted would hand a decompression bomb straight to
the recursive descent.

That write is bounded rather than unguarded, which is what keeps the
ordering survivable: ``enumerate_single_stream`` reads at most
``_INNER_STREAM_CAP + 1`` bytes and writes at most ``_INNER_STREAM_CAP``
— 64 MiB — so a gz bomb costs that and no more, and the guard then
refuses everything downstream. The bound is a truncation, so the
indicators still see a prefix of the payload rather than nothing.

Two gaps in archive-only recursion, both consequences of it not being
the full pipeline and both recorded rather than fixed here. A nested
OOXML container is skipped, and since ``doc_analysis`` is not run on
nested members in this mode, its macros go unread — the member still
scores for its extension, and ``archive_full_recursion`` exists for
the case where that is not enough. A nested PE is skipped for the same
structural reason: ``_recurse_into_inner_archives`` gates on
``is_archive_target``, which answers False for a PE by design, so a
nested SFX dropper is not carved the way a top-level one is.

**One owner for the scratch directory, one cleanup.** ``tmp_dir`` is
created here and removed in the ``finally``, whatever happens in
between. The extracted bytes are live malware and a path that leaves
them behind is the defect class this package has already had twice.

Every indicator runs whether or not extraction happened. A
header-encrypted archive, or one the bomb guard refused, still has
member names, sizes and timestamps to judge — reporting nothing for it
would be the single worst outcome, since those are exactly the archives
worth reporting on.

**Nested results merge their flags into the parent and discard their
scores.** A child's indicator flags are added to the parent's set, so a
dangerous member three archives deep scores at full parent weight. The
damping that would fix it has a receiving end in ``core.scoring`` —
``_clamp`` accepts a float specifically for it — and no sender. That is
a deliberate deferral to the end-of-project calibration sweep, because
wiring it changes every nested archive's score and the corpus would
need re-observing.

The module never raises. ``run`` wraps everything in a last-resort
handler that turns an unexpected failure into ``status="error"``, per
design rule 2, because this module parses attacker-controlled binary
formats through six third-party libraries.
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
    detect_duplicate_member_names,
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
    """Module entry point — returns the standard result dict.

    Args:
        file_path: The file to analyse.
        config:    Pipeline configuration. Read for the recursion depth,
                   the extraction budget, the bomb thresholds and the
                   MIME-check ceiling.

    Returns:
        The standard module dict. ``status`` is ``"skipped"`` for a file
        this module does not own, ``"error"`` for one it could not read,
        and ``"success"`` otherwise — including for an archive it could
        only describe rather than open.

    The three gates run in this order for a reason. A PE is checked
    first because ``is_archive_target`` deliberately answers False for
    one, so asking that first would route every SFX dropper to
    "not applicable". The OOXML check comes before the general archive
    test because an Office document *is* a valid ZIP and would otherwise
    be enumerated here as well as by ``doc_analysis``, scoring the same
    file twice.
    """
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
    """Analyse a PE as a possible self-extracting archive.

    Args:
        file_path: A file already known to start with ``MZ``.
        config:    Pipeline configuration, passed to the child analysis.

    Returns:
        The standard module dict. ``"skipped"`` when the PE carries no
        archive overlay, which is the common case for an ordinary
        executable.

    The carved payload is analysed by re-entering ``_analyse_archive``
    at depth 1 rather than by a second parser, so an SFX dropper's
    contents get the full indicator set. Its flags are merged into the
    parent's, which is what lets ``sfx_dropper`` combine with whatever
    the payload itself raises.

    The ``finally`` is not optional: ``scan_pe_overlay`` hands back a
    tempfile it does not own, and this function is the only place that
    can delete it. Those are carved malware bytes, and a child analysis
    that raises must not leave them behind.
    """
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
    """Enumerate, guard, extract, indicate, recurse and score one archive.

    Args:
        file_path: The container.
        depth:     Current recursion depth; 0 for the file the user
                   named. Compared against
                   ``max_archive_recursion_depth``.
        config:    Pipeline configuration.

    Returns:
        The standard module dict, always ``"success"`` — a format that
        could not be opened yields an empty listing and a recorded
        handler error rather than a failure, because "this is an archive
        nothing could read" is itself worth reporting.

    Note the budget values are re-read from config on every call,
    including recursive ones, so each archive in a nested tree is
    granted the full allowance rather than a decrementing remainder. The
    name ``max_archive_extracted_size_mb`` suggests otherwise; it is
    per-archive.
    """
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

    # The scratch directory is created here, before enumeration, because
    # the single-stream formats have no member listing to read: gz/bz2/xz
    # must decompress the inner payload to disk before there is anything
    # to describe. Every other format fills it later, after the bomb guard
    # has cleared extraction. One owner, one cleanup, in the finally below
    # — the extracted bytes are live malware and must not outlive the scan.
    tmp_dir: Path | None = None
    if fmt in _SINGLE_STREAM_FORMATS:
        tmp_dir = Path(tempfile.mkdtemp(prefix="single_stream_"))

    try:
        entries, meta = _dispatch_enumerate(file_path, fmt, tmp_dir, config)
        data = _empty_data()
        data["detected_format"] = fmt
        data["entry_count"] = len(entries)
        data["total_uncompressed_size"] = sum(e.size_uncompressed for e in entries)
        data["zip_header_mismatch"] = list(meta.zip_header_mismatches)
        data["encryption"]["header_encrypted"] = bool(meta.header_encrypted)

        bomb = evaluate_bomb_guard(
            entries=entries,
            container_size=container_size,
            ratio_threshold=ratio_threshold,
            size_threshold_bytes=extract_budget,
            count_threshold=count_threshold,
        )
        data["bomb_guard"] = bomb

        # Single-stream formats already wrote their payload during
        # enumeration and own a directory; reassigning here would orphan it.
        #
        # `not bomb["triggered"]` is load-bearing. gz/bz2/xz have no member
        # listing, so the payload necessarily lands on disk before the guard
        # can run — but once the guard trips, nothing downstream may touch
        # it. `extracted` gates the MIME check, the embedded-PE hashing and,
        # above all, the recursion, so treating a bomb as extracted would
        # hand a decompression bomb straight to the recursive descent.
        extracted = (
            fmt in _SINGLE_STREAM_FORMATS
            and bool(entries)
            and not bomb["triggered"]
        )
        if entries and not bomb["triggered"] and fmt != "ace":
            if tmp_dir is None:
                tmp_dir = Path(tempfile.mkdtemp(prefix="archive_extract_"))
            try:
                _dispatch_extract(file_path, fmt, entries, tmp_dir, extract_budget)
                extracted = True
            except Exception as exc:  # noqa: BLE001
                meta.handler_errors.append({"stage": "extract", "error": str(exc)})

        # Snapshot handler errors only now. list() copies, so taking it
        # before extraction detached it from meta.handler_errors and every
        # failure appended by the extract block above was dropped before the
        # caller saw it — extraction failures reported as a clean scan.
        data["errors"] = list(meta.handler_errors)

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

        # A repeated member name hides one record behind another. For 7z
        # and CAB the hidden bytes are unrecoverable — the external
        # extractor overwrote them — so the report has to say a member
        # could not be examined rather than imply a clean result.
        data["duplicate_member_names"] = detect_duplicate_member_names(entries, fmt)
        if data["duplicate_member_names"]:
            flags.add("duplicate_member_name")
            if any(not d["recoverable"] for d in data["duplicate_member_names"]):
                flags.add("shadowed_member_unrecoverable")

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

        return {
            "module": "archive_analysis",
            "status": "success",
            "data": data,
            "score_delta": score_delta,
            "reason": reason,
        }
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Dispatch helpers
# ---------------------------------------------------------------------------

_SINGLE_STREAM_FORMATS = ("gz", "bz2", "xz")


def _dispatch_enumerate(
    file_path: Path,
    fmt: str | None,
    tmp_dir: Path | None = None,
    config: dict | None = None,
) -> tuple[list[ArchiveEntry], ContainerMeta]:
    """Route to the format's enumerator and return its normalised listing.

    Args:
        file_path: The container to enumerate.
        fmt:       Detected format key, or None when detection failed.
        tmp_dir:   Scratch directory owned by the caller. Only the
                   single-stream formats use it — they have no member
                   listing to read, so the inner payload must be
                   decompressed to disk before there is anything to
                   describe.
        config:    Pipeline configuration. Only the TAR walker reads it,
                   to bound enumeration on an archive with no index.

    Returns:
        ``(entries, meta)``. An unrecognised format yields an empty listing
        rather than raising, so the caller's scoring path is uniform.
    """
    if fmt == "zip":
        return enumerate_zip(file_path)
    if fmt == "rar":
        return enumerate_rar(file_path)
    if fmt == "7z":
        return enumerate_7z(file_path)
    if fmt == "tar":
        return enumerate_tar(file_path, config)
    if fmt in _SINGLE_STREAM_FORMATS:
        # The scratch directory is the caller's: this function used to mint
        # its own with mkdtemp and return only the entries, so the path was
        # unreachable and nothing ever removed it. Every .gz/.bz2/.xz scan
        # left the decompressed payload — live malware — in /tmp.
        return enumerate_single_stream(file_path, fmt, tmp_dir)
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
    """Route to the format's extractor.

    Args:
        file_path:       The container.
        fmt:             Detected format key.
        entries:         Members, updated in place with
                         ``extracted_path``.
        tmp_dir:         Scratch directory owned by the caller.
        max_total_bytes: Budget passed through to the extractor, which
                         enforces it in the way its format allows —
                         member by member for ZIP, RAR, TAR and ISO, as
                         a single pre-flight decision for 7z and CAB.

    Returns:
        None.

    The single-stream formats return immediately: their payload was
    already written during enumeration, because those formats have no
    member listing to read without decompressing. Falling through to an
    extractor here would write it a second time.

    An unrecognised format falls off the end and does nothing, which is
    correct — enumeration produced no entries for it either.
    """
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

    Args:
        entries: Members of the parent, already extracted.
        config:  Pipeline configuration; ``archive_full_recursion``
                 selects the mode.
        depth:   Depth to analyse the children at, already incremented.

    Returns:
        One result dict per inner archive, in member order.

    Only members that actually reached disk are considered, which ties
    the recursion to the same ``extracted`` gate as everything else —
    a bomb-guarded archive has no extracted members and therefore no
    descent.

    Two modes, and the default is the narrow one. Archive-only recursion
    re-enters this module, so a nested container is opened and its
    members judged but its payloads are not given the full static
    battery. Full-pipeline recursion runs ``run_pipeline`` on each inner
    archive, which is far more expensive and can re-enter this module
    again from the other side — it is config-gated for that reason.

    A nested OOXML container is skipped rather than descended into, for
    the same reason the top-level check exists: ``doc_analysis`` owns
    those, and analysing one here would double-count it.

    The full-pipeline arm catches broadly because it is calling the
    entire pipeline on attacker-controlled bytes; a child failure must
    cost that child, not the parent scan.
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
    """Slim a full-pipeline child report so it doesn't bloat the parent.

    Args:
        child: A complete ``run_pipeline`` report.

    Returns:
        Its scoring block plus a one-line summary per module.

    A nested report embedded whole would carry every module's full data
    — strings, IOCs, capa matches — for each inner archive, at every
    depth. The parent's JSON is meant to be readable; the child's score
    and per-module verdicts are what the parent needs to convey.
    """
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
    """The report contract: every key this module can ever emit.

    Returns:
        A fully-populated dict of empty values.

    Built in one place and always in full, so a reporter can index any
    key without guarding it. A key that appears only when its indicator
    fires would mean every consumer — the terminal rows, the HTML
    mirror, the JSON schema — needs a ``.get`` with the right default,
    and one of them would eventually get it wrong. ``classification``
    defaults to ``CLEAN`` rather than None for the same reason.
    """
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
        "duplicate_member_names": [],
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
    """A file this module does not own.

    Args:
        reason: Shown to the user as the skip explanation.

    Returns:
        The standard dict with ``status="skipped"`` and no score.

    Distinct from ``_error``: a skip means the question does not apply,
    an error means it applied and could not be answered. The pipeline
    renders them differently and design rule 10 turns on the
    difference.
    """
    return {
        "module": "archive_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    """A file this module should have handled and could not.

    Args:
        reason: Shown to the user as the failure explanation.

    Returns:
        The standard dict with ``status="error"`` and no score.

    Scores zero deliberately. An analysis that did not run must never
    contribute to a verdict in either direction — see design rule 10,
    which is the same principle at the CLI level.
    """
    return {
        "module": "archive_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
