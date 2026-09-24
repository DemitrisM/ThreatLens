"""Windows shortcut (`.lnk`) static analysis.

Shell links became a first-class malware delivery format after the 2022
macro block: Unit 42 counted 21,098 malicious samples in 2023 and 68,392
in 2024. The payload command is normally sitting in plaintext inside the
file — a `.lnk` is a structured binary whose target, arguments, working
directory, icon path and originating machine's NetBIOS name and MAC
address all live in fixed, parseable fields.

The parser is first-party and dependency-free. That is not
not-invented-here: the obvious alternative, ``LnkParse3``, still lets
``struct.error`` and ``UnicodeDecodeError`` escape on malformed input,
and malformed-by-design is the norm for this format. Writing it here is
the only way to actually honour the never-raise contract.

Layout:

* ``parser.py`` — the bounds-checked [MS-SHLLINK] walker
* ``shellitems.py`` — shell-item decoding, incl. NTFS MFT references
* ``propstore.py`` — PropertyStoreDataBlock into named properties
* ``command.py`` — target resolution, command patterns, padding analysis
* ``indicators.py`` / ``scoring.py`` — flags, then weighted combo rules

Any appended payload is hashed and surfaced under
``data["embedded_executables"]`` in the shape
``modules.enrichment.virustotal`` already consumes, so it gets a free
forward-lookup. There is no full-pipeline recursion here — two recursion
engines already exist in the project, and a single appended blob does not
justify a third.

Design notes
------------
The pipeline is linear and each stage consumes only the one before it:
parse the bytes, carve the overlay, resolve and characterise the
command, derive flags, score. Nothing loops back, which is why this
module needs no recursion guard of its own and why a failure anywhere
degrades to a partial report rather than a lost one.

The overlay is carved **before** the command analysis rather than after,
because its type feeds ``derive_flags`` as ``overlay_kind`` — an
appended blob that types as a PE scores differently from one that does
not type at all, and the flag has to exist before scoring runs.

``parse_bytes`` is the public seam for a future container hand-off. This
module reads a path, but nothing below it does: a LNK recovered from a
RAR or a OneNote blob can be analysed from memory without touching the
filesystem. That is the piece of work the archive and OneNote modules
are waiting on, and it is why the parser takes bytes rather than a path.

Only the size cap and the ANSI codepage come from config. Everything
else is a published threshold sitting beside its citation in the module
that uses it — see ``indicators.py`` on why those are not tunable.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict
from pathlib import Path

from . import command as command_analysis
from .indicators import derive_flags
from .parser import ParsedLnk, is_lnk_file, parse_bytes, shannon_entropy
from .scoring import score_lnk

logger = logging.getLogger(__name__)

_DEFAULT_MAX_SIZE_MB = 10
_DEFAULT_CODEPAGE = "cp1252"

#: Magic bytes for anything appended after the shell-link structure.
#: Order matters — the base64 markers are checked last so a real PE wins.
#: ``TVqQ`` is what ``MZ\x90\x00`` becomes under base64, so a raw PE would
#: satisfy neither of those and a base64 one satisfies only them; the
#: ordering matters for the blob that begins with a plausible prefix of
#: both, where the concrete type is the better answer.
#:
#: An unmatched overlay stays ``"unknown"`` and is deliberately *not*
#: forwarded to VirusTotal. Hashing an unidentified blob costs a lookup
#: that will almost always miss, while the overlay's presence, size and
#: entropy are already reported and already score.
_OVERLAY_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "pe", "PE executable"),
    (b"PK\x03\x04", "zip", "ZIP archive"),
    (b"\x7fELF", "elf", "ELF executable"),
    (b"Rar!\x1a\x07", "rar", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (b"\xd0\xcf\x11\xe0", "ole", "OLE compound file"),
    (b"%PDF", "pdf", "PDF document"),
    (b"#@~^", "jscript_encoded", "Encoded JScript (JScript.Encode)"),
    (b"<script", "script", "Inline script"),
    (b"<html", "html", "HTML document"),
    (b"<hta:", "hta", "HTA application"),
    (b"TVqQ", "base64_pe", "Base64-encoded PE"),
    (b"TVpQ", "base64_pe", "Base64-encoded PE"),
)


def run(file_path: Path, config: dict) -> dict:
    """Module entry point — returns the standard result dict.

    Args:
        file_path: The file to analyse.
        config:    Reads ``max_lnk_size_mb`` and ``lnk_ansi_codepage``.

    Returns:
        The standard module dict. ``"skipped"`` for a file that is not a
        shortcut or is past the size cap, ``"error"`` for one that could
        not be read, ``"success"`` otherwise — including for a shortcut
        so malformed that only its header parsed, since that is a
        finding rather than a failure.

    The size cap bounds how much is **read**, never whether the file is
    looked at. It used to skip the file outright, which made eleven
    megabytes of appended nulls — requiring no understanding of the
    format — enough to remove this module from the analysis: a corpus
    sample scoring 60 and classifying MALICIOUS came back skipped and
    worth zero. The shell-link structure sits at the front of the file,
    so a bounded prefix always contains it, and truncating the read
    costs only the overlay's digests.
    """
    try:
        if not file_path.exists():
            return _error("File does not exist")

        if not is_lnk_file(file_path):
            return _skipped("Not applicable — not a Windows shortcut")

        max_size = int(config.get("max_lnk_size_mb", _DEFAULT_MAX_SIZE_MB))
        codepage = str(config.get("lnk_ansi_codepage", _DEFAULT_CODEPAGE))
        return _analyse(file_path, codepage, max_size * 1024 * 1024)

    except Exception as exc:  # noqa: BLE001
        logger.error("lnk_analysis crashed on %s: %s", file_path, exc)
        return _error(f"Analysis error: {exc}")


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def _analyse(file_path: Path, codepage: str, max_bytes: int) -> dict:
    """Run the five stages and assemble the result.

    Args:
        file_path: The shortcut, already gated by :func:`run`.
        codepage:  ANSI codepage for the non-Unicode string fields.
        max_bytes: How much of the file to read. A larger file is parsed
                   from this prefix rather than refused.

    Returns:
        The standard module dict, always ``"success"`` — every failure
        below this point is recorded as an anomaly rather than raised.

    The filename is passed to the command analysis because it is the
    single best source for the double-extension check:
    ``Invoice.pdf.lnk`` is what the victim sees in Explorer and it
    appears in no field inside the file.

    On a truncated read the real file size is restored onto the parse
    result before the flags are derived. ``file_size`` drives the
    ``large_file`` indicator and is printed in the report, and reporting
    the prefix length would understate a file by exactly the payload
    that made it oversized.
    """
    total_size = file_path.stat().st_size
    with file_path.open("rb") as handle:
        data = handle.read(max_bytes)
    truncated = total_size > len(data)

    parsed = parse_bytes(data, codepage=codepage)
    if truncated:
        parsed.file_size = total_size
        parsed.anomalies.append(
            f"File is {total_size} bytes; parsed the first {len(data)} "
            f"against the lnk_analysis read cap"
        )
        # Recompute the overlay bounds from the real file size. The
        # parser derives them from what it was given, so a structure
        # ending exactly at the cap leaves the prefix with no trailing
        # bytes and the overlay looks absent — while the real file
        # continues for as long as the attacker likes. Padding the
        # structure out to the boundary is the only work that takes.
        if parsed.parsed_end < total_size:
            parsed.overlay_offset = parsed.parsed_end
            parsed.overlay_size = total_size - parsed.parsed_end
    overlay = _describe_overlay(
        data, parsed, file_path.name, total_size=total_size, truncated=truncated,
    )
    cmd = command_analysis.analyse(parsed, file_path.name)

    flags = derive_flags(parsed, cmd, overlay_kind=overlay["kind"] if overlay else "")
    score_delta, reason, fired, classification = score_lnk(flags)

    # A truncated overlay is never forwarded: its digests describe a
    # prefix, and a VirusTotal lookup on a fragment's hash is a miss
    # dressed up as an answer.
    embedded = []
    if overlay and overlay["kind"] != "unknown" and not overlay["truncated"]:
        embedded.append({
            "name": overlay["name"],
            "md5": overlay["md5"],
            "sha256": overlay["sha256"],
            "size": overlay["size"],
            "type": overlay["description"],
        })

    return {
        "module": "lnk_analysis",
        "status": "success",
        "data": _build_data(parsed, cmd, overlay, embedded, flags,
                            fired, classification),
        "score_delta": score_delta,
        "reason": reason,
    }


def _build_data(
    parsed: ParsedLnk,
    cmd: command_analysis.CommandAnalysis,
    overlay: dict | None,
    embedded: list[dict],
    flags: frozenset[str],
    fired: list[str],
    classification: str,
) -> dict:
    """Assemble the reporter-facing payload.

    Arguments are surfaced twice on purpose: ``arguments`` is the raw
    string (the reporters truncate for display), while
    ``arguments_length`` and the padding block describe its *shape*. A
    260-space prefix is invisible in a report but is the whole finding.
    """
    header = parsed.header
    link_info = parsed.link_info

    return {
        "valid_magic": parsed.valid_magic,
        "classification": classification,
        "fired_rules": fired,
        "indicator_flags": sorted(flags),
        "anomalies": parsed.anomalies,

        # --- what runs ---
        "target": cmd.target,
        "target_source": cmd.target_source,
        "target_basename": cmd.target_basename,
        "is_lolbin": cmd.is_lolbin,
        "target_disagreement": cmd.target_disagreement,
        "arguments": parsed.arguments,
        "arguments_length": len(parsed.arguments or ""),
        "argument_count": cmd.argument_count,
        "command_line": cmd.command_line,
        "working_dir": parsed.working_dir,
        "name_string": parsed.name_string,
        "relative_path": parsed.relative_path,
        "icon_location": parsed.icon_location,
        "icon_index": header.icon_index,
        "icon_masquerade": cmd.icon_masquerade,
        "remote_icon": cmd.remote_icon,
        "double_extension": cmd.double_extension,
        "traversal_depth": cmd.traversal_depth,
        "matched_patterns": cmd.matches,
        "urls": cmd.urls,
        "suspicious_hosts": cmd.suspicious_hosts,
        "deobfuscated_iocs": cmd.deobfuscated_iocs,
        "deobfuscation_chains": cmd.deobfuscation_chains,

        # --- padding evasion ---
        "arg_padding": asdict(cmd.arg_padding),
        "path_padding": asdict(cmd.path_padding),

        # --- structure ---
        "link_flags": header.flag_names,
        "file_attributes": header.attribute_names,
        "show_command": header.show_command_name,
        "hotkey": header.hotkey,
        "target_file_size": header.target_file_size,
        "creation_time": header.creation_time,
        "access_time": header.access_time,
        "write_time": header.write_time,
        "extra_blocks": parsed.extra_blocks,
        "env_target": parsed.env_target,
        "icon_env_target": parsed.icon_env_target,
        "darwin_id": parsed.darwin_id,
        "shim_layer": parsed.shim_layer,
        "known_folder_id": parsed.known_folder_id,
        "special_folder_id": parsed.special_folder_id,

        # --- link info ---
        "local_base_path": link_info.local_base_path if link_info else "",
        "net_name": link_info.net_name if link_info else "",
        "drive_serial": link_info.drive_serial if link_info else None,
        "volume_label": link_info.volume_label if link_info else "",

        # --- attribution ---
        "machine_id": parsed.machine_id,
        "mac_address": parsed.mac_address,
        "mac_vendor": parsed.mac_vendor,
        "droid_volume_guid": parsed.droid_volume_guid,
        "droid_file_guid": parsed.droid_file_guid,
        "droid_birth_differs": parsed.droid_birth_differs,

        # --- LECmd-depth forensics ---
        "shell_items": [asdict(item) for item in parsed.shell_items],
        "shell_item_count": len(parsed.shell_items),
        "property_store": parsed.property_store,

        # --- payload carriage ---
        "file_size": parsed.file_size,
        "entropy": round(parsed.entropy, 3),
        "parsed_end": parsed.parsed_end,
        "overlay": overlay,
        "embedded_executables": embedded,
    }


def _describe_overlay(
    data: bytes,
    parsed: ParsedLnk,
    source_name: str,
    *,
    total_size: int | None = None,
    truncated: bool = False,
) -> dict | None:
    """Carve and characterise anything appended past the terminal block.

    Nothing in [MS-SHLLINK] puts bytes there, so any overlay is anomalous
    by construction. Unit 42 group it as one of four malicious strategies
    ("overlay execution"), extracted in ~95% of cases by findstr, mshta or
    PowerShell reading the shortcut back off disk.

    Args:
        data:        The whole file.
        parsed:      The parse result, which records where it stopped.
        source_name: The shortcut's filename, used to label the carved
                     blob in the report.

    Returns:
        A description of the overlay, or None when there is none.

    The signature match is tried twice per candidate: once against the
    payload with leading padding stripped, once against its raw start.
    Builders pad the gap between the terminal block and the payload with
    nulls and newlines, so the stripped view is usually the right one —
    but a payload whose own first bytes are meaningful padding would be
    missed by stripping alone, which is why the raw view is kept as
    well.

    The hashes cover the payload as carved, padding included. That is
    the form an extraction command reads back off disk, so it is the
    form worth looking up.

    When the read was truncated the digests are omitted entirely rather
    than computed over the prefix. A hash of the part that happened to
    be read would be forwarded to VirusTotal as though it identified the
    payload; the size and offset still describe it honestly.
    """
    if parsed.overlay_offset is None or parsed.overlay_size <= 0:
        return None

    payload = data[parsed.overlay_offset:]
    if not payload and not truncated:
        return None

    real_size = (
        total_size - parsed.overlay_offset
        if truncated and total_size is not None
        else len(payload)
    )

    kind, description = "unknown", "Unrecognised appended data"
    stripped = payload.lstrip(b"\x00\r\n \t")[:16]
    for signature, sig_kind, sig_desc in _OVERLAY_SIGNATURES:
        if stripped.startswith(signature) or payload[:16].startswith(signature):
            kind, description = sig_kind, sig_desc
            break

    return {
        "offset": parsed.overlay_offset,
        "size": real_size,
        "kind": kind,
        "description": description,
        "truncated": truncated,
        "entropy": None if truncated else round(shannon_entropy(payload), 3),
        "md5": None if truncated else hashlib.md5(payload).hexdigest(),
        "sha256": None if truncated else hashlib.sha256(payload).hexdigest(),
        "name": f"{source_name}::overlay",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skipped(reason: str) -> dict:
    """A file this module does not own, or will not open.

    Args:
        reason: Shown to the user as the skip explanation.

    Returns:
        The standard dict with ``status="skipped"`` and no score.

    Distinct from :func:`_error`: a skip means the question does not
    apply, an error means it applied and could not be answered.
    """
    return {
        "module": "lnk_analysis",
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

    Scores zero deliberately: an analysis that did not run must not
    contribute to a verdict in either direction.
    """
    return {
        "module": "lnk_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
