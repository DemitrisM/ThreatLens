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
    """Module entry point — returns the standard result dict."""
    try:
        if not file_path.exists():
            return _error("File does not exist")

        if not is_lnk_file(file_path):
            return _skipped("Not applicable — not a Windows shortcut")

        max_size = int(config.get("max_lnk_size_mb", _DEFAULT_MAX_SIZE_MB))
        size = file_path.stat().st_size
        if size > max_size * 1024 * 1024:
            return _skipped(
                f"File exceeds lnk_analysis size cap ({max_size} MiB)"
            )

        codepage = str(config.get("lnk_ansi_codepage", _DEFAULT_CODEPAGE))
        return _analyse(file_path, codepage)

    except Exception as exc:  # noqa: BLE001
        logger.error("lnk_analysis crashed on %s: %s", file_path, exc)
        return _error(f"Analysis error: {exc}")


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def _analyse(file_path: Path, codepage: str) -> dict:
    data = file_path.read_bytes()
    parsed = parse_bytes(data, codepage=codepage)
    overlay = _describe_overlay(data, parsed, file_path.name)
    cmd = command_analysis.analyse(parsed, file_path.name)

    flags = derive_flags(parsed, cmd, overlay_kind=overlay["kind"] if overlay else "")
    score_delta, reason, fired, classification = score_lnk(flags)

    embedded = []
    if overlay and overlay["kind"] != "unknown":
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


def _describe_overlay(data: bytes, parsed: ParsedLnk, source_name: str) -> dict | None:
    """Carve and characterise anything appended past the terminal block.

    Nothing in [MS-SHLLINK] puts bytes there, so any overlay is anomalous
    by construction. Unit 42 group it as one of four malicious strategies
    ("overlay execution"), extracted in ~95% of cases by findstr, mshta or
    PowerShell reading the shortcut back off disk.
    """
    if parsed.overlay_offset is None or parsed.overlay_size <= 0:
        return None

    payload = data[parsed.overlay_offset:]
    if not payload:
        return None

    kind, description = "unknown", "Unrecognised appended data"
    stripped = payload.lstrip(b"\x00\r\n \t")[:16]
    for signature, sig_kind, sig_desc in _OVERLAY_SIGNATURES:
        if stripped.startswith(signature) or payload[:16].startswith(signature):
            kind, description = sig_kind, sig_desc
            break

    return {
        "offset": parsed.overlay_offset,
        "size": len(payload),
        "kind": kind,
        "description": description,
        "entropy": round(shannon_entropy(payload), 3),
        "md5": hashlib.md5(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "name": f"{source_name}::overlay",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skipped(reason: str) -> dict:
    return {
        "module": "lnk_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    return {
        "module": "lnk_analysis",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
