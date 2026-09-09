"""PE file analysis module.

Uses pefile to extract headers, sections with per-section Shannon
entropy, imports/exports, digital signature status, packer detection,
and a wide range of PEStudio/DIE/Manalyze/CAPE-inspired structural
indicators. Returns the standard module result dict with score_delta
and reason. All extraction is wrapped in try/except — pe_analysis
NEVER kills the pipeline on a malformed PE; fields default to
empty/None when an indicator can't be computed (graceful degradation).

Entropy calculation: Shannon entropy formula, per-section (not whole
file). Sections with entropy > 7.0 are flagged. Normal `.text`
entropy is roughly 5.5–6.5; close to 8.0 means almost certainly
packed or encrypted.

Structural indicators surfaced in `data` (terminal + HTML reporters
render them in the "PE Structural Indicators" panel):

- `compiled_language` — `"go" | "rust" | "nim" | None` (fingerprint
  via `.symtab` / `Go build ID:`, `rust_panic` / `/rustc/`, `nimrtl`).
- `dll_characteristics_flags` — `{aslr, dep, cfg, seh,
  high_entropy_va, force_integrity}` from
  `IMAGE_DLLCHARACTERISTICS_*`. ASLR + DEP missing on a modern binary
  is a strong "old or stripped" signal; CFG missing is normal for
  many malware families and Go/Rust binaries.
- `entry_point_section` — `{section, anomaly}`. Anomaly fires when
  AddressOfEntryPoint lands outside a recognised code section
  (`.text`, `code`, `.code`, `text`, `CODE`, `INIT`) or outside every
  section entirely — packers and unpackers commonly redirect entry
  into `.rsrc`, `.data`, or a custom section.
- `section_size_mismatch` — sections whose VirtualSize is much larger
  than RawSize (>4× and >0x10000 absolute delta), plus sections with a
  zero RawSize and a non-trivial VirtualSize outside `.bss`/`.data`/
  `.tls`. Classic packed-code marker.
- `rich_header` — `{present, n_entries, corrupted, checksum, tools}`.
  Absent on non-MS toolchains (Go/Rust/MinGW). Corruption is verified
  by recomputing the linker XOR checksum (rotate-left over the DOS
  header bytes with `e_lfanew` zeroed, then over the Comp.ID/count
  pairs) and comparing against the stored value. `tools` is a coarse
  toolchain-family summary derived from the high 16 bits of each
  Comp.ID.
- `pe_checksum` — `{stored, computed, mismatch_signed}`. Recomputes
  `OptionalHeader.CheckSum` via pefile's `generate_checksum()`. A
  mismatch on a *signed* binary is a strong post-signing-tamper
  signal (+10). On unsigned binaries it's reported informationally
  (most compilers leave the field zero anyway).
- `import_footprint` — `{dll_count, is_kernel32_only, loader_only}`.
  A native PE that imports only `kernel32.dll` is the canonical
  packer / shellcode-loader shape; if the imported function set is
  also limited to `LoadLibrary*` + `GetProcAddress` (+ a couple of
  helpers) we tag it as `loader_only`. .NET binaries are exempt
  (they legitimately import only `mscoree!_CorExeMain`).
- `resource_types` — `{types: {RT_*: total_bytes}, largest_rcdata,
  autoit}`. Walks `DIRECTORY_ENTRY_RESOURCE` and tallies per-type
  sizes. RT_RCDATA blobs ≥1 KiB are sampled and matched against the
  AutoIt `AU3!` / `AutoIt v3` markers — AutoIt-compiled binaries are
  a common commodity-malware wrapper (+15). A large RT_RCDATA blob
  without AutoIt markers is still flagged as a probable embedded
  payload (+5).
- `installer` — short name of the detected installer wrapper
  (`NSIS`, `InnoSetup`, `Wise`, `InstallShield`, `7-Zip SFX`) or
  `None`. Many droppers ship inside off-the-shelf installers; +5.
- `forwarded_exports` — count of export entries that forward to
  another DLL. Normal in API set DLLs; suspicious on a non-DLL EXE
  (DLL-hijack proxy candidate).
- `section_permission_anomalies` — list of sections whose permissions
  don't match their conventional role (writable `.text`, executable
  `.data` / `.rdata`, writable `.rdata`). +10.
- `dos_stub` — `{modified, preview}`. Default stub is `"This program
  cannot be run in DOS mode."`; modified stubs are a fingerprinting
  opportunity (Cobalt Strike beacons, custom loaders).
- `debug_info` — `{pdb_path, suspicious_pdb, pdb_username}`.
  Suspicious PDB tokens: `loader`, `stub`, `inject`, `redline`,
  `agent`, `payload`, `crypter`, etc. Username is extracted from
  `C:\\Users\\<name>\\...` paths.
- `version_info` — `{CompanyName, ProductName, FileDescription, ...}`
  extracted from VS_VERSIONINFO. Impersonation (Microsoft / Adobe /
  Google metadata on an unsigned binary) scores +10.
- `embedded_pe` — `{where, offset}` if a second `MZ` header is found
  in `.rsrc` or the overlay (multi-stage dropper signal).
- `hollowing_apis` — list of process-injection / hollowing APIs found
  in the import table (`SetThreadContext`, `ResumeThread`,
  `NtUnmapViewOfSection`, `WriteProcessMemory`, `VirtualAllocEx`,
  `CreateProcessA/W` with the suspended flag, `ZwUnmapViewOfSection`).
  Two or more = process-hollowing pattern.
- `api_categories` — coarse behavioural buckets the imports cover
  (`injection`, `execution`, `loader`, `antidebug`, `network`,
  `persistence`, `keylog`, `crypto`, `privilege`). Diversity of 3
  scores +5, 4 scores +10, 5 or more scores +15 as a multi-stage
  malware profile.
- `dynamic_api_resolution` — `{count, apis}`. Suspicious WinAPI names
  appearing as raw strings only (not in IAT) — the GetProcAddress
  runtime-resolution pattern used by packers, shellcode loaders, and
  most stealers.
- `certificate` — `{present, common_name, issuer_hint}` from
  `IMAGE_DIRECTORY_ENTRY_SECURITY` Authenticode subject.
- `rwx_sections`, `has_tls_callbacks`, `overlay`, `resources` —
  classic structural anomalies (RWX, pre-main TLS code execution,
  overlay/resource entropy).

See `docs/scoring.md` for the per-indicator score weights.

Design notes
------------
Roughly forty indicators feed one score, and none of them is conclusive on
its own. Packing, a missing signature, high entropy and a Go build are each
ordinary in isolation; what identifies malware is the combination. The
weights are therefore deliberately small and additive, and the pipeline
clamps the total once at the end rather than letting any one finding
dominate.

Several checks are ordered because later ones depend on earlier results:
`_is_dotnet` runs before the import scoring (a managed binary legitimately
imports one function), and `_check_signature` runs before both the
certificate extraction and the checksum comparison (a checksum mismatch only
means tampering on a file that was signed in the first place).

`pe.close()` is in a `finally` so the memory map is released even when
analysis raises — without it a `triage` run over a large directory would
accumulate open mappings until it hit the file-descriptor limit.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import pefile

    _HAS_PEFILE = True
except ImportError:
    _HAS_PEFILE = False
    logger.warning("pefile not available — PE analysis disabled")

from .fingerprint import _analyse_dll_characteristics, _detect_compiled_language
from .headers import _check_timestamp, _extract_headers
from .imports import (
    _API_CATEGORIES,
    _HOLLOWING_API_INDICATORS,
    _classify_import_footprint,
    _count_forwarded_exports,
    _detect_dynamic_api_resolution,
    _extract_exports,
    _extract_imports,
)
from .metadata import (
    _analyse_dos_stub,
    _analyse_rich_header,
    _extract_debug_info,
    _extract_version_info,
    _score_version_info,
)
from .packers import _detect_installer, _detect_packers, _is_dotnet
from .resources import _analyse_resource_types, _analyse_resources
from .sections import (
    _analyse_sections,
    _detect_section_permission_anomalies,
    _detect_section_size_mismatch,
    _find_rwx_sections,
)
from .signing import _check_pe_checksum, _check_signature, _extract_certificate_info
from .structure import (
    _analyse_overlay,
    _check_entry_point,
    _find_embedded_pe,
    _has_tls_callbacks,
)


def run(file_path: Path, config: dict) -> dict:
    """Analyse a PE file and return structured findings with score contributions.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict.

    Returns:
        Standard module result dict.
    """
    if not _HAS_PEFILE:
        return {
            "module": "pe_analysis",
            "status": "skipped",
            "data": {},
            "score_delta": 0,
            "reason": "pefile library not installed",
        }

    try:
        pe = pefile.PE(str(file_path))
    except pefile.PEFormatError as exc:
        logger.info("Not a valid PE file — skipping PE analysis: %s", exc)
        return {
            "module": "pe_analysis",
            "status": "skipped",
            "data": {},
            "score_delta": 0,
            "reason": f"Not a valid PE file: {exc}",
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("PE parsing failed: %s", exc)
        return {
            "module": "pe_analysis",
            "status": "error",
            "data": {},
            "score_delta": 0,
            "reason": f"PE parsing error: {exc}",
        }

    try:
        data, score_delta, reasons = _analyse_pe(pe)
    except Exception as exc:  # noqa: BLE001
        logger.error("PE analysis raised an exception: %s", exc)
        return {
            "module": "pe_analysis",
            "status": "error",
            "data": {},
            "score_delta": 0,
            "reason": f"Analysis error: {exc}",
        }
    finally:
        pe.close()

    reason_text = "; ".join(reasons) if reasons else "No suspicious PE indicators found"

    return {
        "module": "pe_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


def _analyse_pe(pe: "pefile.PE") -> tuple[dict, int, list[str]]:
    """Run all PE sub-analyses and aggregate findings.

    Args:
        pe: A parsed ``pefile.PE`` object, owned by the caller — this
            function does not close it.

    Returns:
        (data_dict, total_score_delta, list_of_reason_strings)

        Every indicator appends to `reasons` only when it actually
        fires, so the reason list doubles as the audit trail for the
        score: each entry names one contribution, and an empty list
        means nothing scored.
    """
    score_delta = 0
    reasons: list[str] = []

    # --- Headers ---
    headers = _extract_headers(pe)

    # --- Sections + entropy ---
    sections, entropy_delta, entropy_reasons = _analyse_sections(pe)
    score_delta += entropy_delta
    reasons.extend(entropy_reasons)

    # ------------------------------------------------------------------
    # .NET detection, deliberately early.
    #
    # Several later checks would fire on every managed binary without
    # it: a .NET assembly imports exactly one function, has no real
    # native import table, and often carries a high-entropy .text.
    # ------------------------------------------------------------------
    # --- .NET detection (needed before import scoring decisions) ---
    is_dotnet = _is_dotnet(pe)

    # --- Imports ---
    imports, suspicious_imports = _extract_imports(pe)
    total_imports = sum(len(funcs) for funcs in imports.values())
    # Tiered rather than per-API: scoring each suspicious import
    # individually would let one API-heavy binary outweigh every
    # structural finding combined.
    if suspicious_imports:
        # Tier the import score by how many suspicious APIs are present.
        n_susp = len(suspicious_imports)
        if n_susp >= 20:
            score_delta += 20
            tier_note = "extensive"
        elif n_susp >= 10:
            score_delta += 15
            tier_note = "many"
        elif n_susp >= 5:
            score_delta += 10
            tier_note = "several"
        else:
            score_delta += 5
            tier_note = "few"
        top_five = sorted(suspicious_imports)[:5]
        suffix = f" (+{n_susp - 5} more)" if n_susp > 5 else ""
        reasons.append(
            f"Suspicious imports ({tier_note}): {', '.join(top_five)}{suffix}"
        )

    # Tiny native import table is itself an indicator of dynamic
    # API resolution / packing — but only on non-.NET binaries
    # (.NET binaries legitimately import only mscoree!_CorExeMain).
    if not is_dotnet and 0 < total_imports < 5:
        score_delta += 5
        reasons.append(
            f"Very small import table ({total_imports} functions) — "
            "likely dynamic API resolution or packed"
        )

    # --- Process-injection / hollowing API combo ---
    # Two or more of the hollowing-API set co-occurring is a strong
    # indicator of a process-injection routine. Award a bonus on top of
    # the per-import score.
    hollow_overlap = suspicious_imports & _HOLLOWING_API_INDICATORS
    if len(hollow_overlap) >= 2:
        score_delta += 10
        sample = sorted(hollow_overlap)[:4]
        reasons.append(
            f"Process-injection API combo: {', '.join(sample)} — "
            "classic hollowing / shellcode loader pattern"
        )

    # --- Behaviour-category diversity ---
    # A binary that touches many distinct API categories is exhibiting
    # multi-stage malware behaviour even if no single category is large.
    behaviour_cats = {
        cat for cat, apis in _API_CATEGORIES.items()
        if suspicious_imports & apis
    }
    if len(behaviour_cats) >= 5:
        score_delta += 15
        reasons.append(
            f"Spans {len(behaviour_cats)} suspicious API categories: "
            f"{', '.join(sorted(behaviour_cats))} — multi-stage malware profile"
        )
    elif len(behaviour_cats) >= 4:
        score_delta += 10
        reasons.append(
            f"Spans {len(behaviour_cats)} suspicious API categories: "
            f"{', '.join(sorted(behaviour_cats))}"
        )
    elif len(behaviour_cats) == 3:
        score_delta += 5
        reasons.append(
            f"Spans {len(behaviour_cats)} suspicious API categories: "
            f"{', '.join(sorted(behaviour_cats))}"
        )

    # --- Exports ---
    exports = _extract_exports(pe)

    # ------------------------------------------------------------------
    # Digital signature.
    #
    # Asymmetric on purpose: absence scores, presence does not. A valid
    # signature would be evidence of provenance, but this only checks
    # that a signature EXISTS, and commodity stealers routinely ship
    # with stolen or self-signed certificates. Rewarding presence would
    # therefore reward the attacker who bothered to sign.
    # ------------------------------------------------------------------
    # --- Digital signature ---
    # Presence-only check: we never validated the signature, and many
    # commodity stealers (Lumma, Vidar, …) ship with stolen / abused
    # certificates. Treat presence as neutral; only the absence of a
    # signature counts against the file.
    has_signature = _check_signature(pe)
    if not has_signature:
        score_delta += 10
        reasons.append("No digital signature found")
    else:
        reasons.append(
            "PE is digitally signed (presence only — validity not verified)"
        )

    # --- Packer detection ---
    packers_found = _detect_packers(pe, sections)
    if packers_found:
        score_delta += 15
        reasons.append(f"Packer detected: {', '.join(packers_found)}")

    # ------------------------------------------------------------------
    # Section count, anomalous at both extremes.
    #
    # A typical compiler emits 4-6. Many sections suggest an appended or
    # rebuilt table; exactly one means the whole binary is a single
    # blob, which is what a shellcode loader looks like — hence the
    # heavier weight on the low end.
    # ------------------------------------------------------------------
    # --- Section count anomaly ---
    n_sections = len(sections)
    if n_sections >= 8:
        score_delta += 5
        reasons.append(
            f"Unusual section count ({n_sections}) — typical PEs have 4–6"
        )
    elif n_sections == 1:
        # Single-section binaries are typically heavily packed shellcode loaders.
        score_delta += 10
        reasons.append("Single-section PE — likely shellcode loader / heavily packed")

    # --- RWX (read+write+execute) sections — strong self-modify signal ---
    rwx_sections = _find_rwx_sections(pe)
    if rwx_sections:
        score_delta += 15
        reasons.append(
            f"Read+Write+Execute section(s): {', '.join(rwx_sections)} — "
            "self-modifying / unpacker stub"
        )

    # --- TLS callbacks (anti-debug / pre-main code execution) ---
    has_tls_callbacks = _has_tls_callbacks(pe)
    if has_tls_callbacks:
        score_delta += 5
        reasons.append("TLS callbacks present — common anti-debug technique")

    # --- Overlay analysis (data after the last section) ---
    overlay_info = _analyse_overlay(pe)
    if overlay_info["size"] > 0 and overlay_info["entropy"] >= 7.0:
        score_delta += 10
        reasons.append(
            f"High-entropy overlay ({overlay_info['size']} bytes, "
            f"entropy {overlay_info['entropy']:.2f}) — embedded encrypted payload"
        )

    # --- Resource section anomalies (large/high-entropy .rsrc) ---
    rsrc_info = _analyse_resources(pe, sections)
    if rsrc_info.get("high_entropy"):
        score_delta += 10
        reasons.append(
            f"High-entropy .rsrc section ({rsrc_info['entropy']:.2f}) — "
            "likely embedded encrypted payload"
        )

    # --- Compiled-language hints (Go / Rust / Nim are increasingly
    #     abused by modern malware: Lumma, Sliver, Brute Ratel, ChaosRAT) ---
    lang_hint = _detect_compiled_language(pe, sections)
    if lang_hint == "go":
        score_delta += 5
        reasons.append(
            "Go-compiled binary — language commonly abused by modern stealers/C2"
        )
    elif lang_hint == "rust":
        score_delta += 5
        reasons.append(
            "Rust-compiled binary — increasingly used by malware loaders"
        )
    elif lang_hint == "nim":
        score_delta += 10
        reasons.append(
            "Nim-compiled binary — heavily used by red-team / commodity malware"
        )

    # --- Packed .NET binary heuristic ---
    # A .NET assembly with a high-entropy .text section means the IL
    # bytecode itself is encrypted at rest — a defining trait of
    # ConfuserEx, .NET Reactor, and other commodity .NET packers.
    if is_dotnet:
        for s in sections:
            if s.get("name", "").lower() == ".text" and s.get("entropy", 0) >= 7.0:
                score_delta += 10
                reasons.append(
                    f"Packed .NET assembly — .text entropy {s['entropy']:.2f} "
                    "(IL bytecode encrypted on disk)"
                )
                break

    # ------------------------------------------------------------------
    # Imphash: a hash of the import table's names and order.
    #
    # Scores nothing by itself. Its value is comparative — samples from
    # one family built by one toolchain share an imphash even when every
    # byte of the payload differs, which makes it a pivot for
    # VirusTotal and for clustering across a triage run.
    # ------------------------------------------------------------------
    # --- Imphash (for clustering / future YARA fingerprinting) ---
    try:
        imphash = pe.get_imphash()
    except Exception:  # noqa: BLE001
        imphash = ""

    # --- DLL characteristics flags (ASLR / DEP / CFG / SEH) ---
    dll_flags = _analyse_dll_characteristics(pe)
    missing_mitigations = [k for k, v in dll_flags.items() if not v]
    # Most modern, legitimately-built executables enable ASLR + DEP at
    # minimum. Missing both is a strong red flag for a hand-crafted /
    # packed binary; missing one is mildly suspicious.
    if not dll_flags["aslr"] and not dll_flags["dep"]:
        score_delta += 10
        reasons.append(
            "Missing ASLR + DEP mitigations — non-standard build "
            "(packed / hand-rolled / ancient toolchain)"
        )
    elif missing_mitigations:
        # CFG and SEH being missing alone is common in older builds;
        # only worth a small note.
        if not dll_flags["aslr"]:
            score_delta += 5
            reasons.append("ASLR (DYNAMIC_BASE) disabled")
        elif not dll_flags["dep"]:
            score_delta += 5
            reasons.append("DEP (NX_COMPAT) disabled")

    # --- Entry-point validation ---
    ep_info = _check_entry_point(pe, sections)
    if ep_info["anomaly"]:
        score_delta += 10
        reasons.append(
            f"Entry point in unusual section '{ep_info['section']}' "
            "(not the standard code section) — likely packed/unpacker stub"
        )

    # --- Rich header (Microsoft compiler fingerprint) ---
    rich_info = _analyse_rich_header(pe)
    # Missing Rich header is normal for Go/Rust/Nim/MinGW binaries — no
    # score impact, just informational. But a present-but-corrupted Rich
    # header is a strong tampering signal.
    if rich_info.get("corrupted"):
        score_delta += 5
        reasons.append("Rich header present but checksum mismatch — likely tampered")

    # --- DOS stub anomaly ---
    dos_stub_info = _analyse_dos_stub(pe)
    if dos_stub_info["modified"]:
        score_delta += 5
        reasons.append(
            "Non-standard MS-DOS stub — replaced from default "
            "'This program cannot be run in DOS mode.'"
        )

    # --- PDB / debug path extraction ---
    debug_info = _extract_debug_info(pe)
    if debug_info.get("suspicious_pdb"):
        score_delta += 10
        reasons.append(
            f"Suspicious PDB debug path: {debug_info['pdb_path']} "
            "— leaks attacker project / username"
        )
    elif debug_info.get("pdb_path"):
        # NOTE: dead branch. A clean PDB path is already carried in
        # `data["debug_info"]` for the reporters, so there is nothing to
        # add here; kept as a marker of where an informational tier
        # would attach if one is ever added.
        # Path is present but not on the suspicious list — informational.
        pass

    # --- Resource version info (CompanyName / ProductName / …) ---
    version_info = _extract_version_info(pe)
    vi_score, vi_reason = _score_version_info(version_info)
    if vi_score:
        score_delta += vi_score
        reasons.append(vi_reason)

    # --- Section size mismatches (VirtualSize >> RawSize) ---
    size_mismatch = _detect_section_size_mismatch(pe, sections)
    if size_mismatch["count"] > 0:
        score_delta += 10
        reasons.append(
            f"{size_mismatch['count']} section(s) have VirtualSize >> "
            f"RawSize ({', '.join(size_mismatch['names'])}) — "
            "code unpacked at runtime"
        )

    # --- Embedded MZ executable inside .rsrc / overlay ---
    embedded_pe = _find_embedded_pe(pe)
    if embedded_pe:
        score_delta += 15
        reasons.append(
            f"Embedded PE/MZ payload found at {embedded_pe['where']} "
            f"(offset 0x{embedded_pe['offset']:x}) — second-stage executable"
        )

    # --- Dynamic API resolution detection ---
    # APIs that appear as strings in the file but NOT in the import
    # table are typically resolved at runtime via GetProcAddress — a
    # classic packer / shellcode loader trick.
    dyn_api_info = _detect_dynamic_api_resolution(pe, suspicious_imports)
    if dyn_api_info["count"] >= 5:
        score_delta += 10
        reasons.append(
            f"Dynamic API resolution likely — {dyn_api_info['count']} "
            "suspicious APIs appear as raw strings but are not in "
            "the import table (GetProcAddress pattern)"
        )

    # --- Authenticode certificate subject (best-effort) ---
    cert_info = _extract_certificate_info(pe) if has_signature else {}

    # --- Section permission anomalies (writable .text, exec .data, …) ---
    perm_anomalies = _detect_section_permission_anomalies(pe)
    if perm_anomalies:
        score_delta += 10
        reasons.append(
            "Section permission anomalies: "
            + ", ".join(perm_anomalies[:4])
        )

    # --- PE checksum (OptionalHeader.CheckSum) integrity ---
    checksum_info = _check_pe_checksum(pe, has_signature)
    if checksum_info.get("mismatch_signed"):
        score_delta += 10
        reasons.append(
            f"PE checksum mismatch on signed binary "
            f"(stored=0x{checksum_info['stored']:08x}, "
            f"computed=0x{checksum_info['computed']:08x}) — tampered after signing"
        )

    # --- Imported-DLL footprint (kernel32-only = packer marker) ---
    dll_footprint = _classify_import_footprint(imports, is_dotnet)
    if dll_footprint["is_kernel32_only"]:
        score_delta += 10
        reasons.append(
            "Only kernel32.dll imported — classic packer / shellcode-loader footprint"
        )
    elif dll_footprint["dll_count"] == 0 and not is_dotnet:
        # NOTE: dead branch — scores nothing. The tiny-import-table
        # check above only fires on `0 < total_imports < 5`, so a PE
        # with zero imports currently scores nothing from either. Left
        # as-is because closing the gap is a scoring change.
        # Already partially handled by tiny-import-table check, but a
        # zero-DLL native PE is its own red flag.
        pass

    # --- Resource type breakdown + AutoIt detection ---
    rsrc_types = _analyse_resource_types(pe)
    if rsrc_types.get("autoit"):
        score_delta += 15
        reasons.append(
            "AutoIt-compiled binary — common commodity-malware wrapper"
        )
    elif rsrc_types.get("large_rcdata", 0) >= 256 * 1024:
        # Big RT_RCDATA blob without AutoIt markers is still a strong
        # embedded-payload signal.
        score_delta += 5
        reasons.append(
            f"Large RT_RCDATA resource ({rsrc_types['large_rcdata']} bytes) — "
            "embedded payload likely"
        )

    # --- Installer / wrapper detection (NSIS / InnoSetup / Wise) ---
    installer = _detect_installer(pe, sections)
    if installer:
        # Installers are dual-use; we flag presence as informational
        # (+5) since malware frequently wraps droppers in NSIS/Inno.
        score_delta += 5
        reasons.append(
            f"{installer} installer wrapper detected — inspect dropped contents"
        )

    # --- Forwarded exports (DLL-hijack / proxy DLL hint) ---
    # Reports but does not score: forwarded exports are normal in API
    # set DLLs and only mildly odd elsewhere, so this earns a line in
    # the report without moving the number.
    forwarded = _count_forwarded_exports(pe)
    if forwarded >= 1:
        # A handful of forwarded exports are normal in API set DLLs;
        # only flag when present alongside an export table on a non-DLL.
        # 0x2000 is IMAGE_FILE_DLL in FileHeader.Characteristics. The
        # value was stringified to hex by _extract_headers for display,
        # so it has to be parsed back to test the bit.
        is_dll = bool(headers.get("characteristics")) and (
            int(headers["characteristics"], 16) & 0x2000
        )
        if not is_dll and forwarded >= 1:
            reasons.append(
                f"{forwarded} forwarded export(s) on a non-DLL binary — "
                "unusual"
            )

    # --- Anomalous compile timestamp ---
    ts_delta, ts_reason = _check_timestamp(headers)
    if ts_delta:
        score_delta += ts_delta
        reasons.append(ts_reason)

    # ------------------------------------------------------------------
    # Assemble the result.
    #
    # Every indicator is published whether or not it scored: the report
    # shows what was examined, not only what was damning, and a reader
    # needs the clean results to trust the flagged ones.
    # ------------------------------------------------------------------
    data = {
        "headers": headers,
        "sections": sections,
        "imports": imports,
        "total_imports": total_imports,
        "suspicious_imports": sorted(suspicious_imports) if suspicious_imports else [],
        "api_categories": sorted(behaviour_cats),
        "hollowing_apis": sorted(hollow_overlap),
        "exports": exports,
        "has_signature": has_signature,
        "certificate": cert_info,
        "packers_detected": packers_found,
        "is_dotnet": is_dotnet,
        "rwx_sections": rwx_sections,
        "has_tls_callbacks": has_tls_callbacks,
        "overlay": overlay_info,
        "resources": rsrc_info,
        "imphash": imphash,
        "section_count": n_sections,
        "compiled_language": lang_hint or None,
        "dll_characteristics_flags": dll_flags,
        "entry_point_section": ep_info,
        "rich_header": rich_info,
        "dos_stub": dos_stub_info,
        "debug_info": debug_info,
        "version_info": version_info,
        "section_size_mismatch": size_mismatch,
        "embedded_pe": embedded_pe,
        "dynamic_api_resolution": dyn_api_info,
        "section_permission_anomalies": perm_anomalies,
        "pe_checksum": checksum_info,
        "import_footprint": dll_footprint,
        "resource_types": rsrc_types,
        "installer": installer,
        "forwarded_exports": forwarded,
    }

    return data, score_delta, reasons
