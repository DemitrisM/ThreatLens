"""PE file analysis module.

Uses pefile to extract headers, sections with per-section Shannon entropy,
imports/exports, digital signature status, packer detection, and a wide
range of PEStudio/DIE/Manalyze-inspired structural indicators (RWX
sections, TLS callbacks, Rich header presence, DLL characteristics
flags, entry-point validation, embedded MZ in resources, PDB debug
path leakage, version-info metadata, dynamic API resolution markers,
section size mismatches and more). Returns a standard module result
dict with score_delta and reason.
"""

import logging
import math
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import pefile

    _HAS_PEFILE = True
except ImportError:
    _HAS_PEFILE = False
    logger.warning("pefile not available — PE analysis disabled")

# Suspicious imports that indicate potentially malicious behaviour.
_SUSPICIOUS_IMPORTS = {
    # Memory allocation / process injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtWriteVirtualMemory", "NtCreateThreadEx",
    "QueueUserAPC", "NtQueueApcThread",
    "RtlCreateUserThread",
    # Process hollowing / thread manipulation (modern injection)
    "OpenProcess", "OpenThread",
    "SetThreadContext", "GetThreadContext",
    "Wow64SetThreadContext", "Wow64GetThreadContext",
    "ResumeThread", "SuspendThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "NtMapViewOfSection", "ZwMapViewOfSection",
    "NtCreateSection", "ZwCreateSection",
    # Code execution
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW",
    "CreateProcessInternalA", "CreateProcessInternalW",
    # DLL injection / dynamic resolution
    "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    # Privilege / token manipulation
    "OpenProcessToken", "AdjustTokenPrivileges",
    "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    "ImpersonateLoggedOnUser", "DuplicateTokenEx",
    # Anti-debug / anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "OutputDebugStringA", "OutputDebugStringW",
    "FindWindowA", "FindWindowW",  # used to detect analysis windows
    # Crypto (often used for payload encryption)
    "CryptEncrypt", "CryptDecrypt",
    "CryptAcquireContextA", "CryptAcquireContextW",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
    # Networking
    "InternetOpenA", "InternetOpenW",
    "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequestA", "HttpSendRequestW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "WSASocketA", "WSASocketW",
    "connect", "send", "recv", "WSAConnect",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    # Registry persistence
    "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    # Keylogging / hooking
    "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "GetKeyState",
    "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW",
    # File-system staging
    "CreateFileMappingA", "CreateFileMappingW",
    "MapViewOfFile", "UnmapViewOfFile",
}

# APIs that, when present *together*, almost guarantee a process-hollowing
# / shellcode-injection routine. We award an extra bonus if any TWO of
# these are imported (the combo is rare in benign software).
_HOLLOWING_API_INDICATORS = frozenset({
    "SetThreadContext", "Wow64SetThreadContext",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "NtMapViewOfSection", "ZwMapViewOfSection",
    "WriteProcessMemory", "NtWriteVirtualMemory",
    "VirtualAllocEx",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "QueueUserAPC", "NtQueueApcThread",
    "ResumeThread",  # combined with SetThreadContext = classic hollowing
})

# Buckets used to score behaviour-category diversity. A binary that
# imports across many distinct buckets (e.g. anti-debug + persistence
# + execution + network) is performing classic multi-stage malware
# behaviour even if no single bucket has many entries.
_API_CATEGORIES: dict[str, frozenset[str]] = {
    "injection": frozenset({
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtWriteVirtualMemory", "NtCreateThreadEx",
        "QueueUserAPC", "NtQueueApcThread", "RtlCreateUserThread",
        "OpenProcess", "OpenThread",
        "SetThreadContext", "GetThreadContext",
        "Wow64SetThreadContext", "Wow64GetThreadContext",
        "ResumeThread", "SuspendThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "NtMapViewOfSection", "ZwMapViewOfSection",
        "NtCreateSection", "ZwCreateSection",
    }),
    "execution": frozenset({
        "WinExec", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW",
        "CreateProcessA", "CreateProcessW",
        "CreateProcessInternalA", "CreateProcessInternalW",
    }),
    "loader": frozenset({
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    }),
    "antidebug": frozenset({
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugStringA", "OutputDebugStringW",
        "FindWindowA", "FindWindowW",
    }),
    "network": frozenset({
        "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WSAStartup", "WSASocketA", "WSASocketW",
        "connect", "send", "recv", "WSAConnect",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    }),
    "persistence": frozenset({
        "RegOpenKeyExA", "RegOpenKeyExW",
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
    }),
    "keylog": frozenset({
        "SetWindowsHookExA", "SetWindowsHookExW",
        "GetAsyncKeyState", "GetKeyState",
        "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW",
    }),
    "crypto": frozenset({
        "CryptEncrypt", "CryptDecrypt",
        "CryptAcquireContextA", "CryptAcquireContextW",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
    }),
    "privilege": frozenset({
        "OpenProcessToken", "AdjustTokenPrivileges",
        "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "ImpersonateLoggedOnUser", "DuplicateTokenEx",
    }),
}

# Known packer section names and signatures.
_PACKER_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", "UPX!",
    ".mpress1", ".mpress2", "MPRESS1", "MPRESS2",
    ".themida", ".vmp0", ".vmp1", ".vmp2",
    ".aspack", ".adata",
    ".nsp0", ".nsp1",  # NSPack
    ".petite",
    ".yP",  # Y0da Packer
    ".packed",
}

# Common packer strings found in PE overlay or headers.
_PACKER_SIGNATURES = {
    "UPX": "UPX",
    "MPRESS": "MPRESS",
    "Themida": "Themida",
    "VMProtect": "VMProtect",
    "ASPack": "ASPack",
    "PECompact": "PECompact",
    "Petite": "Petite",
    "NSPack": "NSPack",
}

# Machine type constants.
_MACHINE_TYPES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x86-64 (64-bit)",
    0x01C0: "ARM",
    0x01C4: "ARMv7 Thumb-2",
    0xAA64: "ARM64",
    0x0200: "IA-64",
}


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

    Returns:
        (data_dict, total_score_delta, list_of_reason_strings)
    """
    score_delta = 0
    reasons: list[str] = []

    # --- Headers ---
    headers = _extract_headers(pe)

    # --- Sections + entropy ---
    sections, entropy_delta, entropy_reasons = _analyse_sections(pe)
    score_delta += entropy_delta
    reasons.extend(entropy_reasons)

    # --- .NET detection (needed before import scoring decisions) ---
    is_dotnet = _is_dotnet(pe)

    # --- Imports ---
    imports, suspicious_imports = _extract_imports(pe)
    total_imports = sum(len(funcs) for funcs in imports.values())
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
    forwarded = _count_forwarded_exports(pe)
    if forwarded >= 1:
        # A handful of forwarded exports are normal in API set DLLs;
        # only flag when present alongside an export table on a non-DLL.
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


def _extract_headers(pe: "pefile.PE") -> dict:
    """Extract key PE header fields."""
    file_header = pe.FILE_HEADER
    optional_header = pe.OPTIONAL_HEADER

    machine = file_header.Machine
    machine_str = _MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04X})")

    # Compile timestamp.
    timestamp_raw = file_header.TimeDateStamp
    try:
        compile_time = datetime.fromtimestamp(timestamp_raw, tz=timezone.utc).isoformat()
    except (OSError, ValueError, OverflowError):
        compile_time = f"Invalid timestamp ({timestamp_raw})"

    return {
        "machine": machine_str,
        "compile_timestamp": compile_time,
        "compile_timestamp_raw": timestamp_raw,
        "entry_point": hex(optional_header.AddressOfEntryPoint),
        "image_base": hex(optional_header.ImageBase),
        "number_of_sections": file_header.NumberOfSections,
        "characteristics": hex(file_header.Characteristics),
        "dll_characteristics": hex(optional_header.DllCharacteristics),
        "subsystem": optional_header.Subsystem,
    }


def _analyse_sections(pe: "pefile.PE") -> tuple[list[dict], int, list[str]]:
    """Analyse PE sections and compute per-section Shannon entropy.

    Returns:
        (section_list, score_delta, reason_strings)

    The .rsrc section is excluded from the high-entropy score here —
    legitimate resources (icons, JPEGs, compressed AutoIt scripts) often
    push entropy above 7.0, and that case is handled separately by
    ``_analyse_resources`` so we never double-count the same finding.
    """
    sections = []
    score_delta = 0
    reasons: list[str] = []
    high_entropy_sections = []

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        entropy = section.get_entropy()
        raw_size = section.SizeOfRawData
        virtual_size = section.Misc_VirtualSize

        section_info = {
            "name": name,
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "entropy": round(entropy, 4),
            "characteristics": hex(section.Characteristics),
        }
        sections.append(section_info)

        # Skip the resource section here — handled in _analyse_resources.
        if name.lower() == ".rsrc":
            continue

        # Flag high-entropy sections (> 7.0 suggests packing/encryption).
        if entropy > 7.0:
            high_entropy_sections.append((name, entropy))

    if high_entropy_sections:
        # Score scales: 7.0-7.5 = +15, 7.5+ = +20
        max_entropy = max(e for _, e in high_entropy_sections)
        delta = 20 if max_entropy >= 7.5 else 15
        score_delta += delta
        section_strs = [f"{n} ({e:.2f})" for n, e in high_entropy_sections]
        reasons.append(
            f"High entropy sections: {', '.join(section_strs)} — likely packed/encrypted"
        )

    return sections, score_delta, reasons


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in frequency:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _extract_imports(pe: "pefile.PE") -> tuple[dict, set]:
    """Extract imported DLLs and functions, flag suspicious ones.

    Returns:
        (imports_dict, set_of_suspicious_function_names)
    """
    imports: dict[str, list[str]] = {}
    suspicious: set[str] = set()

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports, suspicious

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="replace")
        functions = []
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode("utf-8", errors="replace")
                functions.append(func_name)
                if func_name in _SUSPICIOUS_IMPORTS:
                    suspicious.add(func_name)
            else:
                functions.append(f"ordinal_{imp.ordinal}")
        imports[dll_name] = functions

    return imports, suspicious


def _extract_exports(pe: "pefile.PE") -> list[str]:
    """Extract exported function names."""
    exports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports.append(exp.name.decode("utf-8", errors="replace"))
        else:
            exports.append(f"ordinal_{exp.ordinal}")
    return exports


def _check_signature(pe: "pefile.PE") -> bool:
    """Check whether the PE has a digital signature (Authenticode).

    Only checks for the presence of the security directory entry,
    not whether the signature is valid (that requires OS-level verification).
    """
    # IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    security_dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= security_dir_index:
        return False

    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_index]
    return security_dir.VirtualAddress != 0 and security_dir.Size != 0


def _detect_packers(pe: "pefile.PE", sections: list[dict]) -> list[str]:
    """Detect known packers by section names and PE characteristics.

    Returns a list of packer names found (empty list if none detected).
    """
    found: list[str] = []
    section_names = {s["name"] for s in sections}

    # Check section names against known packer section names.
    for name in section_names:
        name_upper = name.upper().strip()
        if name_upper.startswith("UPX"):
            if "UPX" not in found:
                found.append("UPX")
        elif name_upper.startswith("MPRESS") or name_upper.startswith(".MPRESS"):
            if "MPRESS" not in found:
                found.append("MPRESS")
        elif name_upper in (".THEMIDA", "THEMIDA"):
            if "Themida" not in found:
                found.append("Themida")
        elif name_upper.startswith(".VMP"):
            if "VMProtect" not in found:
                found.append("VMProtect")
        elif name_upper in (".ASPACK", ".ADATA"):
            if "ASPack" not in found:
                found.append("ASPack")
        elif name_upper == ".PETITE":
            if "Petite" not in found:
                found.append("Petite")
        elif name_upper.startswith(".NSP"):
            if "NSPack" not in found:
                found.append("NSPack")

    # Check for UPX magic bytes in the PE overlay (after all sections).
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            overlay_data = pe.__data__[overlay_offset:overlay_offset + 256]
            if b"UPX!" in overlay_data and "UPX" not in found:
                found.append("UPX")
    except Exception:  # noqa: BLE001
        pass

    return found


def _is_dotnet(pe: "pefile.PE") -> bool:
    """Detect whether the PE is a .NET (CLR) assembly.

    Checks for the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14).
    """
    com_descriptor_index = pefile.DIRECTORY_ENTRY.get(
        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"
    )
    if com_descriptor_index is None:
        com_descriptor_index = 14

    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= com_descriptor_index:
        return False

    clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_descriptor_index]
    return clr_dir.VirtualAddress != 0 and clr_dir.Size != 0


# Section characteristic flags (winnt.h)
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ    = 0x40000000
_SCN_MEM_WRITE   = 0x80000000


def _find_rwx_sections(pe: "pefile.PE") -> list[str]:
    """Return the names of any sections marked Read + Write + Execute.

    RWX sections are extremely rare in legitimate binaries — almost
    every modern compiler emits .text as RX and .data as RW. RWX
    typically indicates a self-modifying unpacker stub or hand-crafted
    shellcode loader.
    """
    rwx: list[str] = []
    for section in pe.sections:
        c = section.Characteristics
        if (c & _SCN_MEM_EXECUTE) and (c & _SCN_MEM_WRITE) and (c & _SCN_MEM_READ):
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            rwx.append(name)
    return rwx


def _has_tls_callbacks(pe: "pefile.PE") -> bool:
    """Detect whether the PE registers TLS callbacks.

    TLS callbacks run before the entry point and are commonly used
    by malware for anti-debugging (the debugger may not have control
    yet) and to defeat naive analysis tools that only look at the EP.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return False
    try:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        if not getattr(tls, "AddressOfCallBacks", 0):
            return False
        # Walk the callback array to confirm at least one entry.
        callback_rva = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        try:
            data = pe.get_data(callback_rva, 8)
            return any(b != 0 for b in data)
        except Exception:  # noqa: BLE001
            # We saw a callback table pointer — that alone is enough.
            return True
    except Exception:  # noqa: BLE001
        return False


def _analyse_overlay(pe: "pefile.PE") -> dict:
    """Inspect any overlay (data appended after the last PE section).

    Overlay data is commonly used to smuggle encrypted payloads,
    second-stage DLLs, or installer archives. We compute the size and
    Shannon entropy of the overlay.
    """
    info = {"size": 0, "entropy": 0.0}
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
    except Exception:  # noqa: BLE001
        return info
    if overlay_offset is None:
        return info
    raw = pe.__data__
    overlay = raw[overlay_offset:]
    if not overlay:
        return info
    info["size"] = len(overlay)
    # Sample at most 1 MiB for entropy to keep the cost bounded.
    sample = overlay[:1024 * 1024]
    info["entropy"] = round(_shannon_entropy(sample), 4)
    return info


def _analyse_resources(pe: "pefile.PE", sections: list[dict]) -> dict:
    """Compute size + entropy of the .rsrc section if present.

    Large, high-entropy .rsrc sections frequently hide embedded
    payloads — AutoIt scripts, second-stage executables, encrypted
    blobs. We flag entropy >= 7.0 with a non-trivial size.
    """
    info = {
        "present": False,
        "size": 0,
        "entropy": 0.0,
        "high_entropy": False,
    }
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        if name.lower() != ".rsrc":
            continue
        info["present"] = True
        info["size"] = section.SizeOfRawData
        try:
            entropy = section.get_entropy()
            info["entropy"] = round(entropy, 4)
            # Only flag entropy spikes on resource sections that are big
            # enough to plausibly hide a payload (>= 4 KiB).
            if entropy >= 7.0 and info["size"] >= 4096:
                info["high_entropy"] = True
        except Exception:  # noqa: BLE001
            pass
        break
    return info


def _detect_compiled_language(pe: "pefile.PE", sections: list[dict]) -> str:
    """Detect Go / Rust / Nim binaries via section names + magic strings.

    Returns one of: "go", "rust", "nim", or "" (unknown / standard).

    We sample only the first 4 MiB of the binary for marker bytes to
    keep the cost bounded on large samples.
    """
    section_names = {s.get("name", "").lower() for s in sections}

    # .symtab is the strongest single Go indicator on Windows.
    if ".symtab" in section_names:
        return "go"

    try:
        sample = pe.__data__[: 4 * 1024 * 1024]
    except Exception:  # noqa: BLE001
        return ""

    # Go binaries embed an unmistakable build-id banner.
    if b"Go build ID:" in sample or b"go.buildinfo" in sample:
        return "go"

    # Rust binaries embed compiler/std markers.
    if (b"rust_panic" in sample
            or b"RUST_BACKTRACE" in sample
            or b"/rustc/" in sample):
        return "rust"

    # Nim binaries embed nimrtl / system.nim references.
    if (b"nimrtl" in sample
            or b"system.nim" in sample
            or b"NimMain" in sample):
        return "nim"

    return ""


# DLL characteristics bit flags (winnt.h IMAGE_DLLCHARACTERISTICS_*).
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE     = 0x0040  # ASLR
_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY  = 0x0080
_IMAGE_DLLCHARACTERISTICS_NX_COMPAT        = 0x0100  # DEP
_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION     = 0x0200
_IMAGE_DLLCHARACTERISTICS_NO_SEH           = 0x0400
_IMAGE_DLLCHARACTERISTICS_NO_BIND          = 0x0800
_IMAGE_DLLCHARACTERISTICS_GUARD_CF         = 0x4000  # CFG
_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
_IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA  = 0x0020  # 64-bit ASLR


def _analyse_dll_characteristics(pe: "pefile.PE") -> dict:
    """Inspect the DllCharacteristics flags for missing modern mitigations.

    Modern compilers enable ASLR (DYNAMIC_BASE), DEP (NX_COMPAT) and CFG
    (GUARD_CF) by default. Their absence is a soft signal that the
    binary was hand-built, packed by a custom packer, or compiled by a
    non-mainstream toolchain (often the case for malware).
    """
    try:
        c = pe.OPTIONAL_HEADER.DllCharacteristics
    except AttributeError:
        return {"aslr": False, "dep": False, "cfg": False, "seh": False,
                "high_entropy_va": False, "force_integrity": False}
    return {
        "aslr": bool(c & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        "dep": bool(c & _IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        "cfg": bool(c & _IMAGE_DLLCHARACTERISTICS_GUARD_CF),
        # SEH = NO_SEH bit *unset* means SEH is allowed (= "has SEH"),
        # which is the safe default. We invert so the dict is uniform:
        # True everywhere means "mitigation enabled".
        "seh": not bool(c & _IMAGE_DLLCHARACTERISTICS_NO_SEH),
        "high_entropy_va": bool(c & _IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
        "force_integrity": bool(c & _IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY),
    }


def _check_entry_point(pe: "pefile.PE", sections: list[dict]) -> dict:
    """Validate that the entry point lies inside a normal code section.

    Returns:
        {
          "section": "<section name containing the EP>",
          "anomaly": True if EP is in a non-code section,
        }

    Most legitimate compilers place the EP inside .text. Packers and
    shellcode loaders frequently move it to .data, .rsrc, or a
    randomly-named section.
    """
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    except AttributeError:
        return {"section": None, "anomaly": False}
    ep_section = None
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= ep < end:
            ep_section = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            break
    if ep_section is None:
        return {"section": None, "anomaly": True}
    # Standard code-section names that we treat as benign.
    benign = {".text", "code", ".code", "text", "CODE", "INIT"}
    anomaly = ep_section.strip().lower() not in {b.lower() for b in benign}
    return {"section": ep_section, "anomaly": anomaly}


def _analyse_rich_header(pe: "pefile.PE") -> dict:
    """Extract the Microsoft Rich header (compiler/linker fingerprint).

    The Rich header is an undocumented Microsoft-toolchain footprint
    inserted between the DOS stub and the PE header. It contains
    Comp.ID + counts for every Microsoft toolchain component used to
    build the binary. We capture presence and verify the linker XOR
    checksum against a recomputed value — a mismatch is a strong
    tampering signal (some crypters strip or rebuild the header
    incorrectly).
    """
    info = {
        "present": False,
        "n_entries": 0,
        "corrupted": False,
        "checksum": None,
        "tools": [],
    }
    try:
        rh = pe.parse_rich_header()
    except Exception:  # noqa: BLE001
        return info
    if not rh or not isinstance(rh, dict):
        return info
    info["present"] = True

    values = rh.get("values", []) or []
    # values is a flat list [comp_id_0, count_0, comp_id_1, count_1, …]
    info["n_entries"] = len(values) // 2 if values else 0

    stored_checksum = rh.get("checksum")
    if stored_checksum is not None:
        info["checksum"] = stored_checksum

    # Verify the Rich header checksum. The linker computes:
    #   csum = e_lfanew
    #   for each byte b in dos_header_and_stub (excluding e_lfanew bytes):
    #       csum += rol32(b, i)
    #   for each (comp_id, count) pair:
    #       csum += rol32(comp_id, count & 0x1f)
    # pefile exposes ``clear_data`` which is the dos header+stub region
    # with the Rich header itself zeroed out, ready for the rolling sum.
    clear_data = rh.get("clear_data")
    if clear_data and stored_checksum is not None and values:
        try:
            # Force a writable copy and zero out the e_lfanew field
            # (offsets 0x3C..0x3F) — the standard checksum skips them.
            buf = bytearray(clear_data)
            for k in range(0x3C, 0x40):
                if k < len(buf):
                    buf[k] = 0
            csum = pe.DOS_HEADER.e_lfanew & 0xFFFFFFFF
            for i, b in enumerate(buf):
                csum = (csum + _rol32(b, i & 0x1F)) & 0xFFFFFFFF
            # Pairs of (comp_id, count).
            for j in range(0, len(values) - 1, 2):
                comp_id = values[j] & 0xFFFFFFFF
                count = values[j + 1] & 0xFFFFFFFF
                csum = (csum + _rol32(comp_id, count & 0x1F)) & 0xFFFFFFFF
            info["corrupted"] = (csum != (stored_checksum & 0xFFFFFFFF))
        except Exception:  # noqa: BLE001
            info["corrupted"] = False

    # Best-effort toolchain summary — translate top Comp.IDs to a
    # human-readable list ("MSVC linker x.y", "MASM", …). We do not
    # ship the full Microsoft Comp.ID database; just bucket by the
    # high 16 bits which encode the product family.
    if values:
        families: dict[int, int] = {}
        for j in range(0, len(values) - 1, 2):
            family = (values[j] >> 16) & 0xFFFF
            families[family] = families.get(family, 0) + values[j + 1]
        info["tools"] = sorted(
            ({"family": f"0x{fam:04x}", "objects": cnt}
             for fam, cnt in families.items()),
            key=lambda x: -x["objects"],
        )[:6]
    return info


def _rol32(value: int, bits: int) -> int:
    """32-bit rotate-left helper used by the Rich header checksum."""
    value &= 0xFFFFFFFF
    bits &= 0x1F
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF if bits else value


# Default DOS stub message in MS toolchain output.
_DEFAULT_DOS_STUB = b"This program cannot be run in DOS mode."


def _analyse_dos_stub(pe: "pefile.PE") -> dict:
    """Detect modifications to the standard MS-DOS stub.

    Most legitimate Microsoft toolchain binaries contain the literal
    'This program cannot be run in DOS mode.' inside the DOS stub.
    Packers and crypters frequently overwrite this region.
    """
    info = {"modified": False, "preview": ""}
    try:
        # The PE header starts at e_lfanew. Everything before that
        # (after the DOS header) is the stub.
        e_lfanew = pe.DOS_HEADER.e_lfanew
        stub = pe.__data__[64:e_lfanew]
        if not stub:
            return info
        info["preview"] = stub[:64].decode("ascii", errors="replace").strip()
        if _DEFAULT_DOS_STUB not in stub:
            info["modified"] = True
    except Exception:  # noqa: BLE001
        pass
    return info


# Suspicious tokens that often appear in attacker PDB paths.
_SUSPICIOUS_PDB_TOKENS = re.compile(
    r"\b(?:redline|lumma|vidar|raccoon|stealc|asyncrat|njrat|quasar|"
    r"agenttesla|formbook|remcos|nanocore|cobalt|sliver|havoc|"
    r"meterpreter|stub|loader|injector|crypter|packer|payload|"
    r"shellcode|dropper|backdoor|rat\b|stealer\b|keylogger|miner|"
    r"trojan|malware|exploit|bypass|uac|amsi|defender|killdef)\b",
    re.IGNORECASE,
)


def _extract_debug_info(pe: "pefile.PE") -> dict:
    """Extract the PDB debug path from the IMAGE_DEBUG_DIRECTORY.

    Returns:
        {
          "pdb_path": "<extracted path or empty>",
          "suspicious_pdb": True if path matches malicious tokens,
          "pdb_username": "<extracted Windows username if any>",
        }

    Many attackers ship debug builds with leaked usernames or project
    names ("redline_stub", "loader", their handle/email).
    """
    info = {"pdb_path": "", "suspicious_pdb": False, "pdb_username": ""}
    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return info
    for entry in pe.DIRECTORY_ENTRY_DEBUG:
        try:
            data = entry.entry
        except AttributeError:
            continue
        # CodeView entries (RSDS / NB10) carry the PDB path.
        for attr in ("PdbFileName", "Pdb70FileName", "Pdb20FileName"):
            pdb = getattr(data, attr, None)
            if pdb:
                if isinstance(pdb, bytes):
                    pdb = pdb.rstrip(b"\x00").decode("utf-8", errors="replace")
                info["pdb_path"] = pdb
                if _SUSPICIOUS_PDB_TOKENS.search(pdb):
                    info["suspicious_pdb"] = True
                m = re.search(r"[\\/]Users[\\/]([^\\/]+)", pdb, re.IGNORECASE)
                if m:
                    info["pdb_username"] = m.group(1)
                return info
    return info


def _extract_version_info(pe: "pefile.PE") -> dict:
    """Pull CompanyName / ProductName / FileDescription / etc.

    Goes through the resource VS_VERSIONINFO StringFileInfo block.
    """
    info: dict = {}
    if not hasattr(pe, "FileInfo"):
        return info
    try:
        for fileinfo in pe.FileInfo:
            # pefile gives us a list-of-lists in newer versions.
            if not isinstance(fileinfo, list):
                fileinfo = [fileinfo]
            for fi in fileinfo:
                if not hasattr(fi, "StringTable"):
                    continue
                for st in fi.StringTable:
                    for k, v in st.entries.items():
                        try:
                            key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
                            val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                        except Exception:  # noqa: BLE001
                            continue
                        info[key] = val.strip("\x00").strip()
    except Exception:  # noqa: BLE001
        return info
    return info


def _score_version_info(info: dict) -> tuple[int, str]:
    """Score the version info block.

    Two failure modes:
      • Block missing entirely (score +5, mild — common in Go/Rust too).
      • Block claims a Microsoft / Google / well-known vendor identity
        but the binary is unsigned and small (impersonation +10).
    """
    if not info:
        return 0, ""
    company = (info.get("CompanyName") or "").strip()
    product = (info.get("ProductName") or "").strip()
    description = (info.get("FileDescription") or "").strip()
    # Watch for impersonation of well-known vendors.
    impersonated = {
        "microsoft corporation", "google inc", "google llc",
        "adobe systems incorporated", "adobe inc.",
        "apple inc.", "intel corporation", "nvidia corporation",
        "oracle corporation", "vmware, inc.",
    }
    company_lower = company.lower()
    if company_lower in impersonated:
        # Real impersonation detection requires cert checking too —
        # we surface it as suspicious-only when desc/product also look
        # off (very short or generic).
        if len(description) < 4 or description.lower() in {
                "application", "windows host process", "host process"}:
            return 10, (
                f"Version info impersonates '{company}' but FileDescription "
                f"is generic ('{description}') — likely impersonation"
            )
    return 0, ""


def _detect_section_size_mismatch(
    pe: "pefile.PE", sections: list[dict]
) -> dict:
    """Find sections where VirtualSize is much larger than RawSize.

    A section with little data on disk but a large virtual footprint
    will be filled in at load time — the classic shape of a packed
    section that decompresses itself in memory.
    """
    bad: list[str] = []
    for section in pe.sections:
        raw = section.SizeOfRawData
        virt = section.Misc_VirtualSize
        if raw == 0 and virt > 0x100:
            # Zero raw size + non-trivial virtual size = pure runtime
            # buffer (legitimate for .bss but not for code sections).
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            if name.lower() not in {".bss", ".data", ".tls"}:
                bad.append(name)
            continue
        if raw > 0 and virt > raw * 4 and virt - raw > 0x10000:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            bad.append(name)
    return {"count": len(bad), "names": bad[:5]}


def _find_embedded_pe(pe: "pefile.PE") -> dict | None:
    """Search the resource section and overlay for embedded MZ payloads.

    A second-stage executable embedded inside .rsrc or appended to the
    file as overlay is a defining trait of droppers / installers /
    AutoIt-compiled malware. We look for the MZ + 'This program' DOS
    stub combo at any offset > 1024 (avoid matching the host file's
    own header).
    """
    raw = pe.__data__
    # Search the .rsrc section first.
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        if end <= start or end > len(raw):
            continue
        chunk = raw[start:end]
        idx = 0
        while True:
            i = chunk.find(b"MZ", idx)
            if i < 0 or i > len(chunk) - 0x40:
                break
            # Quick verification: check for the DOS stub message
            # within the next 256 bytes.
            window = chunk[i : i + 256]
            if _DEFAULT_DOS_STUB in window:
                return {
                    "where": f"section:{name}",
                    "offset": start + i,
                }
            idx = i + 2
    # Then the overlay.
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
    except Exception:  # noqa: BLE001
        overlay_offset = None
    if overlay_offset:
        overlay = raw[overlay_offset:overlay_offset + 4 * 1024 * 1024]
        i = overlay.find(b"MZ")
        if i >= 0 and i < len(overlay) - 0x40:
            window = overlay[i : i + 256]
            if _DEFAULT_DOS_STUB in window:
                return {
                    "where": "overlay",
                    "offset": overlay_offset + i,
                }
    return None


# Win32 APIs that, if seen as raw strings inside the file but missing
# from the import table, indicate runtime resolution via GetProcAddress.
# Drawn from the suspicious-imports list intersected with names that
# are realistically resolvable at runtime.
_DYNAMIC_API_CANDIDATES = frozenset({
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx",
    "SetThreadContext", "ResumeThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "CreateProcessA", "CreateProcessW",
    "InternetOpenA", "InternetOpenW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "connect",
    "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueExA", "RegSetValueExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "SetWindowsHookExA", "SetWindowsHookExW",
})


def _detect_dynamic_api_resolution(
    pe: "pefile.PE", suspicious_imports: set[str]
) -> dict:
    """Find suspicious APIs that appear as raw strings but not as imports.

    A binary that contains the *string* "VirtualAllocEx" but does not
    import it is almost certainly resolving the function at runtime via
    GetProcAddress / hash-based resolution — a packer / shellcode
    loader hallmark.
    """
    info = {"count": 0, "apis": []}
    try:
        raw = pe.__data__
    except Exception:  # noqa: BLE001
        return info
    candidates = _DYNAMIC_API_CANDIDATES - suspicious_imports
    found: list[str] = []
    for api in candidates:
        # Use a quick byte search; the API names are ASCII-only.
        if api.encode("ascii") in raw:
            found.append(api)
    info["count"] = len(found)
    info["apis"] = sorted(found)[:10]
    return info


def _extract_certificate_info(pe: "pefile.PE") -> dict:
    """Best-effort extraction of the Authenticode certificate subject.

    We do not validate the signature; we just pull the WIN_CERTIFICATE
    blob and try to extract a printable subject CN. This is enough for
    spotting binaries signed with stolen / abused certificates from
    well-known issuers (Comodo, DigiCert, Sectigo, GlobalSign).
    """
    info: dict = {"present": False}
    try:
        sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]
        if not (sec_dir.VirtualAddress and sec_dir.Size):
            return info
        cert_blob = pe.__data__[
            sec_dir.VirtualAddress : sec_dir.VirtualAddress + sec_dir.Size
        ]
        info["present"] = True
        info["size"] = len(cert_blob)
        # Heuristic CN extraction — find any "CN=" or printable
        # CommonName-style sequences in the blob.
        text = cert_blob.decode("latin-1", errors="replace")
        m = re.search(r"CN\s*=\s*([^,/\x00\r\n]{3,80})", text)
        if m:
            info["common_name"] = m.group(1).strip()
        # Look for issuer-like substrings.
        for issuer in ("Sectigo", "Comodo", "DigiCert", "GlobalSign",
                       "Let's Encrypt", "VeriSign", "GoDaddy",
                       "Certum", "SSL.com", "Entrust"):
            if issuer in text:
                info["issuer_hint"] = issuer
                break
    except Exception:  # noqa: BLE001
        return info
    return info


def _check_timestamp(headers: dict) -> tuple[int, str]:
    """Check for anomalous compile timestamps.

    Returns:
        (score_delta, reason_string) — (0, "") if timestamp looks normal.
    """
    raw_ts = headers.get("compile_timestamp_raw", 0)
    if raw_ts == 0:
        return 0, ""

    try:
        compile_dt = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return 5, f"Invalid compile timestamp ({raw_ts}) — likely forged"

    now = datetime.now(tz=timezone.utc)

    # Future timestamp = definitely forged.
    if compile_dt > now:
        return 5, (
            f"Compile timestamp is in the future ({compile_dt.strftime('%Y-%m-%d')}) "
            f"— likely forged"
        )

    # Before 1990 = suspicious (Windows PE format didn't exist).
    if compile_dt.year < 1990:
        return 5, (
            f"Compile timestamp is implausibly old ({compile_dt.strftime('%Y-%m-%d')}) "
            f"— likely forged"
        )

    return 0, ""


def _detect_section_permission_anomalies(pe: "pefile.PE") -> list[str]:
    """Catch sections whose permissions don't match their conventional role.

    Examples:
      • A writable .text — code section that is also writable, used by
        self-modifying code / unpackers (already partially handled by
        the RWX check; this catches the W-without-X case too).
      • An executable .data / .rdata — code hidden in a data section,
        common when packers decompress into the data segment.
      • A writable .rdata — read-only data section that is writable,
        commonly seen with hand-modified PEs.

    Returns a list of human-readable anomaly strings.
    """
    out: list[str] = []
    for section in pe.sections:
        try:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace").lower()
        except Exception:  # noqa: BLE001
            continue
        c = section.Characteristics
        is_x = bool(c & _SCN_MEM_EXECUTE)
        is_w = bool(c & _SCN_MEM_WRITE)
        if name in (".text", "code", ".code") and is_w and not (is_x and is_w):
            out.append(f"writable {name}")
        if name in (".data", ".rdata", ".bss") and is_x:
            out.append(f"executable {name}")
        if name == ".rdata" and is_w:
            out.append("writable .rdata")
    # de-dup while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _check_pe_checksum(pe: "pefile.PE", has_signature: bool) -> dict:
    """Compare the OptionalHeader.CheckSum against a recomputed value.

    A mismatch is only meaningful for signed binaries — Microsoft signs
    with a valid checksum, so a mismatch indicates the binary was
    altered after signing. For unsigned binaries it's noise (most
    compilers leave the field zero).
    """
    info: dict = {
        "stored": 0,
        "computed": 0,
        "mismatch_signed": False,
    }
    try:
        stored = pe.OPTIONAL_HEADER.CheckSum
    except AttributeError:
        return info
    info["stored"] = stored
    try:
        computed = pe.generate_checksum()
    except Exception:  # noqa: BLE001
        return info
    info["computed"] = computed
    if has_signature and stored != 0 and computed != 0 and stored != computed:
        info["mismatch_signed"] = True
    return info


def _classify_import_footprint(imports: dict, is_dotnet: bool) -> dict:
    """Classify the import-table footprint at a high level.

    The defining mark of a packed/shellcode-loader binary is a tiny
    import table — usually a single DLL (kernel32) with just a handful
    of functions (LoadLibrary, GetProcAddress, VirtualAlloc, …) so the
    real imports can be resolved at runtime.
    """
    info = {
        "dll_count": len(imports),
        "is_kernel32_only": False,
        "loader_only": False,
    }
    if is_dotnet:
        return info
    dll_names = {dll.lower() for dll in imports.keys()}
    if dll_names == {"kernel32.dll"}:
        info["is_kernel32_only"] = True
        funcs = {f.lower() for f in imports.get("kernel32.dll", [])
                 if isinstance(f, str)}
        loader_set = {"loadlibrarya", "loadlibraryw", "getprocaddress",
                      "virtualalloc", "virtualprotect", "exitprocess"}
        if funcs and funcs.issubset(loader_set | {"getmodulehandlea",
                                                  "getmodulehandlew"}):
            info["loader_only"] = True
    return info


def _analyse_resource_types(pe: "pefile.PE") -> dict:
    """Walk the resource directory and tally per-type sizes.

    Returns:
        {
          "types": {"RT_ICON": 1234, "RT_RCDATA": 56789, ...},
          "largest_rcdata": <bytes>,
          "large_rcdata": <bytes>,    # alias for the largest blob
          "autoit": True/False,
        }
    """
    info: dict = {
        "types": {},
        "largest_rcdata": 0,
        "large_rcdata": 0,
        "autoit": False,
    }
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return info
    rt_names = {
        1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
        5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
        9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE",
        12: "RT_GROUP_CURSOR", 14: "RT_GROUP_ICON", 16: "RT_VERSION",
        17: "RT_DLGINCLUDE", 19: "RT_PLUGPLAY", 20: "RT_VXD",
        21: "RT_ANICURSOR", 22: "RT_ANIICON", 23: "RT_HTML",
        24: "RT_MANIFEST",
    }
    rcdata_blobs: list[tuple[int, bytes]] = []  # (size, sample)
    try:
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            try:
                type_id = entry.id if entry.id is not None else 0
            except AttributeError:
                continue
            type_name = rt_names.get(type_id, f"TYPE_{type_id}")
            total = 0
            if not hasattr(entry, "directory"):
                continue
            for sub in entry.directory.entries:
                if not hasattr(sub, "directory"):
                    continue
                for leaf in sub.directory.entries:
                    data_entry = getattr(leaf, "data", None)
                    if not data_entry or not hasattr(data_entry, "struct"):
                        continue
                    size = data_entry.struct.Size
                    total += size
                    if type_name == "RT_RCDATA" and size > 1024:
                        try:
                            rva = data_entry.struct.OffsetToData
                            sample = pe.get_data(rva, min(size, 256))
                        except Exception:  # noqa: BLE001
                            sample = b""
                        rcdata_blobs.append((size, sample))
            if total:
                info["types"][type_name] = info["types"].get(type_name, 0) + total
    except Exception:  # noqa: BLE001
        return info

    if rcdata_blobs:
        rcdata_blobs.sort(key=lambda x: -x[0])
        info["largest_rcdata"] = rcdata_blobs[0][0]
        info["large_rcdata"] = rcdata_blobs[0][0]
        # AutoIt scripts compiled with Aut2Exe carry the "AU3!" marker.
        for _size, sample in rcdata_blobs[:5]:
            if b"AU3!" in sample or b"AutoIt v3" in sample:
                info["autoit"] = True
                break

    return info


def _detect_installer(pe: "pefile.PE", sections: list[dict]) -> str | None:
    """Detect common Windows installer wrappers (NSIS, InnoSetup, …).

    Many commodity droppers ship as off-the-shelf installers because
    they need to extract a payload + a config + an autorun shim. We
    scan a bounded prefix of the binary for vendor strings and
    section-name signatures.
    """
    # Section-name signatures first (cheapest).
    section_names = {s.get("name", "").lower() for s in sections}
    if ".ndata" in section_names:  # NSIS uses .ndata
        return "NSIS"

    try:
        sample = pe.__data__[: 2 * 1024 * 1024]
    except Exception:  # noqa: BLE001
        return None

    if b"Nullsoft.NSIS" in sample or b"NullsoftInst" in sample:
        return "NSIS"
    if b"Inno Setup Setup Data" in sample or b"InnoSetupLdr" in sample:
        return "InnoSetup"
    if b"WiseInstallation" in sample or b"WiseMain" in sample:
        return "Wise"
    if b"InstallShield" in sample:
        return "InstallShield"
    if b"7z\xbc\xaf\x27\x1c" in sample[256 * 1024:]:
        # 7z magic in the overlay region — common SFX dropper shape.
        return "7-Zip SFX"
    return None


def _count_forwarded_exports(pe: "pefile.PE") -> int:
    """Count export entries that forward to another DLL.

    Forwarded exports are how Windows API set DLLs (api-ms-win-*)
    redirect calls to their real implementation. On a normal EXE
    they're suspicious because they suggest a proxy / hijack DLL.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return 0
    count = 0
    try:
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if getattr(sym, "forwarder", None):
                count += 1
    except Exception:  # noqa: BLE001
        return 0
    return count
