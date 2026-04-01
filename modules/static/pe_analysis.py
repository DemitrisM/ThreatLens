"""PE file analysis module.

Uses pefile to extract headers, sections with per-section Shannon entropy,
imports/exports, digital signature status, and packer detection.
Returns a standard module result dict with score_delta and reason.
"""

import logging
import math
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
    # Process injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtWriteVirtualMemory", "NtCreateThreadEx",
    "QueueUserAPC", "NtQueueApcThread",
    "RtlCreateUserThread",
    # Code execution
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW",
    "CreateProcessInternalA", "CreateProcessInternalW",
    # DLL injection / loading
    "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll",
    # Privilege / token
    "OpenProcessToken", "AdjustTokenPrivileges",
    "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    # Anti-debug / anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA",
    # Crypto
    "CryptEncrypt", "CryptDecrypt",
    "CryptAcquireContextA", "CryptAcquireContextW",
    # Networking
    "InternetOpenA", "InternetOpenW",
    "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpOpenRequestA", "HttpOpenRequestW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "connect", "send", "recv",
    # Registry
    "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    # Keylogging / hooking
    "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "GetKeyState",
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

    # --- Imports ---
    imports, suspicious_imports = _extract_imports(pe)
    if suspicious_imports:
        score_delta += 10
        top_five = sorted(suspicious_imports)[:5]
        suffix = f" (+{len(suspicious_imports) - 5} more)" if len(suspicious_imports) > 5 else ""
        reasons.append(
            f"Suspicious imports detected: {', '.join(top_five)}{suffix}"
        )

    # --- Exports ---
    exports = _extract_exports(pe)

    # --- Digital signature ---
    has_signature = _check_signature(pe)
    if has_signature:
        score_delta -= 10
        reasons.append("PE has a digital signature (presence only — validity not verified)")
    else:
        score_delta += 15
        reasons.append("No digital signature found")

    # --- Packer detection ---
    packers_found = _detect_packers(pe, sections)
    if packers_found:
        score_delta += 15
        reasons.append(f"Packer detected: {', '.join(packers_found)}")

    # --- .NET detection ---
    is_dotnet = _is_dotnet(pe)

    # --- Anomalous compile timestamp ---
    ts_delta, ts_reason = _check_timestamp(headers)
    if ts_delta:
        score_delta += ts_delta
        reasons.append(ts_reason)

    data = {
        "headers": headers,
        "sections": sections,
        "imports": imports,
        "suspicious_imports": sorted(suspicious_imports) if suspicious_imports else [],
        "exports": exports,
        "has_signature": has_signature,
        "packers_detected": packers_found,
        "is_dotnet": is_dotnet,
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
