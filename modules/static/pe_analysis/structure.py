"""TLS callbacks, overlay, entry point, embedded MZ payload search."""

from .metadata import _DEFAULT_DOS_STUB
from .sections import _shannon_entropy


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
