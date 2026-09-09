"""TLS callbacks, overlay, entry point, embedded MZ payload search.

Design notes
------------
These four checks share a theme: they look at where code and data actually
live, rather than at what the file claims about itself. A packer can rename
sections and forge a timestamp cheaply, but it cannot avoid *putting the
payload somewhere* — appended as overlay, buried in .rsrc, or reached through
an execution path that starts before the entry point.

Every scan here is bounded. These functions run against attacker-controlled
files of arbitrary size, so each one caps how much it reads rather than
trusting a length field in the file.
"""

from .metadata import _DEFAULT_DOS_STUB
from .sections import _shannon_entropy


def _has_tls_callbacks(pe: "pefile.PE") -> bool:
    """Detect whether the PE registers TLS callbacks.

    TLS callbacks run before the entry point and are commonly used
    by malware for anti-debugging (the debugger may not have control
    yet) and to defeat naive analysis tools that only look at the EP.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        True when a non-empty callback table is registered.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return False
    try:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        # A TLS directory can exist purely for thread-local storage, with
        # no callbacks at all — that is ordinary and not worth reporting.
        if not getattr(tls, "AddressOfCallBacks", 0):
            return False
        # AddressOfCallBacks is a virtual address, not an RVA, so
        # ImageBase has to come off before pefile can resolve it.
        # Walk the callback array to confirm at least one entry.
        callback_rva = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        try:
            # The array is NULL-terminated by a single pointer, so the
            # read must be exactly one pointer wide. Reading a fixed 8
            # bytes on a 32-bit image would consume the 4-byte
            # terminator PLUS 4 bytes of whatever follows, and report a
            # callback whenever that trailing data happened to be
            # non-zero. Magic 0x20B is PE32+ (64-bit); anything else,
            # including a missing field, is treated as 32-bit.
            is_64bit = getattr(pe.OPTIONAL_HEADER, "Magic", 0x10B) == 0x20B
            pointer_size = 8 if is_64bit else 4
            data = pe.get_data(callback_rva, pointer_size)
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

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        ``{"size", "entropy"}``, both zero when there is no overlay.
        Note that an overlay is not inherently suspicious — signed
        binaries carry their certificate there, and every self-extracting
        installer appends its archive. Size and entropy together are what
        make it interesting.
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
    # Size is the true total; entropy is measured on a prefix. A 1 MiB
    # sample is far more than enough to characterise the distribution,
    # and bounds the cost on a 500 MB installer.
    info["size"] = len(overlay)
    # Sample at most 1 MiB for entropy to keep the cost bounded.
    sample = overlay[:1024 * 1024]
    info["entropy"] = round(_shannon_entropy(sample), 4)
    return info


def _check_entry_point(pe: "pefile.PE", sections: list[dict]) -> dict:
    """Validate that the entry point lies inside a normal code section.

    Args:
        pe:       A parsed ``pefile.PE`` object.
        sections: Section dicts (unused; uniform submodule signature).

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

    # ------------------------------------------------------------------
    # Step 1: Find which section contains the entry point RVA.
    #
    # The larger of virtual and raw size is used as the extent because a
    # packed section's real in-memory footprint is the virtual one, and
    # an EP past the raw bytes is exactly the case worth catching.
    # ------------------------------------------------------------------
    ep_section = None
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= ep < end:
            ep_section = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            break

    # ------------------------------------------------------------------
    # Step 2: Judge it. An EP outside every section is the strongest form
    # of this anomaly — the file declares an entry point that does not
    # map to any of its own content.
    # ------------------------------------------------------------------
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

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        ``{"where", "offset"}`` for the first payload found, or None.
        "MZ" alone is only two bytes and occurs constantly in compressed
        data, so a match is confirmed by requiring the DOS stub string
        within the following 256 bytes — that pairing is what makes this
        specific rather than noisy.
    """
    raw = pe.__data__

    # ------------------------------------------------------------------
    # Step 1: Sweep each section's raw bytes.
    #
    # Offsets are validated against the real file length first: the
    # section table is attacker-controlled and can point past the end.
    # ------------------------------------------------------------------
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
            # Stop when there is not enough room left for a DOS header —
            # a match in the last 64 bytes cannot be a real executable.
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

    # ------------------------------------------------------------------
    # Step 2: Then the overlay, capped at 4 MiB.
    #
    # Only the first MZ is checked here rather than every occurrence:
    # a dropper puts its payload at the start of the appended data, and
    # scanning an entire multi-gigabyte installer archive for a two-byte
    # sequence would cost far more than the extra coverage is worth.
    # ------------------------------------------------------------------
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
