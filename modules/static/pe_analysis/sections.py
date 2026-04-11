"""PE section analysis — entropy, RWX, size mismatch, permission anomalies."""

import math

# Section characteristic flags (winnt.h)
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ    = 0x40000000
_SCN_MEM_WRITE   = 0x80000000


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
