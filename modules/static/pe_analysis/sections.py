"""PE section analysis — entropy, RWX, size mismatch, permission anomalies.

Design notes
------------
Every check here asks the same underlying question: does this section's
*shape* match the role its name claims? Compilers are extremely consistent —
.text is read+execute, .data is read+write, raw and virtual sizes track each
other — so deviations are cheap, high-signal indicators that do not depend on
recognising any particular malware family.

Entropy is the headline metric and the most abused one. Above ~7.0 a byte
stream is indistinguishable from random, which means compressed, encrypted or
packed. It is not evidence of malice on its own: installers, embedded media
and any packed commercial binary reach it legitimately. That is why .rsrc is
excluded here and handled separately, and why the weights are moderate.
"""

import math

# Section characteristic flags (winnt.h)
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ    = 0x40000000
_SCN_MEM_WRITE   = 0x80000000


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence.

    Args:
        data: Raw bytes to measure.

    Returns:
        Entropy in bits per byte, 0.0 to 8.0. 0.0 means every byte is
        identical; 8.0 means a perfectly uniform distribution. Above
        ~7.0 in practice means compressed or encrypted.
    """
    if not data:
        return 0.0
    # A fixed 256-entry list rather than a dict or Counter: this runs over
    # multi-megabyte sections, and direct indexing avoids the hashing.
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in frequency:
        # Skip absent byte values — log2(0) is undefined, and their
        # contribution to the sum is zero anyway.
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _analyse_sections(pe: "pefile.PE") -> tuple[list[dict], int, list[str]]:
    """Analyse PE sections and compute per-section Shannon entropy.

    Args:
        pe: A parsed ``pefile.PE`` object.

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

    # ------------------------------------------------------------------
    # Step 1: Describe every section, and collect the high-entropy ones.
    #
    # The descriptive list is built for ALL sections including .rsrc —
    # the exclusion below is only from scoring, never from the report.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 2: Score once for the whole file, on the worst section.
    #
    # Scoring per section would let a packer with six compressed sections
    # outweigh every other indicator in the report; the finding is "this
    # binary is packed", which is true once regardless of section count.
    # ------------------------------------------------------------------
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

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        Names of RWX sections, empty when none. Writable-and-executable
        together is what matters: it lets code rewrite itself at
        runtime, which is precisely what an unpacker stub must do.
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

    Args:
        pe:       A parsed ``pefile.PE`` object.
        sections: Section dicts (unused; uniform submodule signature).

    Returns:
        ``{"count": int, "names": [...]}`` with names capped at five to
        keep the report readable; the count is the true total.
    """
    bad: list[str] = []
    for section in pe.sections:
        raw = section.SizeOfRawData
        virt = section.Misc_VirtualSize

        # --------------------------------------------------------------
        # Case 1: no bytes on disk at all.
        #
        # Legitimate for uninitialised data (.bss, .data, .tls), which is
        # why those three names are excused. Anywhere else it means the
        # section's contents arrive only at runtime.
        # --------------------------------------------------------------
        if raw == 0 and virt > 0x100:
            # Zero raw size + non-trivial virtual size = pure runtime
            # buffer (legitimate for .bss but not for code sections).
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            if name.lower() not in {".bss", ".data", ".tls"}:
                bad.append(name)
            continue

        # --------------------------------------------------------------
        # Case 2: disproportionate expansion.
        #
        # Both conditions are needed. The 4x ratio alone fires on small
        # sections where alignment padding dominates; the 64 KiB absolute
        # floor requires the gap to be big enough to hold a real payload.
        # --------------------------------------------------------------
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

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        A list of human-readable anomaly strings, deduplicated in
        first-seen order.
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
        # `is_w and not (is_x and is_w)` reduces to "writable but NOT
        # executable", so a writable+executable .text is left to
        # _find_rwx_sections instead of being reported twice.
        #
        # NOTE: that exclusion is applied ONLY here. The two data-section
        # checks below do not test for it, so an RWX .rdata currently
        # raises "executable .rdata", "writable .rdata" AND the separate
        # RWX finding. Flagged rather than changed: suppressing findings
        # alters scoring, which does not belong in a comment pass.
        if name in (".text", "code", ".code") and is_w and not (is_x and is_w):
            out.append(f"writable {name}")
        if name in (".data", ".rdata", ".bss") and is_x:
            out.append(f"executable {name}")
        if name == ".rdata" and is_w:
            out.append("writable .rdata")
    # Order-preserving dedup: a binary with several executable data
    # sections should report the anomaly once, but the first one seen
    # stays first in the report.
    # de-dup while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
