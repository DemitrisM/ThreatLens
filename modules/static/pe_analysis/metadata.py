"""Rich header, DOS stub, debug PDB info, version info — PE metadata.

Design notes
------------
Metadata is what a binary says about itself, so all four checks here look for
the same thing: a claim that does not hold up. The Rich header and DOS stub
are written by the Microsoft toolchain and are hard to reproduce correctly by
hand, which makes a *corrupted* one more telling than a missing one. The PDB
path and version block are free text, which makes them a source of attacker
mistakes — a leaked username, a project name like "stub" or "crypter", a
stolen CompanyName over a generic FileDescription.

None of these is conclusive alone. Go and Rust binaries have no Rich header,
plenty of legitimate software ships no version block, and packers strip all of
it. They earn their weight in combination with the structural indicators.
"""

import re

# Default DOS stub message in MS toolchain output.
_DEFAULT_DOS_STUB = b"This program cannot be run in DOS mode."

# Tokens seen in real attacker PDB paths: stealer/RAT family names, C2
# frameworks, and generic build-role words. Matched case-insensitively on
# word boundaries so "loader" does not fire inside "downloader_test".
# Suspicious tokens that often appear in attacker PDB paths.
_SUSPICIOUS_PDB_TOKENS = re.compile(
    r"\b(?:redline|lumma|vidar|raccoon|stealc|asyncrat|njrat|quasar|"
    r"agenttesla|formbook|remcos|nanocore|cobalt|sliver|havoc|"
    r"meterpreter|stub|loader|injector|crypter|packer|payload|"
    r"shellcode|dropper|backdoor|rat\b|stealer\b|keylogger|miner|"
    r"trojan|malware|exploit|bypass|uac|amsi|defender|killdef)\b",
    re.IGNORECASE,
)


def _rol32(value: int, bits: int) -> int:
    """32-bit rotate-left helper used by the Rich header checksum.

    Args:
        value: The value to rotate; masked to 32 bits first.
        bits:  Rotation amount, masked to 0-31.

    Returns:
        The rotated 32-bit value. Python integers are unbounded, so both
        the input and the result must be masked explicitly to emulate
        the 32-bit arithmetic the linker performs.
    """
    value &= 0xFFFFFFFF
    bits &= 0x1F
    # A rotate by zero is returned unchanged: `value >> 32` would shift
    # the whole value out rather than being a no-op.
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF if bits else value


def _analyse_rich_header(pe: "pefile.PE") -> dict:
    """Extract the Microsoft Rich header (compiler/linker fingerprint).

    The Rich header is an undocumented Microsoft-toolchain footprint
    inserted between the DOS stub and the PE header. It contains
    Comp.ID + counts for every Microsoft toolchain component used to
    build the binary. We capture presence and verify the linker XOR
    checksum against a recomputed value — a mismatch is a strong
    tampering signal (some crypters strip or rebuild the header
    incorrectly).

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        ``{"present", "n_entries", "corrupted", "checksum", "tools"}``.
        Absence is NOT reported as corruption: Go, Rust, MinGW and every
        non-Microsoft toolchain legitimately emit no Rich header.
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

    # ------------------------------------------------------------------
    # Recompute the checksum and compare.
    #
    # This is the whole point of the function. The checksum doubles as
    # the XOR key for the header, so a crypter that rewrites the region
    # without recomputing it leaves a mismatch behind — evidence the
    # binary was modified after the linker finished with it.
    # ------------------------------------------------------------------
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
            # Each byte is rotated by its own offset, so the sum depends
            # on position as well as content.
            for i, b in enumerate(buf):
                csum = (csum + _rol32(b, i & 0x1F)) & 0xFFFFFFFF
            # Pairs of (comp_id, count).
            for j in range(0, len(values) - 1, 2):
                comp_id = values[j] & 0xFFFFFFFF
                count = values[j + 1] & 0xFFFFFFFF
                csum = (csum + _rol32(comp_id, count & 0x1F)) & 0xFFFFFFFF
            info["corrupted"] = (csum != (stored_checksum & 0xFFFFFFFF))
        except Exception:  # noqa: BLE001
            # A failed computation is not evidence of tampering, so this
            # resets the flag rather than leaving it ambiguous.
            info["corrupted"] = False

    # ------------------------------------------------------------------
    # Summarise the toolchain.
    #
    # Bucketing by the high 16 bits (the product family) avoids shipping
    # Microsoft's full Comp.ID table for what is a display-only field.
    # Top six by object count keeps the report readable.
    # ------------------------------------------------------------------
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


def _analyse_dos_stub(pe: "pefile.PE") -> dict:
    """Detect modifications to the standard MS-DOS stub.

    Most legitimate Microsoft toolchain binaries contain the literal
    'This program cannot be run in DOS mode.' inside the DOS stub.
    Packers and crypters frequently overwrite this region.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        ``{"modified": bool, "preview": str}``. The preview is included
        so a reader can see what replaced the stub rather than only
        being told that something did.
    """
    info = {"modified": False, "preview": ""}
    try:
        # The DOS header is a fixed 64 bytes, and e_lfanew (its last
        # field) points at the PE header — so the stub is everything
        # between them.
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


def _extract_debug_info(pe: "pefile.PE") -> dict:
    """Extract the PDB debug path from the IMAGE_DEBUG_DIRECTORY.

    Args:
        pe: A parsed ``pefile.PE`` object.

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
        # Three attribute spellings cover the CodeView formats across
        # pefile versions: RSDS (PDB 7.0) and the older NB10 (PDB 2.0).
        # CodeView entries (RSDS / NB10) carry the PDB path.
        for attr in ("PdbFileName", "Pdb70FileName", "Pdb20FileName"):
            pdb = getattr(data, attr, None)
            if pdb:
                if isinstance(pdb, bytes):
                    pdb = pdb.rstrip(b"\x00").decode("utf-8", errors="replace")
                info["pdb_path"] = pdb
                if _SUSPICIOUS_PDB_TOKENS.search(pdb):
                    info["suspicious_pdb"] = True
                # A build path under C:\Users\<name>\ leaks the account
                # the binary was compiled on — frequently the operator's
                # own handle, and directly useful for attribution.
                m = re.search(r"[\\/]Users[\\/]([^\\/]+)", pdb, re.IGNORECASE)
                if m:
                    info["pdb_username"] = m.group(1)
                # First CodeView entry wins; a PE carries only one real
                # PDB reference and later entries are other debug types.
                return info
    return info


def _extract_version_info(pe: "pefile.PE") -> dict:
    """Pull CompanyName / ProductName / FileDescription / etc.

    Goes through the resource VS_VERSIONINFO StringFileInfo block.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        A flat dict of whatever string keys the block declared, or ``{}``
        when there is no version resource. Keys are not normalised —
        they are whatever the binary named them, which is itself
        informative.
    """
    info: dict = {}
    if not hasattr(pe, "FileInfo"):
        return info
    try:
        # ------------------------------------------------------------------
        # Walk VS_VERSIONINFO -> StringFileInfo -> StringTable -> entries.
        #
        # The isinstance check normalises a pefile API change: newer
        # versions return a list of lists here, older ones a flat list.
        # ------------------------------------------------------------------
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
                            # Skip the unreadable pair, keep the rest.
                            continue
                        info[key] = val.strip("\x00").strip()
    except Exception:  # noqa: BLE001
        return info
    return info


def _score_version_info(info: dict) -> tuple[int, str]:
    """Score the version info block.

    One failure mode is scored: the block claims a Microsoft / Google /
    well-known vendor identity while the FileDescription is missing or
    boilerplate (impersonation, +10).

    A *missing* block is deliberately not scored. Go, Rust and MinGW
    binaries routinely ship without one, so penalising its absence would
    fire across a large benign population for no discriminating power.
    An earlier version of this docstring promised +5 for that case; the
    code never implemented it, and the intended behaviour is the code's,
    not the docstring's.

    Args:
        info: The dict from ``_extract_version_info``. Empty when the
              binary carries no VS_VERSIONINFO resource.

    Returns:
        ``(score_delta, reason)`` — ``(0, "")`` when nothing fires,
        including for a missing block.
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
        # The vendor name alone is not enough — legitimate Microsoft
        # binaries obviously carry it. The pairing with a missing or
        # boilerplate FileDescription is the actual tell, because a real
        # vendor build always fills that field with something specific.
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
