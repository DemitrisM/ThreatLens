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
import struct

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


#: The Rich header's "DanS" marker, and where pefile insists it lives.
#: parse_rich_header slices its record data from a hardcoded 0x80, so
#: the checksum has to be computed against that same offset or it is
#: measuring one region and comparing it against another.
_RICH_DANS = 0x536E6144
_RICH_MARKER_OFFSET = 0x80
#: DanS plus the three repeated key dwords that confirm the key.
_RICH_MARKER_END = _RICH_MARKER_OFFSET + 16

#: e_lfanew, excluded from the byte sum by the algorithm.
_E_LFANEW_OFFSET = 0x3C
_E_LFANEW_END = 0x40


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


def _rich_checksum_mismatch(
    raw: bytes, values: list[int], stored_checksum: int
) -> bool | None:
    """Recompute the Rich header checksum and compare it with the stored one.

    Args:
        raw:             The whole file.
        values:          pefile's flat ``[comp_id, count, ...]`` list.
        stored_checksum: The key recovered from the header.

    Returns:
        True when the recomputed value disagrees with the stored one,
        False when they agree, and **None when the question could not be
        answered** — which the caller must not treat as tampering.

    The linker computes::

        csum = offset of the DanS marker
        for each byte b of the DOS header and stub before that marker,
            excluding the e_lfanew field:  csum += rol32(b, i & 31)
        for each (comp_id, count) pair:    csum += rol32(comp_id,
                                                         count & 31)

    This was previously computed over ``rh["clear_data"]`` seeded with
    ``e_lfanew``, on the belief that ``clear_data`` is the DOS header
    and stub with the Rich header zeroed. It is not — pefile returns
    the **decrypted Rich header body** there. Region and seed were both
    wrong, and the check reported "likely tampered" on every genuine
    Microsoft binary measured, seven of seven.

    The marker is verified in place rather than searched for. 0x80 is
    pefile's own constant — ``parse_rich_header`` slices its record data
    from exactly there, so ``values`` comes from 0x80 whatever the file
    says. An earlier draft scanned for the first dword XORing to DanS,
    which was a tamper-detection **bypass**: the marker is a single
    dword, so planting a copy earlier in the stub moved the computation
    off the real header. pefile cannot be relied on to reject a bad
    marker either — when its own check fails it appends a warning and
    carries on, returning a populated dict with a garbage values list.
    """
    if len(raw) < _RICH_MARKER_END:
        return None
    try:
        marker = struct.unpack_from("<4I", raw, _RICH_MARKER_OFFSET)
        key = stored_checksum & 0xFFFFFFFF
        if (marker[0] ^ key) != _RICH_DANS or marker[1:] != (key, key, key):
            return None

        csum = _RICH_MARKER_OFFSET
        for i in range(_RICH_MARKER_OFFSET):
            if _E_LFANEW_OFFSET <= i < _E_LFANEW_END:
                continue
            csum = (csum + _rol32(raw[i], i & 0x1F)) & 0xFFFFFFFF
        # `values` is flat — [comp_id, count, comp_id, count, ...] — so
        # the pairs are taken by stride. Unpacking it as tuples would
        # raise TypeError, and the handler below would turn that into
        # "not corrupted" on every binary, disabling the check in
        # silence.
        for j in range(0, len(values) - 1, 2):
            comp_id = values[j] & 0xFFFFFFFF
            count = values[j + 1] & 0xFFFFFFFF
            csum = (csum + _rol32(comp_id, count & 0x1F)) & 0xFFFFFFFF
        return (csum & 0xFFFFFFFF) != key
    except Exception:  # noqa: BLE001
        # A failed computation is not evidence of tampering.
        return None


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
    # The checksum doubles as the XOR key for the header, so a crypter
    # that rewrites the region without recomputing it leaves a mismatch
    # behind — evidence the binary was modified after the linker
    # finished with it. None means the question could not be answered,
    # which is not the same as tampering and must not score.
    # ------------------------------------------------------------------
    if stored_checksum is not None and values:
        verdict = _rich_checksum_mismatch(
            getattr(pe, "__data__", b""), values, stored_checksum
        )
        if verdict is not None:
            info["corrupted"] = verdict

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


#: IMAGE_DEBUG_TYPE_REPRO. Emitted by the Microsoft toolchain under
#: /Brepro (the default since VS2015), and the only reliable marker
#: that TimeDateStamp holds a build hash rather than a date.
_IMAGE_DEBUG_TYPE_REPRO = 16


def _has_repro_debug_entry(pe: "pefile.PE") -> bool:
    """Report whether the PE declares a reproducible (/Brepro) build.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        True when a type-16 debug directory entry is present.

    This is deliberately NOT folded into ``_extract_debug_info``. That
    function returns on the first CodeView entry it finds, and a real
    Microsoft binary's debug types run ``[2, 12, 13, 16, 20]`` — type 2
    is CodeView and comes first, so a type-16 test inside that loop
    would never be reached on exactly the files this exists for.

    pefile omits ``DIRECTORY_ENTRY_DEBUG`` entirely rather than leaving
    it empty when a PE has no debug directory, so the attribute is
    checked rather than assumed; an AttributeError escaping here would
    degrade every debug-less PE to an error.

    A debug entry is attacker-writable, so this establishes what the
    file CLAIMS about its own build, not a fact about the timestamp.
    What it licenses is "this field is a build hash per the REPRO
    entry", never "this timestamp is trustworthy".
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return False
    try:
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            if getattr(entry.struct, "Type", None) == _IMAGE_DEBUG_TYPE_REPRO:
                return True
    except Exception:  # noqa: BLE001
        return False
    return False


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
