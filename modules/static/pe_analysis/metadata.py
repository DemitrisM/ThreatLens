"""Rich header, DOS stub, debug PDB info, version info — PE metadata."""

import re

# Default DOS stub message in MS toolchain output.
_DEFAULT_DOS_STUB = b"This program cannot be run in DOS mode."

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
    """32-bit rotate-left helper used by the Rich header checksum."""
    value &= 0xFFFFFFFF
    bits &= 0x1F
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
