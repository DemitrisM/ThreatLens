"""Packer detection, .NET detection, installer-wrapper fingerprints.

Design notes
------------
Packing is not malicious by itself — commercial software uses UPX, Themida and
VMProtect for legitimate size and anti-piracy reasons. What packing means for
this tool is that *the other PE indicators stop being trustworthy*: imports
shrink to a loader stub, entropy rises everywhere, and section layout reflects
the packer rather than the program. So the value of naming the packer is
mostly interpretive, and the scoring weight is correspondingly modest.

The same reasoning applies to installers. A dropper needs to write a payload,
a config and an autorun shim, which is exactly what an installer does, so
commodity malware often just uses NSIS or InnoSetup rather than writing its
own. Naming the wrapper tells the analyst which extractor to reach for.

Detection is ordered cheapest-first throughout: section names are already
parsed, so they are consulted before any byte scan.
"""

import pefile

# ----------------------------------------------------------------------
# Section-name prefixes, mapped to the packer they identify.
#
# PREFIXES, not exact names: packers number their sections (UPX0/UPX1/
# UPX2, .vmp0/.vmp1) and the count varies with the packed program, so an
# exact-match lookup would miss every section but the first. Keys are
# lowercase; the matcher lowercases the section name before comparing.
# ----------------------------------------------------------------------
_PACKER_SECTION_NAMES: dict[str, str] = {
    "upx": "UPX",
    ".mpress": "MPRESS",
    "mpress": "MPRESS",
    ".themida": "Themida",
    "themida": "Themida",
    ".vmp": "VMProtect",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".nsp": "NSPack",
    ".petite": "Petite",
    ".yp": "Y0da Packer",
    ".packed": "Generic packer",
}

# ----------------------------------------------------------------------
# Vendor strings, searched in the DOS/PE header area and the overlay.
#
# Deliberately NOT searched across the whole image. A full-file scan for
# a word like "UPX" or "Petite" fires on any binary that merely mentions
# it - a security tool, an installer's own string table - and the header
# and overlay are where a packer's own stub and trailer actually live.
# ----------------------------------------------------------------------
_PACKER_SIGNATURES: dict[str, bytes] = {
    "UPX": b"UPX",
    "MPRESS": b"MPRESS",
    "Themida": b"Themida",
    "VMProtect": b"VMProtect",
    "ASPack": b"ASPack",
    "PECompact": b"PECompact",
    "Petite": b"Petite",
    "NSPack": b"NSPack",
}

#: Bytes of the file head and of the overlay searched for the vendor
#: strings above. Both are generous for a packer stub and bounded so the
#: scan cost does not scale with the sample.
_HEADER_SCAN_BYTES = 4096
_OVERLAY_SCAN_BYTES = 64 * 1024


def _detect_packers(pe: "pefile.PE", sections: list[dict]) -> list[str]:
    """Detect known packers by section names and PE characteristics.

    Args:
        pe:       A parsed ``pefile.PE`` object.
        sections: Section dicts from the sections submodule.

    Returns:
        A list of packer names found (empty list if none detected).
        Names are deduplicated, since several sections of one packer
        (UPX0/UPX1/UPX2) would otherwise report it repeatedly.
    """
    found: list[str] = []

    def _add(name: str) -> None:
        """Append a packer name once."""
        if name not in found:
            found.append(name)

    # ------------------------------------------------------------------
    # Step 1: Match section names against the prefix table.
    #
    # Longest prefix first so a more specific entry wins over a shorter
    # one that also matches, rather than the result depending on dict
    # ordering.
    # ------------------------------------------------------------------
    ordered = sorted(_PACKER_SECTION_NAMES.items(), key=lambda kv: -len(kv[0]))
    for section in sections:
        name = str(section.get("name", "")).strip().lower()
        if not name:
            continue
        for prefix, packer in ordered:
            if name.startswith(prefix):
                _add(packer)
                break

    # ------------------------------------------------------------------
    # Step 2: Search the header area and the overlay for vendor strings.
    #
    # Catches packers that renamed their sections, which is the standard
    # way of defeating step 1. The UPX case matters most: the "UPX!"
    # magic in the trailing header survives renaming because the
    # unpacker stub needs it to find its own metadata.
    # ------------------------------------------------------------------
    try:
        raw = pe.__data__
        haystack = raw[:_HEADER_SCAN_BYTES]
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            haystack += raw[overlay_offset:overlay_offset + _OVERLAY_SCAN_BYTES]
    except Exception:  # noqa: BLE001
        return found

    for packer, marker in _PACKER_SIGNATURES.items():
        if marker in haystack:
            _add(packer)

    return found


def _is_dotnet(pe: "pefile.PE") -> bool:
    """Detect whether the PE is a .NET (CLR) assembly.

    Checks for the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14).

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        True when the CLR header directory is populated. Worth knowing
        because a .NET assembly's real logic is IL in a managed stream,
        so native-code indicators (imports, entry point, capa) see only
        the runtime shim and read as uninformative rather than clean.
    """
    # pefile has renamed this key across versions; fall back to the
    # literal index from winnt.h rather than raising a KeyError.
    com_descriptor_index = pefile.DIRECTORY_ENTRY.get(
        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"
    )
    if com_descriptor_index is None:
        com_descriptor_index = 14

    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= com_descriptor_index:
        return False

    clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_descriptor_index]
    return clr_dir.VirtualAddress != 0 and clr_dir.Size != 0


def _detect_installer(pe: "pefile.PE", sections: list[dict]) -> str | None:
    """Detect common Windows installer wrappers (NSIS, InnoSetup, …).

    Many commodity droppers ship as off-the-shelf installers because
    they need to extract a payload + a config + an autorun shim. We
    scan a bounded prefix of the binary for vendor strings and
    section-name signatures.

    Args:
        pe:       A parsed ``pefile.PE`` object.
        sections: Section dicts from the sections submodule.

    Returns:
        The wrapper name, or None. First match wins — these wrappers do
        not nest, so there is nothing to gain from scanning on.
    """
    # Section-name signatures first (cheapest).
    section_names = {s.get("name", "").lower() for s in sections}
    if ".ndata" in section_names:  # NSIS uses .ndata
        return "NSIS"

    # 2 MiB prefix: every marker below lives in the installer stub, which
    # is prepended to the payload, so the bound costs no coverage.
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
    # Skips the first 256 KiB deliberately: the 7z magic appears in the
    # SFX *payload*, and matching it in the stub would fire on any binary
    # that merely links the 7-Zip library.
    if b"7z\xbc\xaf\x27\x1c" in sample[256 * 1024:]:
        # 7z magic in the overlay region — common SFX dropper shape.
        return "7-Zip SFX"
    return None
