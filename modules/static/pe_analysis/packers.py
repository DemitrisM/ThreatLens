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
# NOTE: the two tables below are currently UNUSED. `_detect_packers`
# matches with an inline startswith chain instead, and that chain covers
# fewer packers than these tables list — ".yP" (Y0da), ".packed" and
# PECompact appear here but are never actually matched. Kept as the
# reference list they were written to be; wiring them into the matcher is
# a behaviour change and belongs in its own commit.
# ----------------------------------------------------------------------
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
    section_names = {s["name"] for s in sections}

    # ------------------------------------------------------------------
    # Step 1: Match section names.
    #
    # Prefix matching rather than equality, because packers number their
    # sections (UPX0/UPX1/UPX2, .vmp0/.vmp1) and the count varies with
    # the packed program.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 2: Catch UPX that renamed its sections.
    #
    # Renaming UPX0/UPX1 is the standard trick for evading the check
    # above, but the "UPX!" magic in the trailing header survives it
    # because the unpacker stub needs it to find its own metadata.
    # ------------------------------------------------------------------
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
