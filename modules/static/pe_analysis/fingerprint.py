"""Compiled-language fingerprint + DllCharacteristics mitigations."""


# DLL characteristics bit flags (winnt.h IMAGE_DLLCHARACTERISTICS_*).
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE     = 0x0040  # ASLR
_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY  = 0x0080
_IMAGE_DLLCHARACTERISTICS_NX_COMPAT        = 0x0100  # DEP
_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION     = 0x0200
_IMAGE_DLLCHARACTERISTICS_NO_SEH           = 0x0400
_IMAGE_DLLCHARACTERISTICS_NO_BIND          = 0x0800
_IMAGE_DLLCHARACTERISTICS_GUARD_CF         = 0x4000  # CFG
_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
_IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA  = 0x0020  # 64-bit ASLR


def _detect_compiled_language(pe: "pefile.PE", sections: list[dict]) -> str:
    """Detect Go / Rust / Nim binaries via section names + magic strings.

    Returns one of: "go", "rust", "nim", or "" (unknown / standard).

    We sample only the first 4 MiB of the binary for marker bytes to
    keep the cost bounded on large samples.
    """
    section_names = {s.get("name", "").lower() for s in sections}

    # .symtab is the strongest single Go indicator on Windows.
    if ".symtab" in section_names:
        return "go"

    try:
        sample = pe.__data__[: 4 * 1024 * 1024]
    except Exception:  # noqa: BLE001
        return ""

    # Go binaries embed an unmistakable build-id banner.
    if b"Go build ID:" in sample or b"go.buildinfo" in sample:
        return "go"

    # Rust binaries embed compiler/std markers.
    if (b"rust_panic" in sample
            or b"RUST_BACKTRACE" in sample
            or b"/rustc/" in sample):
        return "rust"

    # Nim binaries embed nimrtl / system.nim references.
    if (b"nimrtl" in sample
            or b"system.nim" in sample
            or b"NimMain" in sample):
        return "nim"

    return ""


def _analyse_dll_characteristics(pe: "pefile.PE") -> dict:
    """Inspect the DllCharacteristics flags for missing modern mitigations.

    Modern compilers enable ASLR (DYNAMIC_BASE), DEP (NX_COMPAT) and CFG
    (GUARD_CF) by default. Their absence is a soft signal that the
    binary was hand-built, packed by a custom packer, or compiled by a
    non-mainstream toolchain (often the case for malware).
    """
    try:
        c = pe.OPTIONAL_HEADER.DllCharacteristics
    except AttributeError:
        return {"aslr": False, "dep": False, "cfg": False, "seh": False,
                "high_entropy_va": False, "force_integrity": False}
    return {
        "aslr": bool(c & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        "dep": bool(c & _IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        "cfg": bool(c & _IMAGE_DLLCHARACTERISTICS_GUARD_CF),
        # SEH = NO_SEH bit *unset* means SEH is allowed (= "has SEH"),
        # which is the safe default. We invert so the dict is uniform:
        # True everywhere means "mitigation enabled".
        "seh": not bool(c & _IMAGE_DLLCHARACTERISTICS_NO_SEH),
        "high_entropy_va": bool(c & _IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
        "force_integrity": bool(c & _IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY),
    }
