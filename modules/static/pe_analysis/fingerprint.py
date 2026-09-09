"""Compiled-language fingerprint + DllCharacteristics mitigations.

Design notes
------------
Both checks here are *context*, not verdicts. Knowing a sample is a Go binary
changes how every other indicator should be read — Go statically links its
runtime, so a Go executable legitimately shows high entropy, a huge import
footprint and unfamiliar section names that would be suspicious in a C
program. Reporting the language lets the rest of the report be interpreted
correctly rather than penalising a whole toolchain.

The same applies to the mitigation flags: their absence is a soft signal
about how the binary was built, not evidence of malice on its own.
"""


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

    Args:
        pe:       A parsed ``pefile.PE`` object.
        sections: Section dicts from the sections submodule, used for the
                  cheap section-name check before touching file bytes.

    Returns:
        One of: "go", "rust", "nim", or "" (unknown / standard).

    We sample only the first 4 MiB of the binary for marker bytes to
    keep the cost bounded on large samples.
    """
    section_names = {s.get("name", "").lower() for s in sections}

    # ------------------------------------------------------------------
    # Step 1: The free check first.
    #
    # Section names are already parsed, so testing them costs nothing and
    # avoids reading megabytes for the common Go case.
    # ------------------------------------------------------------------
    # .symtab is the strongest single Go indicator on Windows.
    if ".symtab" in section_names:
        return "go"

    # ------------------------------------------------------------------
    # Step 2: Fall back to a bounded byte scan.
    #
    # 4 MiB is chosen because all three toolchains place their markers in
    # the runtime, which is linked early; scanning a 200 MB Go binary in
    # full would cost far more than the signal is worth.
    # ------------------------------------------------------------------
    try:
        sample = pe.__data__[: 4 * 1024 * 1024]
    except Exception:  # noqa: BLE001
        # A truncated or unmapped image — no fingerprint, not an error.
        return ""

    # Ordered most- to least-specific. Each marker is emitted by the
    # language runtime itself, so it survives stripping but not packing;
    # a packed sample simply returns "" rather than a wrong answer.
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

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        A dict of six booleans under a single convention: True always
        means "mitigation enabled". Every key is present even when the
        header is unreadable, so callers never need to guard the lookup.
    """
    try:
        c = pe.OPTIONAL_HEADER.DllCharacteristics
    except AttributeError:
        # No optional header at all — report every mitigation absent
        # rather than omitting keys and breaking the caller.
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
