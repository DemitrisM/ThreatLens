"""PE header extraction + compile-timestamp anomaly check.

Design notes
------------
The compile timestamp is the one header field malware routinely forges, and
it is forged in both directions: forward, to defeat naive "is this newer than
my last scan" logic, and backward, to make a sample look like an old, settled
system file. Neither direction is provable from the file alone, so this module
only flags values that are impossible rather than merely unusual — a
timestamp cannot be in the future, and the PE format did not exist before
1990.

Zero is deliberately not an anomaly. Reproducible builds (Go, and MSVC under
/Brepro) zero the field on purpose, so scoring it would penalise a large
population of legitimate binaries.
"""

from datetime import datetime, timezone

# IMAGE_FILE_HEADER.Machine values from winnt.h. Only the architectures the
# tool can meaningfully encounter on Windows are named; anything else renders
# as its raw hex value rather than being guessed at.
# Machine type constants.
_MACHINE_TYPES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x86-64 (64-bit)",
    0x01C0: "ARM",
    0x01C4: "ARMv7 Thumb-2",
    0xAA64: "ARM64",
    0x0200: "IA-64",
}


def _extract_headers(pe: "pefile.PE") -> dict:
    """Extract key PE header fields.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        A dict of header fields. Addresses are hex strings for display,
        while ``compile_timestamp_raw`` keeps the integer so
        ``_check_timestamp`` can do arithmetic on it without reparsing.
    """
    file_header = pe.FILE_HEADER
    optional_header = pe.OPTIONAL_HEADER

    machine = file_header.Machine
    machine_str = _MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04X})")

    # ------------------------------------------------------------------
    # Convert the timestamp for display.
    #
    # TimeDateStamp is a 32-bit Unix epoch value, and a forged one can sit
    # far outside the range datetime accepts. A failure here is recorded
    # as text and left for _check_timestamp to score — extraction must
    # not raise on a hostile file.
    # ------------------------------------------------------------------
    # Compile timestamp.
    timestamp_raw = file_header.TimeDateStamp
    try:
        compile_time = datetime.fromtimestamp(timestamp_raw, tz=timezone.utc).isoformat()
    except (OSError, ValueError, OverflowError):
        compile_time = f"Invalid timestamp ({timestamp_raw})"

    return {
        "machine": machine_str,
        "compile_timestamp": compile_time,
        "compile_timestamp_raw": timestamp_raw,
        "entry_point": hex(optional_header.AddressOfEntryPoint),
        "image_base": hex(optional_header.ImageBase),
        "number_of_sections": file_header.NumberOfSections,
        "characteristics": hex(file_header.Characteristics),
        "dll_characteristics": hex(optional_header.DllCharacteristics),
        "subsystem": optional_header.Subsystem,
    }


def _check_timestamp(headers: dict) -> tuple[int, str]:
    """Check for anomalous compile timestamps.

    Args:
        headers: The dict returned by ``_extract_headers``.

    Returns:
        (score_delta, reason_string) — (0, "") if timestamp looks normal.
    """
    # ------------------------------------------------------------------
    # Step 1: Ignore a zeroed timestamp.
    #
    # Reproducible builds zero this field deliberately (Go always does,
    # MSVC does under /Brepro), so it is a build-configuration signal
    # rather than an anomaly.
    # ------------------------------------------------------------------
    raw_ts = headers.get("compile_timestamp_raw", 0)
    if raw_ts == 0:
        return 0, ""

    # ------------------------------------------------------------------
    # Step 2: A value datetime cannot represent at all is out of range for
    # a 32-bit epoch and can only have been written by hand.
    # ------------------------------------------------------------------
    try:
        compile_dt = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return 5, f"Invalid compile timestamp ({raw_ts}) — likely forged"

    now = datetime.now(tz=timezone.utc)

    # ------------------------------------------------------------------
    # Step 3: Two impossibilities, scored identically.
    #
    # Only impossible values are flagged, never merely surprising ones: a
    # genuinely old binary is common in the wild, so "older than I
    # expected" would generate false positives without evidence.
    # ------------------------------------------------------------------
    # Future timestamp = definitely forged.
    if compile_dt > now:
        return 5, (
            f"Compile timestamp is in the future ({compile_dt.strftime('%Y-%m-%d')}) "
            f"— likely forged"
        )

    # Before 1990 = suspicious (Windows PE format didn't exist).
    if compile_dt.year < 1990:
        return 5, (
            f"Compile timestamp is implausibly old ({compile_dt.strftime('%Y-%m-%d')}) "
            f"— likely forged"
        )

    return 0, ""
