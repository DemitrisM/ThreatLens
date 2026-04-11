"""PE header extraction + compile-timestamp anomaly check."""

from datetime import datetime, timezone

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
    """Extract key PE header fields."""
    file_header = pe.FILE_HEADER
    optional_header = pe.OPTIONAL_HEADER

    machine = file_header.Machine
    machine_str = _MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04X})")

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

    Returns:
        (score_delta, reason_string) — (0, "") if timestamp looks normal.
    """
    raw_ts = headers.get("compile_timestamp_raw", 0)
    if raw_ts == 0:
        return 0, ""

    try:
        compile_dt = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return 5, f"Invalid compile timestamp ({raw_ts}) — likely forged"

    now = datetime.now(tz=timezone.utc)

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
