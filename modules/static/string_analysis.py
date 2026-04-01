"""String analysis module.

Invokes FLOSS (Mandiant) via subprocess for deobfuscated string extraction.
Falls back to basic regex-based string extraction if FLOSS is unavailable.
Returns a standard module result dict with score_delta and reason.
"""

import json
import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Minimum printable-ASCII string length for raw extraction.
_MIN_STRING_LENGTH = 4

# Regex for printable ASCII runs (the classic Unix `strings` approach).
_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LENGTH)

# Wide-char (UTF-16LE) string pattern — common in Windows PE binaries.
_WIDE_RE = re.compile(
    rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_STRING_LENGTH
)

# Suspicious string patterns that suggest malicious behaviour.
_SUSPICIOUS_PATTERNS = [
    # PowerShell / command execution
    (re.compile(r"powershell", re.IGNORECASE), "PowerShell reference"),
    (re.compile(r"cmd\.exe|command\.com", re.IGNORECASE), "Command shell reference"),
    (re.compile(r"-enc\s|encodedcommand", re.IGNORECASE), "Encoded command flag"),
    (re.compile(r"Invoke-Expression|IEX\s*\(", re.IGNORECASE), "PowerShell IEX"),
    (re.compile(r"bypass|unrestricted", re.IGNORECASE), "Execution policy bypass"),
    # Persistence
    (re.compile(r"\\CurrentVersion\\Run", re.IGNORECASE), "Registry Run key (persistence)"),
    (re.compile(r"schtasks|TaskScheduler", re.IGNORECASE), "Scheduled task reference"),
    (re.compile(r"\\Startup\\", re.IGNORECASE), "Startup folder reference"),
    # Credential / data theft
    (re.compile(r"password|passwd|credential", re.IGNORECASE), "Password/credential string"),
    (re.compile(r"\\Login Data|\\Cookies", re.IGNORECASE), "Browser data path"),
    (re.compile(r"wallet\.dat|bitcoin", re.IGNORECASE), "Cryptocurrency reference"),
    # Network indicators
    (re.compile(r"User-Agent:", re.IGNORECASE), "HTTP User-Agent header"),
    (re.compile(r"POST\s+/|GET\s+/", re.IGNORECASE), "HTTP request pattern"),
    (re.compile(r"smtp|pop3|imap", re.IGNORECASE), "Email protocol reference"),
    # Anti-analysis
    (re.compile(r"vmware|virtualbox|vbox|qemu|sandboxie", re.IGNORECASE), "VM/sandbox detection string"),
    (re.compile(r"wireshark|fiddler|procmon|ollydbg|x64dbg|ida\s", re.IGNORECASE), "Analysis tool detection"),
    # Obfuscation indicators
    (re.compile(r"base64|FromBase64", re.IGNORECASE), "Base64 reference"),
    (re.compile(r"XOR|decrypt|encrypt", re.IGNORECASE), "Crypto/obfuscation reference"),
]

# Maximum number of strings to store in data (prevent huge reports).
_MAX_STRINGS_STORED = 500

# Maximum file size to attempt raw string extraction (50 MiB).
_MAX_RAW_EXTRACT_SIZE = 50 * 1024 * 1024


def run(file_path: Path, config: dict) -> dict:
    """Extract and analyse strings from the target file.

    Tries FLOSS first for deobfuscated strings; falls back to basic
    regex-based extraction if FLOSS is unavailable.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict.

    Returns:
        Standard module result dict.
    """
    floss_path = Path(config.get("floss_binary", "./bin/floss"))
    timeout = config.get("module_timeout_seconds", 60)

    # Try FLOSS first, fall back to raw extraction.
    floss_result = _run_floss(file_path, floss_path, timeout)

    if floss_result is not None:
        all_strings = floss_result["strings"]
        source = "floss"
        floss_data = floss_result
    else:
        all_strings = _extract_raw_strings(file_path)
        source = "raw"
        floss_data = None

    # Analyse extracted strings for suspicious patterns.
    suspicious_hits, suspicious_details = _find_suspicious(all_strings)

    # Build score.
    score_delta = 0
    reasons: list[str] = []

    if suspicious_hits:
        # Scale score by number of distinct suspicious categories found.
        n_categories = len(suspicious_hits)
        if n_categories >= 5:
            score_delta += 15
        elif n_categories >= 3:
            score_delta += 10
        else:
            score_delta += 5

        top = sorted(suspicious_hits)[:5]
        suffix = f" (+{n_categories - 5} more)" if n_categories > 5 else ""
        reasons.append(
            f"Suspicious strings: {', '.join(top)}{suffix}"
        )

    data: dict = {
        "source": source,
        "total_strings": len(all_strings),
        "strings_sample": all_strings[:_MAX_STRINGS_STORED],
        "suspicious_categories": sorted(suspicious_hits) if suspicious_hits else [],
        "suspicious_matches": suspicious_details,
    }

    if floss_data is not None:
        data["floss_static_strings"] = floss_data.get("static_count", 0)
        data["floss_decoded_strings"] = floss_data.get("decoded_count", 0)
        data["floss_stack_strings"] = floss_data.get("stack_count", 0)

        # Decoded/stack strings are strong obfuscation indicators.
        decoded = floss_data.get("decoded_count", 0)
        stack = floss_data.get("stack_count", 0)
        if decoded > 0 or stack > 0:
            score_delta += 10
            parts = []
            if decoded > 0:
                parts.append(f"{decoded} decoded")
            if stack > 0:
                parts.append(f"{stack} stack")
            reasons.append(
                f"FLOSS found obfuscated strings: {', '.join(parts)}"
            )

    reason_text = "; ".join(reasons) if reasons else "No suspicious strings found"

    return {
        "module": "string_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


def _run_floss(
    file_path: Path, floss_path: Path, timeout: int
) -> dict | None:
    """Invoke FLOSS and parse its JSON output.

    Returns a dict with string lists and counts, or None if FLOSS
    is unavailable or fails.
    """
    if not floss_path.is_file():
        logger.info("FLOSS binary not found at %s — falling back to raw strings", floss_path)
        return None

    cmd = [str(floss_path), "--json", str(file_path)]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("FLOSS timed out after %ds — falling back to raw strings", timeout)
        return None
    except OSError as exc:
        logger.warning("FLOSS invocation failed: %s — falling back to raw strings", exc)
        return None

    if proc.returncode != 0:
        stderr_snippet = proc.stderr[:500].decode("utf-8", errors="replace") if proc.stderr else ""
        logger.warning(
            "FLOSS exited with code %d: %s — falling back to raw strings",
            proc.returncode,
            stderr_snippet,
        )
        return None

    try:
        floss_json = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Failed to parse FLOSS JSON output: %s", exc)
        return None

    # Extract strings from FLOSS JSON structure.
    # FLOSS v2+ JSON has: strings.static_strings, strings.decoded_strings,
    # strings.stack_strings, strings.tight_strings
    strings_section = floss_json.get("strings", {})

    static = _extract_floss_strings(strings_section.get("static_strings", []))
    decoded = _extract_floss_strings(strings_section.get("decoded_strings", []))
    stack = _extract_floss_strings(strings_section.get("stack_strings", []))
    tight = _extract_floss_strings(strings_section.get("tight_strings", []))

    all_strings = static + decoded + stack + tight

    return {
        "strings": all_strings,
        "static_count": len(static),
        "decoded_count": len(decoded),
        "stack_count": len(stack),
        "tight_count": len(tight),
    }


def _extract_floss_strings(entries: list) -> list[str]:
    """Extract plain string values from FLOSS JSON string entries.

    FLOSS entries can be either plain strings or dicts with a "string" key.
    """
    result: list[str] = []
    for entry in entries:
        if isinstance(entry, str):
            result.append(entry)
        elif isinstance(entry, dict):
            s = entry.get("string") or entry.get("value", "")
            if s:
                result.append(str(s))
    return result


def _extract_raw_strings(file_path: Path) -> list[str]:
    """Extract printable ASCII and wide-char strings from a file.

    This is the fallback when FLOSS is not available — equivalent to
    the Unix ``strings`` command.
    """
    try:
        file_size = file_path.stat().st_size
        if file_size > _MAX_RAW_EXTRACT_SIZE:
            logger.warning(
                "File too large for raw string extraction (%d bytes) — truncating",
                file_size,
            )
    except OSError:
        return []

    try:
        with file_path.open("rb") as fh:
            data = fh.read(_MAX_RAW_EXTRACT_SIZE)
    except OSError as exc:
        logger.warning("Could not read file for string extraction: %s", exc)
        return []

    # ASCII strings.
    ascii_strings = [m.group().decode("ascii") for m in _ASCII_RE.finditer(data)]

    # Wide-char (UTF-16LE) strings.
    wide_strings = []
    for m in _WIDE_RE.finditer(data):
        try:
            wide_strings.append(m.group().decode("utf-16-le"))
        except UnicodeDecodeError:
            continue

    # Deduplicate while preserving order.
    seen: set[str] = set()
    result: list[str] = []
    for s in ascii_strings + wide_strings:
        if s not in seen:
            seen.add(s)
            result.append(s)

    return result


def _find_suspicious(strings: list[str]) -> tuple[set[str], list[dict]]:
    """Scan strings for suspicious patterns.

    Returns:
        (set of category names, list of match detail dicts)
    """
    categories: set[str] = set()
    details: list[dict] = []

    for s in strings:
        for pattern, category in _SUSPICIOUS_PATTERNS:
            if pattern.search(s):
                categories.add(category)
                # Only store first few examples per category to avoid bloat.
                cat_count = sum(1 for d in details if d["category"] == category)
                if cat_count < 3:
                    # Truncate very long strings.
                    display = s if len(s) <= 120 else s[:117] + "..."
                    details.append({
                        "category": category,
                        "string": display,
                    })

    return categories, details
