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

# Suspicious string patterns. Each entry is (pattern, category, severity).
# Severity values: "critical", "high", "medium", "low".
# Critical patterns are nearly definitive indicators of malware.
# Word boundaries (\b) are used aggressively to avoid substring false
# positives (e.g. 'imap' inside 'abiMap', 'ida' inside 'reconstruIDA').
_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ── CRITICAL: high-confidence malware indicators ──
    # Modern stealer/RAT family names embedded in their own binaries
    (re.compile(r"\b(?:RedLine|Vidar|Lumma|Raccoon|Stealc|MetaStealer|"
                r"Rhadamanthys|Mystic\s*Stealer|Atomic\s*Stealer)\b",
                re.IGNORECASE),
     "Stealer family name", "critical"),
    (re.compile(r"\b(?:AsyncRat|njRat|Quasar(?:\s*Rat)?|Nanocore|Remcos|"
                r"AgentTesla|Formbook|Snake\s*Keylogger|Warzone|XWorm|"
                r"DCRat|VenomRat)\b", re.IGNORECASE),
     "RAT family name", "critical"),
    (re.compile(r"\b(?:Cobalt\s*Strike|beacon\.dll|beacon\.exe|"
                r"Sliver(?:\s*C2)?|Havoc(?:\s*C2)?|Brute\s*Ratel|"
                r"Mythic|Empire|Metasploit|meterpreter)\b",
                re.IGNORECASE),
     "C2 framework reference", "critical"),
    # Telegram bot exfil (ID:hash format)
    (re.compile(r"api\.telegram\.org/bot[0-9]{6,}:", re.IGNORECASE),
     "Telegram bot exfil endpoint", "critical"),
    # Discord webhook exfil
    (re.compile(r"discord(?:app)?\.com/api/webhooks/[0-9]+", re.IGNORECASE),
     "Discord webhook exfil", "critical"),
    # Browser credential store paths (Chromium / Gecko)
    (re.compile(r"\\Login\s*Data\b|\\Web\s*Data\b|\\Cookies\b|"
                r"\\Local\s*State\b|logins\.json|signons\.sqlite|"
                r"key[34]\.db", re.IGNORECASE),
     "Browser credential store path", "critical"),
    # .NET stealer property/method names — extremely common in commodity
    # .NET stealers (RedLine, Vidar, Stealc, …). The compiler emits
    # backing-field markers that directly expose the property names.
    (re.compile(r"Scan(?:Wallet|Browser|Discord|Telegram|"
                r"Cookie|Password|Crypto|Steam)s?\b", re.IGNORECASE),
     ".NET stealer scan-routine", "critical"),
    (re.compile(r"\bGet(?:Chrome|Firefox|Edge|Brave|Opera|Yandex)"
                r"(?:Local|Roaming)?(?:Name|Path)", re.IGNORECASE),
     ".NET browser-harvest method", "critical"),
    (re.compile(r"\b(?:All)?Wallets?Rule\b|\bChromeRule\b|\bFirefoxRule\b|"
                r"\bDiscordRule\b|\bTelegramRule\b|\bSteamRule\b",
                re.IGNORECASE),
     ".NET stealer rule class", "critical"),
    (re.compile(r"k__BackingField.*(?:Wallet|Browser|Discord|Cookie|"
                r"Password|Crypto|Telegram|Steam)", re.IGNORECASE),
     ".NET stealer backing field", "critical"),
    # Crypto wallet artefacts. Avoid bare \bAtomic\b (matches Go's
    # *atomic.Bool / sync/atomic.* identifiers); require "Atomic Wallet".
    (re.compile(r"\bwallet\.dat\b|\bMetaMask\b|\bExodus\s*Wallet\b|"
                r"\bElectrum(?:-LTC|-BTC|-DOGE)?\b|\bCoinomi\b|"
                r"\bAtomic\s*Wallet\b|\bJaxx(?:\s*Liberty)?\b|"
                r"\bArmory\s*Wallet\b|\bBitcoinCore\b|\bGuarda\s*Wallet\b|"
                r"\\Ethereum\\|\\Bitcoin\\|\\Wallets?\\",
                re.IGNORECASE),
     "Crypto wallet artefact", "critical"),
    # Process hollowing — classic API combo
    (re.compile(r"\b(?:Nt|Zw)UnmapViewOfSection\b"),
     "Process hollowing API", "critical"),

    # ── HIGH: strong malware indicators ──
    # PowerShell offensive patterns
    (re.compile(r"powershell(?:\.exe)?\s+(?:-|/)(?:enc|e\s|nop|noni|w\s*hidden)",
                re.IGNORECASE),
     "PowerShell evasion flag", "high"),
    (re.compile(r"\bIEX\s*\(|\bInvoke-Expression\b|\bDownloadString\b|"
                r"\bDownloadFile\b|\bFromBase64String\b", re.IGNORECASE),
     "PowerShell download/exec", "high"),
    (re.compile(r"-EncodedCommand\b|-encodedcommand\b|\benc\s+[A-Za-z0-9+/]{40,}",
                re.IGNORECASE),
     "Encoded command payload", "high"),
    # LOLBins commonly abused for execution
    (re.compile(r"\b(?:regsvr32|rundll32|mshta|bitsadmin|certutil|"
                r"wmic|odbcconf|installutil|msiexec)\.exe\b",
                re.IGNORECASE),
     "LOLBin reference", "high"),
    # Anti-VM / sandbox identifiers
    (re.compile(r"\bVBox(?:Service|Tray|Control)?\b|\bvmware(?:tools|user)?\b|"
                r"\bvmtoolsd\b|\bSbieDll\b|\bSandboxie\b|\bcuckoo\b|\bcwsandbox\b",
                re.IGNORECASE),
     "VM/sandbox check", "high"),
    # Anti-debug API references (in addition to PE imports)
    (re.compile(r"\bIsDebuggerPresent\b|\bCheckRemoteDebuggerPresent\b|"
                r"\bNtGlobalFlag\b|\bProcessHeap\b\s*\+\s*0x18|"
                r"\bDebugActiveProcess\b"),
     "Anti-debug API reference", "high"),
    # .NET obfuscator markers
    (re.compile(r"\bConfuser(?:Ex)?\b|\bEazfuscator\b|"
                r"\b\.?NET\s*Reactor\b|\bSmartAssembly\b|"
                r"\bDeepSea\s*Obfuscator\b|\bDotfuscator\b|"
                r"\bAgile\s*\.NET\b", re.IGNORECASE),
     ".NET obfuscator marker", "high"),
    # Process injection / shellcode execution
    (re.compile(r"\bSetWindowsHookEx\b|\bCreateRemoteThread\b|"
                r"\bWriteProcessMemory\b|\bNtMapViewOfSection\b|"
                r"\bRtlCreateUserThread\b|\bQueueUserAPC\b"),
     "Code injection API string", "high"),

    # ── MEDIUM: suspicious context, weaker on its own ──
    # Persistence
    (re.compile(r"\\(?:CurrentVersion|Microsoft\\Windows)\\Run\b|"
                r"\\Run(?:Once|Services)?\\", re.IGNORECASE),
     "Registry persistence key", "medium"),
    (re.compile(r"\bschtasks(?:\.exe)?\b|\bTask\s*Scheduler\b|"
                r"\bSCHTASKS\b", re.IGNORECASE),
     "Scheduled task reference", "medium"),
    (re.compile(r"\\Start\s*Menu\\Programs\\Startup\\|"
                r"\\Microsoft\\Windows\\Start\s*Menu\\Programs\\Startup\\",
                re.IGNORECASE),
     "Startup folder path", "medium"),
    # Browser targets (without credential paths)
    (re.compile(r"\\(?:Google|BraveSoftware|Microsoft\\Edge|Mozilla)\\"
                r"(?:Chrome|Brave-Browser|User\s*Data|Firefox)",
                re.IGNORECASE),
     "Browser data directory", "medium"),
    # Network protocols (word-bounded — no more abiMap FPs)
    (re.compile(r"\bsmtp\.(?:gmail|yandex|mail|outlook|office365|"
                r"yahoo|protonmail|zoho)", re.IGNORECASE),
     "SMTP exfiltration host", "high"),
    (re.compile(r"\b(?:POP3|IMAP4?)\b\s*(?:Server|Host)?", re.IGNORECASE),
     "Email protocol reference", "medium"),
    # HTTP request artefacts
    (re.compile(r"\bUser-Agent:\s*[A-Za-z]"),
     "HTTP User-Agent header", "medium"),
    # Generic credential keywords (require word boundary)
    (re.compile(r"\b(?:password|passwd|credentials?)\b\s*[=:]",
                re.IGNORECASE),
     "Password/credential assignment", "medium"),
    # Crypto / obfuscation references (word-bounded)
    (re.compile(r"\b(?:base64|FromBase64String|ToBase64String)\b",
                re.IGNORECASE),
     "Base64 reference", "medium"),
    (re.compile(r"\b(?:AES|RC4|DES|RSA|XOR)\b", re.IGNORECASE),
     "Crypto algorithm reference", "low"),
    (re.compile(r"\b(?:decrypt|encrypt|obfuscat|deobfuscat)(?:ed|ion|or)?\b",
                re.IGNORECASE),
     "Crypto/obfuscation reference", "low"),
    # Analysis tool detection (word-bounded)
    (re.compile(r"\b(?:wireshark|fiddler|procmon|procexp|"
                r"ollydbg|x64dbg|x32dbg|windbg|ImmunityDebugger)\b",
                re.IGNORECASE),
     "Analysis tool name", "high"),
    (re.compile(r"\bIDA\s*(?:Pro|Free|7\.|8\.|9\.)|\bida64\.exe\b"),
     "IDA Pro reference", "medium"),
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
    suspicious_hits, suspicious_details, severity_counts = _find_suspicious(
        all_strings
    )

    # Build score — weighted by severity, capped to avoid runaway totals.
    score_delta = 0
    reasons: list[str] = []

    if suspicious_hits:
        # Severity weights: each unique critical = +10, high = +5, medium = +3.
        crit_score = min(severity_counts.get("critical", 0) * 10, 30)
        high_score = min(severity_counts.get("high", 0) * 5, 15)
        med_score = min(severity_counts.get("medium", 0) * 3, 10)
        low_score = 0  # purely informational, no points
        score_delta = crit_score + high_score + med_score + low_score

        # Total cap so string analysis can never dominate.
        score_delta = min(score_delta, 40)

        # Build reason — show critical/high categories first.
        ordered = _order_categories_by_severity(suspicious_hits)
        top = ordered[:5]
        suffix = f" (+{len(ordered) - 5} more)" if len(ordered) > 5 else ""
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


def _find_suspicious(
    strings: list[str],
) -> tuple[set[str], list[dict], dict[str, int]]:
    """Scan strings for suspicious patterns.

    Returns:
        (categories_set, match_details_list, severity_counts_by_level)
    """
    categories: set[str] = set()
    details: list[dict] = []
    # Map category → severity (for ordering and scoring)
    seen_severity: dict[str, str] = {}

    for s in strings:
        for pattern, category, severity in _SUSPICIOUS_PATTERNS:
            if pattern.search(s):
                categories.add(category)
                seen_severity[category] = severity
                # Only store first few examples per category to avoid bloat.
                cat_count = sum(1 for d in details if d["category"] == category)
                if cat_count < 3:
                    # Truncate very long strings.
                    display = s if len(s) <= 120 else s[:117] + "..."
                    details.append({
                        "category": category,
                        "severity": severity,
                        "string": display,
                    })

    # Count distinct categories per severity level
    severity_counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    for sev in seen_severity.values():
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return categories, details, severity_counts


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _order_categories_by_severity(categories: set[str]) -> list[str]:
    """Order categories so the most severe appear first.

    The severity level is recovered by re-checking against the pattern
    table — categories without a known severity sort last.
    """
    sev_lookup: dict[str, str] = {}
    for _, cat, sev in _SUSPICIOUS_PATTERNS:
        if cat not in sev_lookup:
            sev_lookup[cat] = sev
    return sorted(
        categories,
        key=lambda c: (_SEVERITY_RANK.get(sev_lookup.get(c, "low"), 9), c),
    )
