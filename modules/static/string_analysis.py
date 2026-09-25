"""String analysis module.

Invokes FLOSS (Mandiant) via subprocess for deobfuscated string extraction.
Falls back to basic regex-based string extraction if FLOSS is unavailable.
Returns a standard module result dict with score_delta and reason.

Design notes
------------
Two extraction paths, one analysis path. FLOSS is preferred because it
recovers strings that are *never present in the file* — stack strings built
byte by byte at runtime, and strings the sample decodes with its own routine
— which is exactly the population a packed stealer hides its C2 in. When
FLOSS is absent, times out, or fails, the module degrades to a `strings`
equivalent rather than skipping (design rule 2): raw strings still carry
most indicators, and reporting nothing would be worse than reporting less.
``data["source"]`` records which path ran, because the same sample scores
differently under each and the report must not hide that.

Scoring counts *distinct categories*, never occurrences. A binary naming
"CreateRemoteThread" forty times is one injection signal, not forty, and
occurrence counting is precisely how a string-matching module ends up
outweighing every structural finding in the pipeline. Each severity tier
then gets its own sub-cap on top (30/15/10), so no single tier can carry
the module on its own.

Pattern authoring rule: every pattern is word-bounded unless it names a
path fragment or a URL shape. The unanchored versions produced a steady
stream of false positives from ordinary identifiers — 'imap' inside
'abiMap', 'ida' inside 'reconstruIDA', 'Atomic' inside Go's sync/atomic —
and each \b in the table below is there because of a specific one.
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
#
# The tier is a statement about *how often the pattern is wrong*, not about
# how bad the behaviour would be. "critical" is reserved for strings with
# no plausible benign source: a family name a builder stamped into its own
# output, a Telegram bot token in exfil URL form, a browser credential-store
# path. "high" covers strings that are damning in a sample but ordinary in a
# security tool or installer. "medium" is context. "low" scores nothing at
# all and exists only so the category still appears in the report.
#
# Section banners below mark the tiers, but the severity in each tuple is
# what counts — one SMTP pattern sits under the MEDIUM banner carrying a
# "high" severity, and the tuple wins.
#
# Categories, not patterns, are the scoring unit, so several patterns may
# share a category name deliberately to keep one behaviour worth one score.
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
# The full count is reported separately as total_strings, so truncation
# never hides the scale — only the tail of the sample.
_MAX_STRINGS_STORED = 500

# Maximum file size to attempt raw string extraction (50 MiB).
# A read bound rather than a refusal: past this point the file is truncated
# and analysed anyway, since the strings that matter in a padded dropper are
# rarely in the last gigabyte of zero fill.
_MAX_RAW_EXTRACT_SIZE = 50 * 1024 * 1024


def run(file_path: Path, config: dict) -> dict:
    """Extract and analyse strings from the target file.

    Tries FLOSS first for deobfuscated strings; falls back to basic
    regex-based extraction if FLOSS is unavailable.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict. Read for ``floss_binary``
                   and ``module_timeout_seconds``.

    Returns:
        Standard module result dict. Always "success" — every failure below
        degrades to the raw path, and a file with no suspicious strings is a
        real result rather than a skip.
    """
    # ------------------------------------------------------------------
    # Phase 1: Extract. FLOSS first, raw strings as the fallback.
    #
    # _run_floss() returns None for every failure it can have — missing
    # binary, timeout, non-zero exit, unparseable JSON — so the caller has
    # one branch rather than five. Which path ran is recorded in the data,
    # not inferred by the reporters.
    # ------------------------------------------------------------------
    floss_path = Path(config.get("floss_binary", "./bin/floss"))

    # FLOSS gets its own budget, like capa does. It used to be handed the
    # generic `module_timeout_seconds` (default 60), which emulation cannot
    # meet: measured, a 1 MB PE takes 127-170s. So FLOSS timed out on every
    # sample it was ever given and silently fell back to raw — which is why
    # `source` read "raw" on 311 of 311 corpus files.
    timeout = config.get("floss_timeout_seconds", 300)
    emulation = bool(config.get("floss_emulation", False))

    floss_result, failure = _run_floss(file_path, floss_path, timeout,
                                       emulation=emulation)

    # ── Two-step fallback, not one, and only for a timeout ──────────────
    # FLOSS buffers its JSON and writes nothing when killed, so a timed-out
    # emulation run yields no strings at all. Dropping straight to the
    # in-tree raw extractor would mean spending the whole budget and then
    # returning a *worse* result than the one-second static run we could
    # have had. So a timeout retries with emulation off; only a failure of
    # that reaches the raw path.
    #
    # Gated on the reason, not merely on `floss_result is None`. _run_floss
    # answers None for five different failures, and the other four must not
    # take this branch: a crashed emulator would be recorded and rendered
    # as "timed out", telling the analyst the budget was too small when the
    # run never got that far, and an absent binary would log a 300-second
    # wait that never happened and then re-invoke a binary that is still
    # not there.
    emulation_timed_out = False
    if failure == "timeout" and emulation:
        emulation_timed_out = True
        logger.warning(
            "FLOSS emulation exceeded %ds — retrying with static strings only",
            timeout,
        )
        floss_result, _ = _run_floss(file_path, floss_path, timeout,
                                     emulation=False)

    if floss_result is not None:
        all_strings = floss_result["strings"]
        source = "floss"
        floss_data = floss_result
    else:
        logger.info("Falling back to the in-tree raw string extractor")
        all_strings = _extract_raw_strings(file_path)
        source = "raw"
        floss_data = None

    # ------------------------------------------------------------------
    # Phase 2: Match every pattern against every string. Identical for both
    # extraction paths — the analysis does not know or care where the
    # strings came from, which is what keeps the two paths comparable.
    # ------------------------------------------------------------------
    suspicious_hits, suspicious_details, severity_counts = _find_suspicious(
        all_strings
    )

    # ------------------------------------------------------------------
    # Phase 3: Score. Per-tier caps first, then a total cap.
    #
    # The tier caps are what stop a single behaviour class from carrying
    # the module: a sample matching eight critical categories scores the
    # same 30 as one matching three, because past three the extra
    # categories are describing the same malware in more words.
    # ------------------------------------------------------------------
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
        # Applied here, before the FLOSS obfuscation bonus below, so a
        # FLOSS-sourced result can finish above this number.
        score_delta = min(score_delta, 40)

        # Build reason — show critical/high categories first.
        # Severity-ordered because the reason string is truncated at five:
        # what survives truncation must be the categories that scored.
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

    # Recorded, not inferred. A reporter must be able to say "static only"
    # rather than render `0 decoded / 0 stack`, which reads as "this sample
    # does not obfuscate its strings" — the opposite of what a downgraded
    # run established. Same defect class as the lnk and onenote size-cap
    # bypasses, where a skip rendered as a finding.
    data["floss_emulation_timed_out"] = emulation_timed_out
    if floss_data is not None:
        data["floss_mode"] = floss_data.get("mode", "static")
        data["floss_static_strings"] = floss_data.get("static_count", 0)
        data["floss_decoded_strings"] = floss_data.get("decoded_count", 0)
        data["floss_stack_strings"] = floss_data.get("stack_count", 0)
        data["floss_tight_strings"] = floss_data.get("tight_count", 0)
        data["floss_language_strings"] = floss_data.get("language_count", 0)

        # Decoded and stack strings are scored on their *existence*, not
        # their content — a binary that builds strings on the stack or
        # decodes them at runtime has paid a real cost to hide them, and
        # that fact is independent of whether any matched a pattern above.
        # Only FLOSS can produce this signal, which is the whole argument
        # for carrying the dependency.
        decoded = floss_data.get("decoded_count", 0)
        stack = floss_data.get("stack_count", 0)
        # Tight strings were computed by _run_floss and read by nothing.
        # FLOSS documents them as "a special form of stack strings, decoded
        # on the stack", so a sample using only tight strings hid them just
        # as thoroughly and earned nothing for it. 45 across the corpus.
        tight = floss_data.get("tight_count", 0)
        if decoded > 0 or stack > 0 or tight > 0:
            score_delta += 10
            parts = []
            if decoded > 0:
                parts.append(f"{decoded} decoded")
            if stack > 0:
                parts.append(f"{stack} stack")
            if tight > 0:
                parts.append(f"{tight} tight")
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
    file_path: Path, floss_path: Path, timeout: int, *, emulation: bool
) -> tuple[dict | None, str]:
    """Invoke FLOSS and parse its JSON output.

    Returns the parsed sections and a failure reason, one of which is
    always empty.

    Args:
        file_path:  The sample. Passed to FLOSS unmodified.
        emulation: When False, run ``--only static``: no emulation, and so
                   no stack, tight or decoded strings. When True, run
                   FLOSS's default, which emulates. Set from the scan
                   profile, never from the file.
        floss_path: Path to the FLOSS binary. Absent on a fresh clone —
                    install.sh downloads it — so that case logs at info.
        timeout:    Wall-clock bound. FLOSS emulates code to recover
                    decoded strings and is by far the slowest thing in a
                    standard scan, so this bound is load-bearing.

    Returns:
        ``(result, failure)``. On success the parsed sections and ``""``;
        on failure ``None`` and one of ``missing`` / ``timeout`` /
        ``oserror`` / ``exit`` / ``badjson``.

        The reason is returned rather than collapsed into a bare ``None``
        because the caller's response differs by cause. Only a *timeout*
        is worth retrying without emulation, and only a timeout may be
        described to the analyst as one — reporting a crashed emulator as
        "timed out" says the budget was too small when the run never got
        that far, and reporting an absent binary that way invents a
        300-second wait that never happened.
    """
    if not floss_path.is_file():
        logger.info("FLOSS binary not found at %s", floss_path)
        return None, "missing"

    # `--only static` is the entire cost control. Measured over the 30 PE
    # samples in the corpus: static extraction is flat at ~1s regardless of
    # file size, while the default (which emulates the binary under
    # vivisect to recover stack, tight and decoded strings) ranged from
    # 0.7s to 271.1s on those same files — 30.0 minutes against 69 seconds
    # for the corpus, 26x.
    #
    # Size is NOT the predictor and must not be used as one: AdwareTechsnab
    # at 16.6 MB emulates in 10.3s while Amadey3 at 0.6 MB takes 170.8s.
    # Cost tracks the number of candidate decoding functions. The timeout
    # is the only honest control, which is why there is no size gate here.
    cmd = [str(floss_path)]
    if not emulation:
        cmd += ["--only", "static"]
    cmd += ["--json", str(file_path)]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("FLOSS timed out after %ds (%s mode)", timeout,
                       "full" if emulation else "static")
        return None, "timeout"
    except OSError as exc:
        logger.warning("FLOSS invocation failed: %s", exc)
        return None, "oserror"

    # Unlike capa, a non-zero FLOSS exit is treated as total failure: FLOSS
    # writes its JSON document as a whole at the end of a successful run, so
    # a failed run has no partial output worth salvaging.
    if proc.returncode != 0:
        stderr_snippet = proc.stderr[:500].decode("utf-8", errors="replace") if proc.stderr else ""
        logger.warning(
            "FLOSS exited with code %d: %s",
            proc.returncode,
            stderr_snippet,
        )
        return None, "exit"

    try:
        floss_json = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Failed to parse FLOSS JSON output: %s", exc)
        return None, "badjson"

    # Extract strings from FLOSS JSON structure.
    # FLOSS v2+ JSON has: strings.static_strings, strings.decoded_strings,
    # strings.stack_strings, strings.tight_strings
    #
    # All four are concatenated for analysis but counted separately, because
    # the counts are themselves the obfuscation signal scored in run().
    # A missing section degrades to an empty list rather than a KeyError —
    # FLOSS omits sections it could not compute for a given file type.
    strings_section = floss_json.get("strings", {})

    static = _extract_floss_strings(strings_section.get("static_strings", []))
    decoded = _extract_floss_strings(strings_section.get("decoded_strings", []))
    stack = _extract_floss_strings(strings_section.get("stack_strings", []))
    tight = _extract_floss_strings(strings_section.get("tight_strings", []))

    # FLOSS 3.x emits this for Go, Rust and .NET binaries, and emits it
    # even under `--only static` — verified, not assumed: LummaStealer.exe
    # returned 1487 language strings in 1.3s with emulation disabled.
    #
    # Read because discarding a section FLOSS produces is arbitrary, not
    # because it detects: across the three Go samples where these matched
    # anything, they matched only categories the raw extractor had already
    # found, and gained a category on none of them.
    language = _extract_floss_strings(strings_section.get("language_strings", []))

    all_strings = static + decoded + stack + tight + language

    return {
        "strings": all_strings,
        "mode": "full" if emulation else "static",
        "static_count": len(static),
        "decoded_count": len(decoded),
        "stack_count": len(stack),
        "tight_count": len(tight),
        "language_count": len(language),
    }, ""


def _extract_floss_strings(entries: list) -> list[str]:
    """Extract plain string values from FLOSS JSON string entries.

    FLOSS entries can be either plain strings or dicts with a "string" key.

    Args:
        entries: One section of the FLOSS JSON document.

    Returns:
        Plain string values. Both shapes are accepted because the sections
        differ: static strings carry an offset and encoding alongside the
        text, while stack strings are emitted bare in some versions.
        ``value`` is checked as a fallback key for the same reason.
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

    Args:
        file_path: File to read, bounded by _MAX_RAW_EXTRACT_SIZE.

    Returns:
        Deduplicated strings, ASCII runs first then UTF-16LE. Empty on any
        read failure, which run() reports as a successful scan finding no
        strings.
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

    # Scanned as a separate pass rather than by decoding the file as
    # UTF-16: a PE interleaves narrow and wide strings, so no whole-file
    # decode is right for both. The decode guard is needed here and not in
    # the ASCII pass because a matched byte pair can still form a lone
    # surrogate.
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

    Args:
        strings: Every extracted string, from either extraction path.

    Returns:
        (categories_set, match_details_list, severity_counts_by_level)
        where severity_counts holds the number of distinct *categories* at
        each level, not the number of matching strings — that distinction
        is what keeps a repeated string from inflating the score.

    Every pattern is tried against every string even after one matches, so
    a single line mentioning both a RAT name and an injection API records
    both categories.
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
                # Examples are capped at three per category. They exist to
                # show the analyst *what* matched — the fourth example of
                # the same category adds nothing but report length, and the
                # cap also bounds this inner recount to a trivial size.
                cat_count = sum(1 for d in details if d["category"] == category)
                if cat_count < 3:
                    # Truncate very long strings.
                    display = s if len(s) <= 120 else s[:117] + "..."
                    details.append({
                        "category": category,
                        "severity": severity,
                        "string": display,
                    })

    # seen_severity is keyed by category, so its size is the number of
    # distinct categories and this loop counts categories per level — the
    # unit the scoring in run() expects.
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

    Args:
        categories: The category names that fired.

    Returns:
        Category names sorted by (severity rank, name). The name is the
        tie-break so the reason string is stable across runs — a set has no
        order, and an unstable reason would churn the golden snapshots.

    The severity is re-derived rather than threaded through from
    _find_suspicious() so this stays usable from the reporters, which have
    only the category list. First entry wins where a category appears at
    two severities in the table.
    """
    sev_lookup: dict[str, str] = {}
    for _, cat, sev in _SUSPICIOUS_PATTERNS:
        if cat not in sev_lookup:
            sev_lookup[cat] = sev
    return sorted(
        categories,
        key=lambda c: (_SEVERITY_RANK.get(sev_lookup.get(c, "low"), 9), c),
    )
