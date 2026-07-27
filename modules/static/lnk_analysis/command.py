"""Target resolution and command-line analysis.

Two jobs. First, decide what the shortcut actually *runs*: a LNK carries
up to four candidate target paths, and their disagreement is itself a
signal — an EnvironmentVariableDataBlock path that overrides the IDList
while ``PreferEnvironmentPath`` is set is the classic target spoof.

Second, characterise the command line. The pattern lists are ported from
``bartblaze/Yara-rules`` ``LNK_Ruleset.yar`` (MIT) and LOLBAS, and are
kept local to this module — the same convention ``html_analysis``
(``clickfix.py``) and ``string_analysis`` already follow.

The padding analysis deserves its own note. **ZDI-CAN-25373 /
CVE-2025-9491** pads COMMAND_LINE_ARGUMENTS with whitespace so the
malicious portion falls past what Explorer's Properties dialog renders.
ZDI found ~1,000 samples across 11 state-sponsored groups, in the wild
for roughly eight years; Microsoft classified it low severity and
declined to patch. It is invisible to a signature and trivial to detect
statically, which makes it the highest-value check in this module.

Note what is deliberately *not* validated: the widely-repeated 4096-char
argument limit has no primary Microsoft source and is probably a
shell/dialog limit rather than a format one. The format ceiling is the
uint16 ``CountCharacters`` field, 65,535, and the spec explicitly exempts
COMMAND_LINE_ARGUMENTS from its own 260-character rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import deobfuscate

#: What Explorer's Properties dialog actually shows of the arguments.
VISIBLE_ARG_LIMIT = 260

#: Anomalous argument length. Well below the 65,535 format ceiling and
#: well above anything a real shortcut carries.
LONG_ARG_THRESHOLD = 1024

#: Whitespace used for padding. The last three are non-printing control
#: characters that render as nothing — their presence is never innocent.
PADDING_CHARS = frozenset(" \t\n\v\f\r\x11\x12\x13")
_EXOTIC_PADDING = frozenset("\v\f\x11\x12\x13")

#: Living-off-the-land binaries. Unit 42 measured powershell.exe and
#: cmd.exe at >80% of malicious LNK targets between them.
LOLBINS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "wscript.exe", "cscript.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe",
    "forfiles.exe", "conhost.exe", "curl.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "explorer.exe", "ftp.exe", "hh.exe",
    "ieexec.exe", "pcalua.exe", "scriptrunner.exe", "cmstp.exe",
    "control.exe", "odbcconf.exe", "dfsvc.exe", "presentationhost.exe",
    "xwizard.exe", "wt.exe", "winrs.exe", "mavinject.exe",
    # LOLBAS entries that are not .exe. Signed Microsoft scripts shipped in
    # System32 are as good an execution primitive as any binary, and a
    # shortcut targeting one is never legitimate — DonutLoader points at
    # winrm.cmd for exactly this reason.
    "winrm.cmd", "winrm.vbs", "pubprn.vbs", "slmgr.vbs", "manage-bde.wsf",
    "syncappvpublishingserver.vbs", "cl_mutexverifiers.ps1",
    "cl_invocation.ps1", "pester.bat", "checknetisolation.exe",
})

#: Directories a legitimate system-binary shortcut never points into.
_USER_WRITABLE = (
    "\\temp\\", "\\appdata\\", "\\downloads\\", "\\public\\",
    "\\programdata\\", "\\users\\public\\", "%temp%", "%appdata%",
    "%public%", "%programdata%",
)

#: Icon sources that make a shortcut look like a document. Paired with a
#: LOLBin target this is MITRE T1027.012 territory.
_DOCUMENT_ICONS = (
    "imageres.dll", "shell32.dll", "acrord32", "acrobat", "winword",
    "excel", "powerpnt", "notepad.exe", "wordpad.exe", "mspaint",
    "packager.dll", ".pdf", ".doc", ".xls",
)

#: Hosting that shows up in LNK campaigns far out of proportion to its
#: share of legitimate traffic.
_SUSPICIOUS_HOSTS = (
    "workers.dev", "r2.dev", "trycloudflare.com", "pages.dev",
    "blob.core.windows.net", "discordapp.com/attachments",
    "discord.com/attachments", "githubusercontent.com", "xsph.ru",
    "ngrok.io", "ngrok-free.app", "bit.ly", "tinyurl.com", "t.me",
)

# ---------------------------------------------------------------------------
# Patterns
#
# Compiled once at import. No nested quantifiers anywhere: the realistic
# DoS vector in this module is catastrophic backtracking over a 65 KB
# padded argument string, not the binary parse.
# ---------------------------------------------------------------------------

_PATTERNS: tuple[tuple[re.Pattern, str, str], ...] = (
    # PowerShell accepts any unambiguous prefix of a parameter name, so
    # -e, -enc and -encodedcommand are all valid. Matching the literal
    # would miss most real samples.
    (re.compile(r"[-/–—]e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+[A-Za-z0-9+/=]{20,}",
                re.IGNORECASE),
     "encoded_powershell", "Base64-encoded PowerShell command"),
    (re.compile(r"[-/–—]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?\s+h(?:i(?:d(?:d(?:e(?:n)?)?)?)?)?\b",
                re.IGNORECASE),
     "hidden_window", "Hidden window style"),
    (re.compile(r"[-/]no(?:p(?:r(?:o(?:f(?:i(?:l(?:e)?)?)?)?)?)?)?\b", re.IGNORECASE),
     "exec_bypass", "PowerShell profile bypass (-nop)"),
    (re.compile(r"[-/](?:ep|exec(?:utionpolicy)?)\s+bypass\b", re.IGNORECASE),
     "exec_bypass", "ExecutionPolicy bypass"),
    (re.compile(r"[-/]no(?:n(?:i(?:n(?:t(?:e(?:r(?:a(?:c(?:t(?:i(?:v(?:e)?)?)?)?)?)?)?)?)?)?)?)?\b",
                re.IGNORECASE),
     "exec_bypass", "Non-interactive PowerShell"),
    (re.compile(r"\bIEX\b|\bInvoke-Expression\b|\.Invoke\(", re.IGNORECASE),
     "download_cradle", "Invoke-Expression"),
    (re.compile(r"\bDownloadString\b|\bDownloadFile\b|\bDownloadData\b|"
                r"\bNet\.WebClient\b|\bInvoke-WebRequest\b|\biwr\b|"
                r"\bStart-BitsTransfer\b|\bwget\b",
                re.IGNORECASE),
     "download_cradle", "PowerShell download cradle"),
    (re.compile(r"\bcertutil\b[^|;&]{0,80}?(?:-urlcache|-decode|-f\b)", re.IGNORECASE),
     "download_cradle", "certutil download/decode"),
    (re.compile(r"\bbitsadmin\b[^|;&]{0,40}?/transfer\b", re.IGNORECASE),
     "download_cradle", "bitsadmin transfer"),
    (re.compile(r"\bcurl\b[^|;&]{0,80}?[-/]o\b", re.IGNORECASE),
     "download_cradle", "curl download to disk"),
    (re.compile(r"\bmsiexec\b[^|;&]{0,40}?/i\s+https?://", re.IGNORECASE),
     "download_cradle", "msiexec remote install"),
    (re.compile(r"\bregsvr32\b[^|;&]{0,60}?scrobj\.dll", re.IGNORECASE),
     "download_cradle", "regsvr32 scriptlet (Squiblydoo)"),
    (re.compile(r"\brundll32\b[^|;&]{0,40}?(?:javascript:|url\.dll)", re.IGNORECASE),
     "download_cradle", "rundll32 protocol handler abuse"),
    (re.compile(r"\bmshta\b[^|;&]{0,40}?(?:https?://|vbscript:|javascript:)", re.IGNORECASE),
     "download_cradle", "mshta remote/script payload"),
    # Overlay extraction — Unit 42 put find/findstr, mshta and PowerShell
    # at ~95% of all appended-payload cases.
    (re.compile(r"\bfind(?:str)?\b[^|;&]{0,60}?\.lnk\b", re.IGNORECASE),
     "overlay_extraction", "findstr reading the shortcut itself"),
    (re.compile(r"\bSelect-String\b|\bGet-Content\b[^|;&]{0,40}?\$MyInvocation|"
                r"\$MyInvocation\b|\.Substring\(",
                re.IGNORECASE),
     "overlay_extraction", "PowerShell self-read / substring carve"),
    (re.compile(r"\bFromBase64String\b|\[Convert\]::|\[System\.Convert\]::",
                re.IGNORECASE),
     "obfuscation", "Base64 decode in-line"),
    (re.compile(r"-join\b|-bxor\b|\[char\[\]\]|\[Text\.Encoding\]", re.IGNORECASE),
     "obfuscation", "String reassembly / XOR"),
    (re.compile(r"%\w{3,20}:~[-\d]+(?:,[-\d]+)?%"),
     "obfuscation", "cmd character-slice obfuscation"),
    (re.compile(r"%(?:comspec|programdata|appdata|temp|public|userprofile|windir)%",
                re.IGNORECASE),
     "obfuscation", "Environment-variable path indirection"),
    (re.compile(r"\^[a-z]", re.IGNORECASE),
     "obfuscation", "cmd caret escaping"),
    (re.compile(r"`[a-z]", re.IGNORECASE),
     "obfuscation", "PowerShell backtick splitting"),
    # Delayed expansion: `cmd /V:ON` then `pow!x!rsh!x!ll`. The single most
    # distinctive feature of the Formbook and ITA samples, and it defeats
    # every plain keyword match — including our own download-cradle rules.
    (re.compile(r"/V:?\s*ON\b", re.IGNORECASE),
     "obfuscation", "cmd delayed variable expansion enabled (/V:ON)"),
    (re.compile(r"[A-Za-z]![A-Za-z_][A-Za-z0-9_]{0,30}![A-Za-z]"),
     "obfuscation", "Command name split by delayed-expansion variables"),
    (re.compile(r"\bset\s+[A-Za-z_][A-Za-z0-9_]{0,30}=[^&\s]{1,4}\s*&&", re.IGNORECASE),
     "obfuscation", "Single-character variable assignment for name splitting"),
    # Quote insertion inside a command name: `cm""d`, `power""shell`.
    (re.compile(r"[A-Za-z]\"{2,}[A-Za-z]"),
     "obfuscation", "Quote-insertion obfuscation inside a command name"),
    # WebDAV over HTTPS. `\\host@SSL\path` mounts a remote share and runs
    # the payload without ever writing a downloaded file to disk, so none
    # of the download-cradle patterns fire on it.
    (re.compile(r"\\\\[A-Za-z0-9._-]+@SSL\\", re.IGNORECASE),
     "webdav_remote_exec", "WebDAV-over-HTTPS remote path (\\\\host@SSL\\)"),
    (re.compile(r"\\\\[A-Za-z0-9._-]+@[0-9]{2,5}\\", re.IGNORECASE),
     "webdav_remote_exec", "WebDAV remote path on a non-standard port"),
    (re.compile(r"(?:^|[\s&|=\"'^])\\\\[A-Za-z0-9._-]{2,}\\[^\s\"'<>|]+"),
     "unc_in_arguments", "UNC path in the command line"),
    (re.compile(r"\b(?:regsvr32|rundll32|mshta|bitsadmin|certutil|wmic|"
                r"odbcconf|installutil|msiexec|forfiles|conhost)\.exe\b",
                re.IGNORECASE),
     "lolbin_reference", "LOLBin referenced in arguments"),
    (re.compile(r"\.(?:hta|vbs|js|jse|wsf|ps1|bat|cmd|scr|pif)\b", re.IGNORECASE),
     "script_payload", "Script payload extension"),
)

_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>|)]+", re.IGNORECASE)
_UNC_RE = re.compile(r"\\\\[A-Za-z0-9._@-]+\\[^\s\"'<>|)]*")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TRAVERSAL_RE = re.compile(r"\.\.[\\/]")


@dataclass
class PaddingAnalysis:
    """Whitespace-padding measurements for one string."""

    length: int = 0
    max_run: int = 0
    whitespace_ratio: float = 0.0
    exotic_chars: list[str] = field(default_factory=list)
    visible_whitespace_ratio: float = 0.0
    content_beyond_visible: bool = False
    zdi_can_25373: bool = False
    tier: str = "none"


@dataclass
class CommandAnalysis:
    """What the shortcut runs, and what that command line looks like."""

    target: str = ""
    target_source: str = ""
    target_basename: str = ""
    is_lolbin: bool = False
    target_in_user_dir: bool = False
    target_is_remote: bool = False
    target_disagreement: bool = False
    command_line: str = ""
    categories: set[str] = field(default_factory=set)
    matches: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    suspicious_hosts: list[str] = field(default_factory=list)
    deobfuscated_iocs: list[str] = field(default_factory=list)
    deobfuscation_chains: list[str] = field(default_factory=list)
    argument_count: int = 0
    arg_padding: PaddingAnalysis = field(default_factory=PaddingAnalysis)
    path_padding: PaddingAnalysis = field(default_factory=PaddingAnalysis)
    traversal_depth: int = 0
    icon_masquerade: bool = False
    remote_icon: bool = False
    args_smuggled_in_target: bool = False
    double_extension: str = ""


def analyse_padding(text: str) -> PaddingAnalysis:
    """Measure whitespace padding, position-aware.

    The position-aware check is the high-fidelity one: if what Explorer
    renders is essentially blank while real content sits past the visible
    window, that is ZDI-CAN-25373 by definition rather than by heuristic.

    Published thresholds for the cruder checks come from the SigmaHQ rule
    ``proc_creation_win_susp_lnk_exec_hidden_cmd``, which matches on 17
    consecutive spaces or 6 consecutive newlines.
    """
    result = PaddingAnalysis(length=len(text))
    if not text:
        return result

    run = 0
    for char in text:
        if char in PADDING_CHARS:
            run += 1
            if run > result.max_run:
                result.max_run = run
        else:
            run = 0

    padding_total = sum(1 for c in text if c in PADDING_CHARS)
    result.whitespace_ratio = padding_total / len(text)
    result.exotic_chars = sorted({f"0x{ord(c):02X}" for c in text if c in _EXOTIC_PADDING})

    visible = text[:VISIBLE_ARG_LIMIT]
    visible_padding = sum(1 for c in visible if c in PADDING_CHARS)
    result.visible_whitespace_ratio = visible_padding / len(visible)
    beyond = text[VISIBLE_ARG_LIMIT:]
    result.content_beyond_visible = any(c not in PADDING_CHARS for c in beyond)

    result.zdi_can_25373 = (
        len(text) > VISIBLE_ARG_LIMIT
        and result.visible_whitespace_ratio >= 0.95
        and result.content_beyond_visible
    )

    # The whitespace *ratio* only means anything once the string is longer
    # than the visible window. Below that everything is on screen, so a
    # space-heavy argument is untidy rather than evasive — and a short
    # string trivially exceeds any ratio ("  x  " is 80% whitespace).
    ratio_is_meaningful = len(text) > VISIBLE_ARG_LIMIT and result.whitespace_ratio > 0.5

    if result.zdi_can_25373 or result.max_run >= 100 \
            or ratio_is_meaningful or result.exotic_chars:
        result.tier = "strong"
    elif result.max_run >= 20:
        result.tier = "medium"
    elif result.max_run >= 8:
        result.tier = "weak"

    return result


def resolve_target(parsed) -> tuple[str, str, bool]:  # noqa: ANN001 — ParsedLnk, circular
    """Pick the effective target path and report source disagreement.

    Priority: LinkInfo full path, then the IDList, then RELATIVE_PATH,
    then the EnvironmentVariableDataBlock. Disagreement matters more than
    the winner: an environment path that differs from the IDList while
    ``PreferEnvironmentPath`` is set means the thing Explorer displays is
    not the thing that runs.
    """
    candidates: list[tuple[str, str]] = []
    if parsed.link_info and parsed.link_info.full_path:
        candidates.append(("link_info", parsed.link_info.full_path))
    if parsed.idlist_target:
        candidates.append(("idlist", parsed.idlist_target))
    if parsed.relative_path:
        candidates.append(("relative_path", parsed.relative_path))
    if parsed.env_target:
        candidates.append(("environment_block", parsed.env_target))

    if not candidates:
        return "", "", False

    source, target = candidates[0]

    # PreferEnvironmentPath makes the environment block authoritative.
    if parsed.header.has("PreferEnvironmentPath") and parsed.env_target:
        source, target = "environment_block", parsed.env_target

    basenames = {_basename(value).lower() for _, value in candidates if value}
    disagreement = len(basenames) > 1

    return target, source, disagreement


def _basename(path: str) -> str:
    cleaned = path.rstrip("\\/ ").replace("/", "\\")
    return cleaned.rsplit("\\", 1)[-1] if "\\" in cleaned else cleaned


def analyse(parsed, file_name: str = "") -> CommandAnalysis:  # noqa: ANN001
    """Full command-line characterisation for one parsed shortcut.

    ``file_name`` is the shortcut's own filename when known. It is the
    single best source for the double-extension check — ``Invoice.pdf.lnk``
    is what the victim sees in Explorer, and it appears in no field
    inside the file itself.
    """
    out = CommandAnalysis()

    out.target, out.target_source, out.target_disagreement = resolve_target(parsed)
    out.target_basename = _basename(out.target)
    out.is_lolbin = out.target_basename.lower() in LOLBINS

    target_lower = out.target.lower()
    out.target_in_user_dir = any(marker in target_lower for marker in _USER_WRITABLE)
    out.target_is_remote = target_lower.startswith("\\\\") or \
        target_lower.startswith("http://") or target_lower.startswith("https://")

    arguments = parsed.arguments or ""
    out.command_line = f"{out.target} {arguments}".strip()
    out.argument_count = len(arguments.split())

    out.arg_padding = analyse_padding(arguments)
    out.path_padding = analyse_padding(parsed.relative_path or "")

    for pattern, category, label in _PATTERNS:
        if pattern.search(out.command_line):
            out.categories.add(category)
            out.matches.append(label)

    out.urls = _extract_urls(out.command_line, parsed)

    # Hosts written without a scheme — `iex(irm 'noventis8.com' -useb)`
    # carries no http://, so a scheme-anchored regex walks past the C2.
    for host in deobfuscate.bare_hosts(out.command_line):
        if host not in out.urls:
            out.urls.append(host)

    # Then the same again through every reversible transform the dropper
    # applied, so a reversed or base64'd C2 still reaches the report.
    out.deobfuscated_iocs, out.deobfuscation_chains = deobfuscate.recover_iocs(
        out.command_line
    )
    for ioc in out.deobfuscated_iocs:
        if ioc not in out.urls:
            out.urls.append(ioc)
    if out.deobfuscation_chains:
        # Flags the score; the reporters render the chains and recovered
        # indicators in their own rows, so adding a `matches` entry here
        # would print the same finding twice.
        out.categories.add("obfuscation")

    lowered_urls = " ".join(out.urls).lower()
    out.suspicious_hosts = [h for h in _SUSPICIOUS_HOSTS if h in lowered_urls]

    out.traversal_depth = len(_TRAVERSAL_RE.findall(parsed.relative_path or ""))

    out.icon_masquerade = _is_icon_masquerade(parsed, out)
    out.remote_icon = _is_remote_icon(parsed)

    # Arguments hidden in the target field instead of the arguments field —
    # the original ZDI-CAN-25373 shape, and it defeats any check that only
    # ever looks at COMMAND_LINE_ARGUMENTS.
    if not parsed.header.has("HasArguments") and out.target:
        if re.search(r"\s[-/](?:c|k|enc|e)\b", out.target, re.IGNORECASE):
            out.args_smuggled_in_target = True

    out.double_extension = _double_extension(parsed, file_name)

    return out


def _extract_urls(command_line: str, parsed) -> list[str]:  # noqa: ANN001
    """URLs, UNC paths and bare IPs from the command line and icon fields."""
    haystack = " ".join(filter(None, (
        command_line, parsed.icon_location, parsed.icon_env_target,
        parsed.env_target,
    )))
    found: list[str] = []
    found.extend(_URL_RE.findall(haystack))
    found.extend(_UNC_RE.findall(haystack))
    for candidate in _IPV4_RE.findall(haystack):
        octets = candidate.split(".")
        if all(o.isdigit() and int(o) < 256 for o in octets) and candidate not in found:
            found.append(candidate)
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    unique: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique[:50]


def _is_icon_masquerade(parsed, out: CommandAnalysis) -> bool:  # noqa: ANN001
    """A document-shaped icon in front of a LOLBin target.

    This is the social-engineering half of MITRE T1027.012 — what the
    victim sees versus what runs.
    """
    if not out.is_lolbin:
        return False
    icon = (parsed.icon_location or parsed.icon_env_target or "").lower()
    if not icon:
        return False
    if _basename(icon) == out.target_basename.lower():
        return False                    # icon comes from the target itself
    return any(marker in icon for marker in _DOCUMENT_ICONS)


def _is_remote_icon(parsed) -> bool:  # noqa: ANN001
    """An icon Windows fetches over the network when it renders the shortcut.

    Both a payload-download primitive and an NTLM coercion primitive: a
    UNC icon path makes the victim's machine authenticate to the attacker.
    """
    for value in (parsed.icon_location, parsed.icon_env_target):
        lowered = (value or "").lower()
        if lowered.startswith("\\\\") or lowered.startswith("http://") \
                or lowered.startswith("https://"):
            return True
    return False


#: Extensions that make a name *look* like a harmless document.
_DOC_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
    "rtf", "jpg", "jpeg", "png", "gif", "csv", "one", "eml", "msg",
})

#: Extensions that actually execute. The deception only exists when a
#: document extension is immediately followed by one of these.
_EXEC_EXTENSIONS = frozenset({
    "lnk", "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse",
    "vbs", "vbe", "wsf", "wsh", "hta", "msi", "ps1", "jar",
})


def _double_extension(parsed, file_name: str = "") -> str:  # noqa: ANN001
    """``Invoice.pdf.lnk`` — the name claims a document, the file executes.

    Requires the document extension to sit *immediately* before an
    executable one. A looser "contains a document extension somewhere"
    test flags ordinary names like ``report.pdf.backup`` or
    ``notes.txt.old``, which are neither deceptive nor rare.
    """
    candidates = (file_name, parsed.name_string, parsed.relative_path)
    for value in candidates:
        name = _basename(value or "").lower()
        parts = name.split(".")
        if len(parts) < 3:
            continue
        # Walk adjacent extension pairs, not just the final two: an
        # attacker can pad with more suffixes (Invoice.pdf.lnk.txt).
        for first, second in zip(parts[1:-1], parts[2:]):
            if first in _DOC_EXTENSIONS and second in _EXEC_EXTENSIONS:
                return name
    return ""
