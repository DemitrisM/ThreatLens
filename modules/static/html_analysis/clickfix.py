"""ClickFix and clipboard-poisoning detection — Pass 5.

Detects ``navigator.clipboard.writeText()``, ``document.execCommand('copy')``,
extracts the clipboard payload text, flags LOLBins within it, and scans the
visible HTML body for social-engineering lure patterns typical of ClickFix /
fake-verification / fake-CAPTCHA pages.

No external dependencies.

Design notes
------------
ClickFix inverts the usual delivery problem. Nothing is downloaded and
nothing executes in the browser — the page copies a command to the
clipboard and persuades the victim to paste it into Win+R themselves.
So there is no payload to carve and no exploit to match; the evidence is
a clipboard write plus text that talks the user into running it.

That is why the lure patterns are matched against the **rendered HTML**
while the clipboard mechanism is matched against **script blocks**. The
two halves live in different parts of the document and neither is
sufficient alone: a clipboard write is ordinary on a page with a "copy"
button, and verification language is ordinary on a real CAPTCHA page.

Scoring treats them as a combination for that reason. Pattern labels are
returned rather than counts, because "which lure" is what tells an
analyst whether they are looking at a fake CAPTCHA or a fake browser
update.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Living-off-the-land binaries that are dangerous inside a clipboard payload.
_LOLBINS: frozenset[str] = frozenset({
    "powershell", "pwsh",
    "mshta",
    "cmd.exe", "cmd /c", "cmd/c",
    "wscript", "cscript",
    "rundll32", "regsvr32",
    "msiexec",
    "certutil",
    "bitsadmin",
    "msbuild", "installutil",
    "regasm", "regsvcs",
    "wmic",
    "odbcconf",
    "cmstp",
})

# Social-engineering lure patterns checked against the full HTML text.
_SOCIAL_ENG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"press\s+windows\s*\+\s*r|win\s*\+\s*r|winkey.*\+\s*r", re.I),
     "Win+R key instruction"),
    (re.compile(r"paste\s+(?:it|the|this|command|code)|ctrl\s*\+\s*v|press\s+ctrl.*v", re.I),
     "Paste instruction (Ctrl+V)"),
    (re.compile(
        r"i\s+am\s+not\s+a\s+robot|i'm\s+not\s+a\s+robot|not\s+a\s+robot"
        r"|human\s+verif|verify\s+(?:you\s+are|you'?re)\s+human",
        re.I),
     "Anti-robot / human-verification lure"),
    (re.compile(
        r"your\s+browser\s+is\s+(?:out\s+of\s+date|outdated|not\s+supported)"
        r"|update\s+(?:your\s+)?browser\s+to",
        re.I),
     "Fake browser-update lure"),
    (re.compile(r"click\s+allow|allow\s+notifications|enable\s+(?:content|macros|notifications)", re.I),
     "Enable-content / notification-abuse lure"),
    (re.compile(r"captcha\s+(?:failed|error|required)|complete\s+(?:the\s+)?captcha", re.I),
     "Fake CAPTCHA"),
    (re.compile(r"not\s+compatible\s+with\s+your\s+browser|open\s+in\s+(?:a\s+)?browser|aprilo\s+nel\s+browser", re.I),
     "Browser-compatibility social engineering"),
    (re.compile(r"copy\s+(?:the\s+)?(?:command|code|this)\s+(?:and|then)?\s*(?:run|paste|open)", re.I),
     "Copy-and-run instruction"),
    (re.compile(r"(?:run|open|execute)\s+(?:the\s+)?(?:command|code|script)\s+(?:below|above|here)", re.I),
     "Run-script instruction"),
]

# Regex to extract the argument to clipboard.writeText().
# Handles both short inline strings and multi-line concatenated strings.
_WRITETEXT_RE = re.compile(
    r"""navigator\s*\.\s*clipboard\s*\.\s*writeText\s*\(\s*(?P<q>["'`])(?P<content>.*?)(?P=q)""",
    re.DOTALL,
)
_EXEC_COPY_RE = re.compile(r"""document\s*\.\s*execCommand\s*\(\s*['"]copy['"]\s*\)""", re.I)
# Clipboard assignment via a variable: detect the variable value when writeText is called with a var.
_CLIPBOARD_VAR_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+(\w+)\s*=\s*(?P<q>["'`])(?P<content>[^"'`]{20,})(?P=q)""",
    re.DOTALL,
)


def detect_clickfix(html_text: str, script_blocks: list[str]) -> dict:
    """Detect ClickFix / clipboard-poisoning indicators.

    Args:
        html_text:     The full page text, for the social-engineering
                       lures — they live in rendered content, not script.
        script_blocks: Inline script bodies, for the clipboard mechanism.

    Returns:
        A flat dict suitable for merging into the module data dict.

    Only the first ``writeText`` call is captured. A page doing this
    twice is not a different finding, and the payload preview exists to
    show an analyst the command, not to enumerate every copy button.

    ``execCommand('copy')`` sets the mechanism flag without yielding a
    payload: it copies the current selection rather than a literal, so
    there is no string in the source to extract. The flag still matters
    — it is the older API and the one a page uses when the command is
    rendered into the DOM instead of held in a variable.
    """
    combined = "\n".join(script_blocks)

    # ── Clipboard write detection ──────────────────────────────────────────
    clipboard_payload = ""
    has_clipboard_write = False

    m = _WRITETEXT_RE.search(combined)
    if m:
        has_clipboard_write = True
        clipboard_payload = m.group("content")

    # Fallback: detect execCommand('copy') pattern.
    has_exec_copy = bool(_EXEC_COPY_RE.search(combined))
    if has_exec_copy:
        has_clipboard_write = True

    # Substring matching, on the payload only. The clipboard text is a
    # command line the victim is about to run, so a LOLBin name appearing
    # anywhere in it is the finding — there is no surrounding syntax to
    # parse and no legitimate reason for one to be there. Matching the
    # whole page instead would fire on any article mentioning PowerShell.
    # ── LOLBin detection in payload ────────────────────────────────────────
    lolbins_found: list[str] = []
    if clipboard_payload:
        lower_payload = clipboard_payload.lower()
        for lolbin in _LOLBINS:
            if lolbin in lower_payload:
                lolbins_found.append(lolbin)

    # ── Social engineering lure text ───────────────────────────────────────
    social_eng_hits: list[str] = []
    for pattern, label in _SOCIAL_ENG_PATTERNS:
        if pattern.search(html_text):
            social_eng_hits.append(label)

    return {
        "has_clipboard_write": has_clipboard_write,
        "has_exec_copy": has_exec_copy,
        "clipboard_payload_preview": clipboard_payload[:300] if clipboard_payload else "",
        "clipboard_contains_lolbin": bool(lolbins_found),
        "clipboard_lolbins_found": lolbins_found,
        "social_eng_patterns": social_eng_hits,
    }
