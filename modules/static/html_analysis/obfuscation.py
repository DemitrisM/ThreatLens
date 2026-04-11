"""JavaScript obfuscation detection — Pass 4.

Detects: eval(), new Function(), String.fromCharCode(), unescape(),
hex/unicode escape encoding, split-string obfuscation, junk-comment
camouflage (AI-generated compound-word noise, as seen in ClickFix samples),
and obfuscated variable names.

All checks are pure-regex on the already-extracted script blocks.
No external dependencies.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Strip large base64/encoded string literals before analysing script text.
# This prevents false positives from base64 PE data matching comment or
# identifier patterns (e.g. `//8AALgA…` inside a base64 string triggers
# the `//` comment regex; long runs of `A`s trigger the identifier regex).
_LARGE_STRING_RE = re.compile(
    r"""["'`][A-Za-z0-9+/=\r\n\t ]{200,}["'`]""",
    re.DOTALL,
)

# ── Per-indicator patterns ────────────────────────────────────────────────────

_OBF_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("has_eval",
     re.compile(r"\beval\s*\("),
     "eval() call"),
    ("has_fromcharcode",
     re.compile(r"\bString\s*\.\s*fromCharCode\s*\(", re.I),
     "String.fromCharCode() assembly"),
    ("has_unescape",
     re.compile(r"\bunescape\s*\("),
     "unescape() call"),
    ("has_function_constructor",
     re.compile(r"\bnew\s+Function\s*\("),
     "new Function() constructor (eval proxy)"),
    ("has_hex_escapes",
     re.compile(r"\\x[0-9a-fA-F]{2}"),
     "hex escape sequences (\\xNN)"),
    ("has_unicode_escapes",
     re.compile(r"\\u[0-9a-fA-F]{4}"),
     "unicode escape sequences (\\uNNNN)"),
    ("has_split_string",
     re.compile(r"""["']\s*\+\s*["']"""),
     "split-string concatenation obfuscation"),
]

# ── Junk-comment detection ────────────────────────────────────────────────────
# Comments with an unusually high proportion of very long lowercase words are
# likely AI-generated camouflage (the ClickFix technique).
_COMMENT_RE = re.compile(r"//[^\n]{60,}|/\*[\s\S]{100,}?\*/")
_LONG_WORD_RE = re.compile(r"\b[a-zA-Z]{15,}\b")
_JUNK_RATIO_THRESHOLD = 0.28  # 28 % of comment tokens are abnormally long

# ── Obfuscated variable-name detection ───────────────────────────────────────
# Long names with 4+ camelCase transitions look programmatically generated.
_LONG_IDENT_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]{29,})\b")
_MIN_OBFUSCATED_VARS = 3


def detect_obfuscation(script_blocks: list[str]) -> dict:
    """Return obfuscation flags and a human-readable indicator list.

    Args:
        script_blocks: list of inline ``<script>`` block text strings.

    Returns a flat dict suitable for merging into the module data dict.
    """
    if not script_blocks:
        return _empty_result()

    combined = "\n".join(script_blocks)
    # Clean copy with large string literals replaced — used for comment and
    # identifier analysis to avoid false positives from embedded base64 data.
    clean = _LARGE_STRING_RE.sub('""', combined)

    results: dict = {}
    triggered: list[str] = []

    for key, pattern, label in _OBF_PATTERNS:
        hit = bool(pattern.search(combined))
        results[key] = hit
        if hit:
            triggered.append(label)

    junk = _detect_junk_comments(clean)
    results["has_junk_comments"] = junk
    if junk:
        triggered.append("Junk-comment camouflage (AI-generated obfuscation noise)")

    obf_vars = _detect_obfuscated_varnames(clean)
    results["has_obfuscated_varnames"] = obf_vars
    if obf_vars:
        triggered.append("Obfuscated / programmatically-generated variable names")

    results["obfuscation_indicators"] = triggered
    return results


def _detect_junk_comments(clean_js: str) -> bool:
    """Return True when comment blocks contain an implausibly high ratio
    of very-long words — the hallmark of ClickFix-style junk camouflage.

    ``clean_js`` should have large string literals already stripped so that
    base64 data does not match the comment pattern.
    """
    # Only keep comment captures that contain spaces (real text has word gaps;
    # any remaining encoded data would still be space-free).
    comments = [c for c in _COMMENT_RE.findall(clean_js) if c.count(" ") >= 3]
    if not comments:
        return False
    combined = " ".join(comments)
    tokens = combined.split()
    if len(tokens) < 8:
        return False
    long_tokens = _LONG_WORD_RE.findall(combined)
    return (len(long_tokens) / len(tokens)) >= _JUNK_RATIO_THRESHOLD


def _detect_obfuscated_varnames(clean_js: str) -> bool:
    """Return True when multiple very long, programmatically-generated
    identifiers appear in the script content.

    Detects both camelCase (4+ transitions) and snake_case (2+ long parts)
    obfuscation styles, as used in ClickFix-style attacks.

    ``clean_js`` should have large string literals already stripped.
    """
    candidates = _LONG_IDENT_RE.findall(clean_js)
    suspicious = [n for n in candidates if _looks_obfuscated(n)]
    return len(suspicious) >= _MIN_OBFUSCATED_VARS


def _looks_obfuscated(name: str) -> bool:
    """Heuristic: does a variable name look programmatically generated?"""
    if len(name) < 30:
        return False
    # CamelCase obfuscation: many lower→upper transitions.
    camel = sum(
        1 for i in range(1, len(name))
        if name[i - 1].islower() and name[i].isupper()
    )
    if camel >= 4:
        return True
    # Snake_case obfuscation: multiple underscore-separated long segments
    # (e.g. `quadapplicationor_ultramicroserviceer`).
    if "_" in name:
        long_parts = [p for p in name.split("_") if len(p) >= 8]
        return len(long_parts) >= 2
    return False


def _empty_result() -> dict:
    return {
        "has_eval": False,
        "has_fromcharcode": False,
        "has_unescape": False,
        "has_function_constructor": False,
        "has_hex_escapes": False,
        "has_unicode_escapes": False,
        "has_split_string": False,
        "has_junk_comments": False,
        "has_obfuscated_varnames": False,
        "obfuscation_indicators": [],
    }
