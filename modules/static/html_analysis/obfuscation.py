"""JavaScript obfuscation detection — Pass 4.

Detects: eval(), new Function(), String.fromCharCode(), unescape(),
hex/unicode escape encoding, split-string obfuscation, junk-comment
camouflage (AI-generated compound-word noise, as seen in ClickFix samples),
and obfuscated variable names.

All checks are pure-regex on the already-extracted script blocks.
No external dependencies.

Design notes
------------
Two views of the same script text are kept, and using the wrong one is
the mistake this module already made once. ``combined`` is the raw
source, matched by the API patterns — an ``eval(`` inside a string
literal still counts, because the literal is usually what gets eval'd.
``clean`` has large string literals blanked and is matched by the
comment and identifier heuristics, which are statistical and would
otherwise be reading base64: a run of ``A``s satisfies the long-
identifier pattern, and ``//8AALgA`` inside a PE blob satisfies the
line-comment pattern.

Everything here is an *indicator of obfuscation*, never of intent.
Minified production JavaScript trips several of these on its own, which
is why each is a small weight and the module leans on combinations —
and why the junk-comment and identifier checks carry thresholds rather
than firing on a single occurrence.

The junk-comment check is the one genuinely novel heuristic: ClickFix
pages pad their scripts with AI-generated prose full of implausibly long
compound words, which reads as English to a human skimming and is
statistically obvious in aggregate.
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
        script_blocks: Inline ``<script>`` block text strings.

    Returns:
        A flat dict suitable for merging into the module data dict. An
        empty input returns the same keys with everything false, because
        the reporters index them unconditionally.

    The API patterns run against the raw text and the two statistical
    checks against the string-blanked copy — see the module docstring
    for why that split is load-bearing rather than tidiness.
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
    """True when comments carry an implausible ratio of very long words.

    Args:
        clean_js: Script text with large string literals already blanked,
                  so base64 data cannot match the comment pattern.

    Returns:
        Whether the comment text looks like generated camouflage.

    Three guards, each removing a different way to be wrong. Only
    comments containing at least three spaces are kept, because real
    prose has word gaps and any encoded data that survived blanking does
    not. Fewer than eight tokens is not enough text to measure a ratio
    against. And the ratio itself is over tokens rather than characters,
    so one enormous word cannot carry the result.
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
    """True when several implausibly long identifiers appear together.

    Args:
        clean_js: Script text with large string literals already blanked.

    Returns:
        Whether at least ``_MIN_OBFUSCATED_VARS`` such names were found.

    Counted, not matched once. A single 30-character camelCase name is a
    style choice someone might genuinely make; three of them in one file
    is a generator. The threshold is what separates the two, and it is
    why this returns a bool over a population rather than a list of
    names.
    """
    candidates = _LONG_IDENT_RE.findall(clean_js)
    suspicious = [n for n in candidates if _looks_obfuscated(n)]
    return len(suspicious) >= _MIN_OBFUSCATED_VARS


def _looks_obfuscated(name: str) -> bool:
    """Heuristic: does one identifier look programmatically generated?

    Args:
        name: A candidate identifier, already length-filtered by the
              regex that found it.

    Returns:
        Whether it matches either generated style.

    Two styles, because the generators observed in the wild use two.
    Many lower-to-upper transitions is the camelCase form; several long
    underscore-separated segments is the snake_case form, as in
    ``quadapplicationor_ultramicroserviceer``. Both tests are about
    *structure* rather than length alone — a long name that is one word
    is a description, not a generated token.
    """
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
    """Every key this module emits, all negative.

    Returns:
        The full result shape for a page with no inline script.

    Built in one place and always in full so the reporters and the
    scoring engine can index any key without guarding it — the same
    contract the analysis modules' ``_empty_data`` helpers follow.
    """
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
