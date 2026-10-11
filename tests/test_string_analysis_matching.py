"""Pattern matching and example selection in ``_find_suspicious``.

Both behaviours pinned here were found by rendering a real report rather
than by reading the code, which is why they survived the module's own
test file: the FLOSS tests exercise extraction, and nothing had looked at
what the matcher does with what extraction returns.

Design notes
------------
The example list is what the analyst reads; the category *set* is what
scores. ``low`` severity contributes zero points (``run()`` sets
``low_score = 0``), so a false positive in a low-tier category is a
report-quality defect and never a scoring one. That asymmetry is why the
``DES`` test below asserts on the match list and not on ``score_delta``.
"""

from modules.static import string_analysis as sa


# ---------------------------------------------------------------------
# Locale false positive: `DES` against the French/Spanish article "des"
#
# `\b` cannot help when the false positive IS a whole word. Found on the
# first benign file anyone scanned — Wine's notepad.exe, whose localised
# UI resources made three of five reported strings this one pattern.
# ---------------------------------------------------------------------

_LOCALE_PROSE = [
    "Ce fichier contient des caracteres",
    "une des alternatives Unicode dans la liste",
    "Des&hacer\tCtrl+Z",
    "Guarda des archivos",
    "Ouvrir des fichiers recents",
]


def test_localised_prose_does_not_report_a_crypto_reference():
    """"des" is an ordinary French/Spanish word, not a cipher name."""
    categories, details, _ = sa._find_suspicious(_LOCALE_PROSE)

    assert "Crypto algorithm reference" not in categories
    assert [d for d in details if d["category"] == "Crypto algorithm reference"] == []


def test_uppercase_cipher_names_still_match():
    """The real artefacts spell the acronym in capitals, and must still fire."""
    for s in ("CryptEncrypt DES key", "AES-256-CBC", "RC4 keystream",
              "RSA public blob", "XOR decode loop"):
        categories, _, _ = sa._find_suspicious([s])
        assert "Crypto algorithm reference" in categories, s


def test_lowercase_ciphers_other_than_des_keep_their_recall():
    """Case-insensitivity is retained where case genuinely varies.

    Go package paths, .NET constructor calls and script operators all
    spell these in lower or mixed case, and `/` and `.` are word
    boundaries, so the bare token is what the pattern sees. Dropping
    IGNORECASE from the whole group to fix `DES` would have silently cost
    every case below.

    `xor key` rather than `xor eax` on purpose: the latter is the x86
    register-zeroing mnemonic and would be a false positive if a binary
    happened to carry the literal text, so it is no argument for recall.
    Raised in review.

    Measured while writing this: a longer PascalCase identifier such as
    `RsaCryptoServiceProvider` never matched at all, with or without
    IGNORECASE, because there is no word boundary inside it. So the recall
    at stake is narrower than it first appears — it is the bare token, not
    .NET naming in general.
    """
    for s in ("crypto/aes", "crypto/rc4", "Aes.Create()", "xor key"):
        categories, _, _ = sa._find_suspicious([s])
        assert "Crypto algorithm reference" in categories, s


def test_the_powershell_bxor_operator_is_not_matched_and_never_was():
    """A gap this fix neither opened nor closed, pinned so it is not misread.

    `-bxor` is PowerShell's bitwise XOR, and the pattern does not see it:
    `\\b` needs a word/non-word transition, and in `-bxor` both `b` and `x`
    are word characters, so there is no boundary before `xor`. Case has
    nothing to do with it — this was equally true before the split.

    An earlier draft of the test above asserted
    `"$b = $a -bxor 0x41; xor eax"` as a passing case and looked like
    evidence that `-bxor` matched. It passed on the `xor eax` at the end of
    the same string. Raised in review.
    """
    categories, _, _ = sa._find_suspicious(["$b = $a -bxor 0x41"])
    assert "Crypto algorithm reference" not in categories


def test_a_low_severity_category_alone_scores_nothing(tmp_path):
    """Recorded so the next reader does not assume this fix moves verdicts.

    ``low`` categories are worth zero points, so the only cost of the
    false positive was wasted rows in the one table an analyst reads most
    closely — no band moved and no verdict changed.

    Asserted through ``run()`` rather than against the tier table, because
    the weights are applied inline there and a test that re-stated them
    would pass whatever they said. ``floss_binary`` points at a path that
    does not exist so the deterministic raw extractor is used.

    An earlier draft of this test asserted a string search against the
    module docstring, short-circuited with ``or True``, and so asserted
    nothing at all. Raised in review.
    """
    sample = tmp_path / "lowonly.bin"
    sample.write_bytes(b"\x00" * 64 + b"CryptEncrypt DES key\x00" + b"\x00" * 64)

    result = sa.run(sample, {"floss_binary": str(tmp_path / "nope")})

    assert result["status"] == "success"
    assert "Crypto algorithm reference" in result["data"]["suspicious_categories"]
    assert [m["severity"] for m in result["data"]["suspicious_matches"]] == ["low"]
    assert result["score_delta"] == 0


# ---------------------------------------------------------------------
# Duplicate examples: the per-category cap spent its slots on repeats
#
# The raw extractor deduplicates its own output, but FLOSS sections are
# concatenated without deduplication, so one string present in both the
# static and decoded sections arrives twice and was recorded twice.
# ---------------------------------------------------------------------

def test_the_same_string_is_not_recorded_twice_for_one_category():
    """A repeated string inflates the apparent weight of the evidence."""
    _, details, _ = sa._find_suspicious(["NtGlobalFlag", "NtGlobalFlag"])

    rows = [d["string"] for d in details
            if d["category"] == "Anti-debug API reference"]
    assert rows == ["NtGlobalFlag"]


def test_the_example_cap_holds_three_distinct_strings_not_three_repeats():
    """The cap exists to bound report length, not to be spent on repeats.

    Before the dedupe, two copies of the first match left room for only
    one of the genuinely different indicators behind it.
    """
    strings = ["NtGlobalFlag", "NtGlobalFlag", "NtGlobalFlag",
               "CheckRemoteDebuggerPresent", "IsDebuggerPresent"]
    _, details, _ = sa._find_suspicious(strings)

    rows = [d["string"] for d in details
            if d["category"] == "Anti-debug API reference"]
    assert len(rows) == len(set(rows))
    assert "CheckRemoteDebuggerPresent" in rows


def test_distinct_strings_in_one_category_are_still_capped_at_three():
    """The cap itself is unchanged — only what counts toward it is."""
    strings = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
               "NtGlobalFlag", "OutputDebugString"]
    _, details, _ = sa._find_suspicious(strings)

    rows = [d for d in details if d["category"] == "Anti-debug API reference"]
    assert len(rows) == 3


def test_one_string_matching_two_categories_is_recorded_under_both():
    """Deduplication is per (category, string), not per string.

    A single line can be evidence for two different things, and removing
    it from the second category would lose a finding.
    """
    _, details, _ = sa._find_suspicious(["powershell -enc IsDebuggerPresent"])

    cats = {d["category"] for d in details}
    assert cats == {"Anti-debug API reference", "PowerShell evasion flag"}
