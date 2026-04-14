"""Weighted combo scoring engine for Office document indicators.

Earlier versions of this module summed each check's independent score
contribution with a 60-point cap. That rewards co-firing indicators
linearly when reality cares about *combinations* — AutoExec alone is
boring; AutoExec plus a Shell call is unambiguously malicious.

Each rule below is ``(required_flag_set, weight)``. For every rule
whose required flag set is a subset of the detected flags, we add the
weight. Multiple non-overlapping rules can fire together (e.g., VBA
stomping + Equation Editor OLE → 8 + 5), but duplicate signals inside
one rule do not double-count because sets are unordered.

Thresholds (per the brief):

* weight ≥ 7  → MALICIOUS
* 4 – 6        → SUSPICIOUS
* 1 – 3        → INFORMATIONAL
* 0           → CLEAN

The final ``score_delta`` is ``min(total, 60)`` so doc_analysis does
not dominate the 100-point aggregate until the end-of-project
calibration sweep revisits the weights.
"""

from __future__ import annotations

SCORE_CAP = 60

# Ordered from highest to lowest weight for deterministic reason ordering.
COMBO_RULES: list[tuple[frozenset[str], int, str]] = [
    (frozenset({"auto_exec", "shell_keyword"}), 10,
     "AutoExec + Shell call — macro launches an OS command on open"),
    (frozenset({"auto_exec", "url_downloader_keyword"}), 9,
     "AutoExec + URLDownloadToFile/XMLHTTP — drops remote payload on open"),
    (frozenset({"auto_exec", "ole_package_exec_ext"}), 9,
     "AutoExec + embedded executable in OLE Package"),
    (frozenset({"vba_stomping"}), 8,
     "VBA stomping detected (source/p-code divergence)"),
    (frozenset({"xlm_exec_call"}), 7,
     "XLM macro uses EXEC/CALL/FORMULA.FILL"),
    (frozenset({"template_inject_non_ms"}), 7,
     "Template injection to non-Microsoft URL"),
    (frozenset({"template_inject_high"}), 6,
     "External attachedTemplate / oleObject / frame / subDocument"),
    (frozenset({"altchunk"}), 6,
     "altChunk relationship (template-injection vector)"),
    (frozenset({"heavy_vba_obfuscation"}), 6,
     "Heavy VBA obfuscation (Chr/hex arithmetic)"),
    (frozenset({"equation_editor_ole"}), 5,
     "Embedded Equation Editor OLE (CVE-2017-11882 / CVE-2018-0802 candidate)"),
    (frozenset({"ole_package_exec_ext"}), 5,
     "OLE Package embeds executable file"),
    (frozenset({"rtf_objupdate"}), 4,
     "RTF uses \\objupdate — forces object load on open"),
    (frozenset({"dangerous_embedded_file"}), 4,
     "Dangerous file extension inside OOXML container"),
    (frozenset({"vba_present"}), 3,
     "VBA macros present"),
    (frozenset({"xlm_url"}), 3,
     "XLM deobfuscated cells contain HTTP URL"),
    (frozenset({"oleid_high_risk"}), 3,
     "oleid reported HIGH-risk indicator"),
    (frozenset({"ole_object_in_container"}), 2,
     "Embedded OLE object stream"),
    (frozenset({"encryption_only"}), 2,
     "Password-protected document with no macros (evasion pattern)"),
    (frozenset({"decompression_bomb"}), 2,
     "Decompression-bomb guard tripped on container"),
    (frozenset({"malformed_openxml"}), 1,
     "OpenXML container failed clean parse"),
    (frozenset({"rtf_parse_failed"}), 1,
     "RTF failed to parse cleanly (possible exploit attempt)"),
]


def score_document(indicator_flags: set[str]) -> tuple[int, list[str], str]:
    """Compute the document's score contribution.

    Args:
        indicator_flags: set of flag strings emitted by each check.

    Returns:
        ``(score_delta, reasons, classification)`` where ``classification``
        is one of ``MALICIOUS`` / ``SUSPICIOUS`` / ``INFORMATIONAL`` / ``CLEAN``.
    """
    total = 0
    reasons: list[str] = []

    for required, weight, reason in COMBO_RULES:
        if required.issubset(indicator_flags):
            total += weight
            reasons.append(f"{reason} (+{weight})")

    if total >= 7:
        classification = "MALICIOUS"
    elif total >= 4:
        classification = "SUSPICIOUS"
    elif total >= 1:
        classification = "INFORMATIONAL"
    else:
        classification = "CLEAN"

    return min(total, SCORE_CAP), reasons, classification
