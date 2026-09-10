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

Design notes
------------
Two vocabularies meet here, and confusing them is the standing hazard.
The ``classification`` this module returns — MALICIOUS / SUSPICIOUS /
INFORMATIONAL / CLEAN — is computed from the *uncapped combo total* on
the thresholds above, and is entirely separate from the pipeline's
0-100 risk band (LOW / MEDIUM / HIGH / CRITICAL) in ``core/scoring.py``.
A document can therefore be classified MALICIOUS here while the scan
banner reads LOW, because 10 points of a 100-point budget is a low
score however certain this module is. That divergence is a known issue
recorded in CLAUDE.md; unifying the two is a scoring change, not a
display one, and must not be papered over in either reporter.

The rule set is intentionally *layered*, not partitioned. A flag may
appear in several rules — ``ole_package_exec_ext`` scores 5 on its own
and 9 again in combination with ``auto_exec`` — so an embedded
executable that a macro launches on open scores both. That is the
intended reading: the base rule prices the artefact, the combination
prices the delivery mechanism wrapped around it.

Rules are evaluated by subset test, which means a rule can only ever
*add*. There is no way to express "this flag makes that one less
interesting", and the cap is what stands in for that. Any rule added
here must be checked against the ones it will co-fire with, because the
engine will happily award both.

Order is presentational, not semantic: the list runs highest weight
first so the reason strings a truncated report shows are the ones that
carried the score.
"""

from __future__ import annotations

# Bounds this module's contribution to the pipeline's 100-point budget.
# Roughly two strong combinations reach it. Deliberately not a tunable:
# raising it is a calibration decision for the whole corpus, not a
# per-scan preference.
SCORE_CAP = 60

# Ordered from highest to lowest weight for deterministic reason ordering.
#
# Each entry is (required_flags, weight, reason). A rule fires when its
# flag set is a subset of what the passes detected, so a single-flag rule
# is a base price and a multi-flag rule is a combination premium — both
# fire when both match. Weights encode *automation and intent*, not
# severity in the abstract: AutoExec + Shell is 10 because it needs no
# user action beyond opening the file, while an embedded Equation Editor
# object is 5 because it still depends on an unpatched Office install.
#
# Every flag any pass emits must appear in at least one rule here. A flag
# with no rule is a detection that scores nothing, silently — five of them
# accumulated that way before a test pinned the invariant. The three
# class-name flags below (packager_shell, shell_explorer, htmlfile) come
# from ole_objects._HIGH_RISK_CLASS_SUBSTRINGS, so adding an entry there
# means adding a rule here too.
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
    (frozenset({"packager_shell"}), 5,
     "Packager Shell Object embedded — drops and launches a bundled file"),
    (frozenset({"shell_explorer"}), 5,
     "Shell.Explorer / WebBrowser control embedded — loads remote content"),
    (frozenset({"htmlfile"}), 4,
     "htmlfile ActiveX object embedded — script execution primitive"),
    (frozenset({"rtf_objupdate"}), 4,
     "RTF uses \\objupdate — forces object load on open"),
    (frozenset({"dangerous_embedded_file"}), 4,
     "Dangerous file extension inside OOXML container"),
    (frozenset({"altchunk_absolute_path"}), 2,
     "altChunk target is an absolute or UNC path — resolves outside the container"),
    (frozenset({"vba_present"}), 3,
     "VBA macros present"),
    (frozenset({"xlm_url"}), 3,
     "XLM deobfuscated cells contain HTTP URL"),
    (frozenset({"oleid_high_risk"}), 3,
     "oleid reported HIGH-risk indicator"),
    (frozenset({"ole_object_in_container"}), 2,
     "Embedded OLE object stream"),
    (frozenset({"ole_package"}), 2,
     "OLE Package container embeds a file"),
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
        indicator_flags: set of flag strings emitted by each check. A flag
                         the rule set does not mention is silently ignored,
                         which is how a detection can exist and score
                         nothing — worth checking when a pass appears to
                         have no effect.

    Returns:
        ``(score_delta, reasons, classification)`` where ``classification``
        is one of ``MALICIOUS`` / ``SUSPICIOUS`` / ``INFORMATIONAL`` / ``CLEAN``.

    Note the asymmetry between the two returned numbers: ``score_delta`` is
    capped, the classification is derived from the *uncapped* total. A
    document scoring 80 raw is MALICIOUS and contributes 60, and the
    classification does not flatten out at the cap the way the score does.
    """
    total = 0
    reasons: list[str] = []

    for required, weight, reason in COMBO_RULES:
        if required.issubset(indicator_flags):
            total += weight
            reasons.append(f"{reason} (+{weight})")

    # Thresholds are this module's own, and are not the pipeline's risk
    # bands — see the module docstring. Evaluated against the uncapped
    # total on purpose.
    if total >= 7:
        classification = "MALICIOUS"
    elif total >= 4:
        classification = "SUSPICIOUS"
    elif total >= 1:
        classification = "INFORMATIONAL"
    else:
        classification = "CLEAN"

    return min(total, SCORE_CAP), reasons, classification
