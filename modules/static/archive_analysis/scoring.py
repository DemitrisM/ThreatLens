"""Weighted combo scoring engine for archive_analysis.

Mirrors ``modules.static.doc_analysis.scoring``: each rule is a
frozenset of indicator flags + a weight + a human-readable reason. A
rule fires when its required flag set is a subset of the detected
flags. Multiple non-overlapping rules can co-fire (e.g.,
``zip_header_mismatch`` + ``embedded_pe`` + ``dangerous_member``).

Bands, taken from the **uncapped** total (see Design notes):

* ``≥ 7`` → MALICIOUS
* ``4 – 6`` → SUSPICIOUS
* ``1 – 3`` → INFORMATIONAL
* ``0`` → CLEAN

Cap is 60 so archive_analysis can't single-handedly dominate the
100-point aggregate before the end-of-project calibration sweep.

Design notes
------------
**Rules are not mutually exclusive, and the overlap is deliberate.** A
rule fires on subset containment, so a combo rule and the single-flag
rules it contains all fire together: ``dangerous_member`` alone is worth
3, and ``{embedded_pe, dangerous_member}`` is worth a further 5, so that
pair scores 8 rather than 5. Each combo weight is therefore an
*escalation* on top of its parts, not a replacement for them. Reweighting
one rule in isolation will not do what it looks like it does.

**Classification is decided before the cap, the delta after it.** The
band thresholds top out at 7 while the weights sum to 118, so the cap can
only ever change the number the pipeline adds — never the verdict word
the report prints. That asymmetry is intentional: the cap exists to bound
this module's share of the 100-point aggregate, and letting it also
suppress a MALICIOUS classification would be a scoring artefact masking a
detection.

**Two vocabularies meet here.** The classification returned by this
module is not the pipeline's LOW/MEDIUM/HIGH/CRITICAL band; the pipeline
derives its own from the summed 0–100 score. A green LOW banner above a
red MALICIOUS classification is that known mismatch, recorded in
CLAUDE.md, not a bug in this file.

The bands are low because these weights are small and additive by design
— two or three ordinary indicators should reach SUSPICIOUS, since an
archive is a container and a single suspicious member is exactly what one
looks like.
"""

from __future__ import annotations

SCORE_CAP = 60


# Roughly descending by weight. Nothing in the engine depends on the
# order — every rule is tested against the flag set regardless — but
# `fired_rules` is emitted in this order and becomes the report's reason
# string, so the heavier findings lead the sentence an analyst reads.
# "Roughly" is literal: `shadowed_member_unrecoverable` (5) sits below
# the 4-weight rules because it belongs beside the duplicate-name rule
# it escalates, and reading the pair together matters more here than a
# strict sort.

# Note the pairs that stack. `shadowed_member_unrecoverable` never
# occurs without `duplicate_member_name` — the orchestrator raises the
# first only after raising the second — so a shadowed member is worth
# 3 + 5 = 8, which reaches MALICIOUS on its own. That is the intended
# weight for bytes an analyst provably cannot recover.
COMBO_RULES: list[tuple[frozenset[str], int, str]] = [
    (frozenset({"zip_header_mismatch"}), 10,
     "ZIP LFH/CD mismatch — AV evasion"),
    (frozenset({"sfx_dropper"}), 10,
     "PE with archive payload in overlay"),
    (frozenset({"path_traversal"}), 9,
     "Path traversal (ZipSlip / CVE-2025-8088 class)"),
    (frozenset({"symlink_attack"}), 9,
     "Symlink attack"),
    (frozenset({"rtlo_filename"}), 8,
     "RTLO/bidi-override filename"),
    (frozenset({"header_encrypted"}), 6,
     "Header-encrypted archive"),
    (frozenset({"null_byte_filename"}), 6,
     "Null byte in filename"),
    (frozenset({"autorun_inf"}), 6,
     "Root-level autorun.inf"),
    (frozenset({"embedded_pe", "dangerous_member"}), 5,
     "Embedded executable + risky extension"),
    (frozenset({"persistence_path", "dangerous_member"}), 5,
     "Startup-folder drop"),
    (frozenset({"double_extension"}), 5,
     "Double-extension trick (photo.jpg.exe)"),
    (frozenset({"mime_mismatch"}), 5,
     "Declared-type / magic-type mismatch"),
    (frozenset({"is_encrypted", "dangerous_member"}), 4,
     "Password-protected with dangerous name"),
    (frozenset({"bomb_guard"}), 4,
     "Decompression-bomb indicators"),
    (frozenset({"ace_detected"}), 4,
     "ACE archive (CVE-2018-20250 risk)"),
    (frozenset({"shadowed_member_unrecoverable"}), 5,
     "Member hidden behind a duplicate name — bytes unrecoverable"),
    (frozenset({"duplicate_member_name"}), 3,
     "Duplicate member name — one record shadows another"),
    (frozenset({"comment_ioc"}), 3,
     "IOC in archive comment"),
    (frozenset({"high_entropy_filename", "dangerous_member"}), 3,
     "High-entropy name + risky ext"),
    (frozenset({"dangerous_member"}), 3,
     "Dangerous extension inside archive"),
    (frozenset({"is_encrypted"}), 2,
     "Password-protected archive"),
    (frozenset({"timestamp_anomaly"}), 1,
     "Bulk-packed timestamps"),
    (frozenset({"desktop_ini"}), 1,
     "desktop.ini at root"),
    (frozenset({"nested_archive"}), 1,
     "Nested archive layer"),
]


def score_archive(
    flags: set[str],
) -> tuple[int, str, list[str], str]:
    """Compute the archive's score contribution.

    Args:
        flags: Every indicator flag raised for this container, already
               merged across its nested children by the orchestrator.
               Passing a superset is normal — the caller does not filter
               by which rules exist.

    Returns:
        ``(score_delta, reason, fired_rules, classification)``.

        * ``score_delta``     — capped at ``SCORE_CAP``
        * ``reason``          — semicolon-joined human-readable summary
        * ``fired_rules``     — one reason string per rule that fired
        * ``classification``  — MALICIOUS / SUSPICIOUS / INFORMATIONAL /
          CLEAN, derived from the **uncapped** total

    Both the capped and uncapped views are returned because they answer
    different questions: the pipeline needs a bounded contribution to
    sum, while the report needs the verdict the evidence actually
    supports.
    """
    # ---- Accumulate every rule whose flags are all present -----------
    # Subset containment, not equality, so a combo rule and the
    # single-flag rules inside it stack. See the module docstring: that
    # is what makes each combo weight an escalation on top of its parts.
    total = 0
    fired: list[str] = []

    for required, weight, reason in COMBO_RULES:
        if required.issubset(flags):
            total += weight
            fired.append(f"{reason} (+{weight})")

    # ---- Band before cap --------------------------------------------
    # Deliberately reads `total`, not `capped`. The cap bounds this
    # module's share of the aggregate; it must not be able to talk a
    # MALICIOUS archive down to SUSPICIOUS.
    if total >= 7:
        classification = "MALICIOUS"
    elif total >= 4:
        classification = "SUSPICIOUS"
    elif total >= 1:
        classification = "INFORMATIONAL"
    else:
        classification = "CLEAN"

    capped = min(total, SCORE_CAP)
    reason_text = "; ".join(fired) if fired else "No archive indicators fired"
    return capped, reason_text, fired, classification
