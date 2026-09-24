"""Weighted combo scoring engine for onenote_analysis.

Mirrors :mod:`modules.static.archive_analysis.scoring` exactly — same
``(frozenset, weight, reason)`` triples, same cap, same four-band
classification. Weights are provisional and will be calibrated against
the full corpus at end of project.

Design notes
------------
Rules stack on subset containment, so a combo and the single-flag rules
inside it all fire: an embedded LNK alongside a script is worth 30 for
the pair *plus* 15 and 15 for each on its own. Each combo weight is an
escalation on top of its parts, which is why reweighting one rule in
isolation does not do what it appears to.

That top rule is the reason the module exists, and it was unreachable
until 0.5.8 — `_LNK_SIGNATURE` in ``embedded.py`` carried one wrong
byte, so ``contains_embedded_lnk`` could never be raised. A rule is only
as real as the flag that feeds it.

Classification bands, taken from the **uncapped** total:

* ``≥ 25`` → MALICIOUS
* ``10 – 24`` → SUSPICIOUS
* ``1 – 9`` → INFORMATIONAL
* ``0`` → CLEAN

The cap bounds what the pipeline adds, never the verdict word the report
prints: the top band is 25 and the cap is 60, so capping cannot talk a
MALICIOUS file down. Letting it would be a scoring artefact hiding a
detection.
"""

from __future__ import annotations

SCORE_CAP = 60


COMBO_RULES: list[tuple[frozenset[str], int, str]] = [
    (frozenset({"contains_embedded_lnk", "contains_embedded_script"}), 30,
     "LNK + script chain — classic IcedID / Qakbot OneNote TTP"),
    (frozenset({"contains_embedded_pe"}), 25,
     "OneNote carries an embedded PE executable"),
    (frozenset({"contains_embedded_hta"}), 25,
     "OneNote carries an embedded HTA dropper"),
    (frozenset({"contains_embedded_msi"}), 22,
     "OneNote carries an embedded MSI installer"),
    (frozenset({"contains_embedded_chm"}), 20,
     "OneNote carries an embedded CHM"),
    (frozenset({"contains_embedded_lnk"}), 15,
     "OneNote carries an embedded Windows shortcut"),
    (frozenset({"contains_embedded_script"}), 15,
     "OneNote carries an embedded script"),
    (frozenset({"multiple_dangerous_blobs"}), 10,
     "Multiple dangerous payloads stacked in one OneNote file"),
    (frozenset({"encrypted_section"}), 8,
     "OneNote contains an encrypted section — content hidden from static triage"),
    (frozenset({"large_embedded_payload"}), 5,
     "Embedded payload exceeds 100 KiB"),
    (frozenset({"blob_count_anomaly"}), 5,
     "Unusual number of FileDataStoreObjects (stacked payloads)"),
]


def score_onenote(
    flags: frozenset[str],
) -> tuple[int, str, list[str], str]:
    """Compute the module's score contribution.

    Args:
        flags: Every indicator flag raised for this file. A superset is
               normal — the caller does not filter by which rules exist.

    Returns:
        ``(score_delta, reason, fired_rules, classification)``, where the
        delta is capped and the classification is not. Both views are
        returned because they answer different questions: the pipeline
        needs a bounded contribution to sum, the report needs the verdict
        the evidence supports.
    """
    total = 0
    fired: list[str] = []

    for required, weight, reason in COMBO_RULES:
        if required.issubset(flags):
            total += weight
            fired.append(f"{reason} (+{weight})")

    if total >= 25:
        classification = "MALICIOUS"
    elif total >= 10:
        classification = "SUSPICIOUS"
    elif total >= 1:
        classification = "INFORMATIONAL"
    else:
        classification = "CLEAN"

    capped = min(total, SCORE_CAP)
    reason_text = "; ".join(fired) if fired else "No OneNote indicators fired"
    return capped, reason_text, fired, classification
