"""Weighted combo scoring engine for archive_analysis.

Mirrors ``modules.static.doc_analysis.scoring``: each rule is a
frozenset of indicator flags + a weight + a human-readable reason. A
rule fires when its required flag set is a subset of the detected
flags. Multiple non-overlapping rules can co-fire (e.g.,
``zip_header_mismatch`` + ``embedded_pe`` + ``dangerous_member``).

Bands (final score after capping):

* ``≥ 7`` → MALICIOUS
* ``4 – 6`` → SUSPICIOUS
* ``1 – 3`` → INFORMATIONAL
* ``0`` → CLEAN

Cap is 60 so archive_analysis can't single-handedly dominate the
100-point aggregate before the end-of-project calibration sweep.
"""

from __future__ import annotations

SCORE_CAP = 60


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

    Returns ``(score_delta, reason, fired_rules, classification)``.

    * ``score_delta`` — capped at ``SCORE_CAP``
    * ``reason``      — semicolon-joined human-readable summary
    * ``fired_rules`` — list of reason strings (one per rule that fired)
    * ``classification`` — MALICIOUS / SUSPICIOUS / INFORMATIONAL / CLEAN
    """
    total = 0
    fired: list[str] = []

    for required, weight, reason in COMBO_RULES:
        if required.issubset(flags):
            total += weight
            fired.append(f"{reason} (+{weight})")

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
