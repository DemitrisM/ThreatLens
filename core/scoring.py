"""Confidence scoring engine.

Sums score_delta values from all module results, clamps the total to
0-100, assigns a risk band (LOW / MEDIUM / HIGH / CRITICAL), and
formats a human-readable score breakdown.

Design notes
------------
The clamp happens **once, after the sum**, never per module. Clamping each
module's contribution first would let a single 100-point module hide every
other signal, and would make the arithmetic in the report's breakdown table
fail to add up to the total the user is shown.

This module is deliberately the only place that knows the band thresholds.
Reporters ask for the band; they never re-derive it from the number.
"""

import logging

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Risk band thresholds, as (inclusive lower bound, label) pairs.
#
# Ordered highest-first because _risk_band() returns on the first match,
# which makes the list a cheap ordered lookup instead of a range ladder.
# Reordering these entries silently changes every verdict the tool emits.
# ----------------------------------------------------------------------
_BANDS = [
    (76, "CRITICAL"),
    (56, "HIGH"),
    (31, "MEDIUM"),
    (0, "LOW"),
]


def compute_score(module_results: list[dict]) -> dict:
    """Aggregate module score_deltas into a final threat assessment.

    Args:
        module_results: List of standard module result dicts, each
                        containing at least ``score_delta`` (int) and
                        ``reason`` (str).

    Returns:
        A dict with keys:
            total_score  — clamped 0-100 int
            risk_band    — "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            breakdown    — list of {"module", "score_delta", "reason"} dicts
                           (only modules with non-zero deltas)
    """
    breakdown: list[dict] = []
    raw_total = 0

    # ------------------------------------------------------------------
    # Step 1: Accumulate every module's contribution.
    #
    # A module that returns a non-numeric score_delta is logged and
    # skipped rather than raised on: design rule 2 says one malformed
    # module must never take down a scan that eleven others completed.
    # ------------------------------------------------------------------
    for result in module_results:
        delta = result.get("score_delta", 0)
        if not isinstance(delta, (int, float)):
            logger.warning(
                "Module %s returned non-numeric score_delta %r — treating as 0",
                result.get("module", "unknown"),
                delta,
            )
            continue

        raw_total += delta

        # Zero-delta modules are excluded from the breakdown so the report
        # lists only what actually moved the number. file_intake always
        # scores 0, and a table full of "+0" rows buries the real findings.
        if delta != 0:
            breakdown.append(
                {
                    "module": result.get("module", "unknown"),
                    "score_delta": delta,
                    "reason": result.get("reason", ""),
                }
            )

    # ------------------------------------------------------------------
    # Step 2: Clamp once on the raw sum, then band the clamped value.
    #
    # raw_total is kept for the log line: when a sample scores 100 it is
    # useful to know whether the uncapped sum was 101 or 340.
    # ------------------------------------------------------------------
    total_score = _clamp(raw_total, 0, 100)
    risk_band = _risk_band(total_score)

    # ------------------------------------------------------------------
    # Step 2a: a module's own MALICIOUS verdict floors the band.
    #
    # Four modules publish a classification of their own, and the
    # aggregate used to contradict it: archive_analysis caps at +60 but
    # real archives top out near +18, while MEDIUM begins at 31 — so no
    # archive finding of any severity could reach MEDIUM alone, and a
    # working CVE-2025-8088 exploit dropping into the Startup folder
    # banded LOW four lines above its own module calling it MALICIOUS.
    #
    # Measured on the development splits before this was written
    # (docs/measurement_m2_post_fix.md): flooring on MALICIOUS promotes
    # 76 of 144 missed malicious files — 41.5% to 72.4% — and 0 of 279
    # verified-clean controls.
    #
    # SUSPICIOUS deliberately does NOT floor the band. Also measured:
    # it would promote 14 further malicious files AND two benign
    # Microsoft shortcuts, which is the promotion the first
    # false-positive measurement vetoed this whole change over.
    #
    # Only LOW is raised, and only to MEDIUM. One module's certainty is
    # grounds to look, not grounds to call a file critical, and a floor
    # that could lower a band would not be a floor.
    # ------------------------------------------------------------------
    band_floor = None
    if risk_band == "LOW":
        flagged = _modules_reporting_malicious(module_results)
        if flagged:
            band_floor = {"modules": flagged, "raised_from": risk_band}
            risk_band = "MEDIUM"

    logger.info(
        "Scoring complete — %d / 100  [%s]  (raw sum: %d, %d contributors)",
        total_score,
        risk_band,
        raw_total,
        len(breakdown),
    )

    return {
        "total_score": total_score,
        "risk_band": risk_band,
        "breakdown": breakdown,
        # Absent rather than None when nothing was floored, so a
        # consumer can test presence instead of truthiness.
        **({"band_floor": band_floor} if band_floor else {}),
    }


def _clamp(value: int | float, lo: int, hi: int) -> int:
    """Clamp *value* to [lo, hi] and return as int.

    Args:
        value: The number to constrain. Accepts float because a nested
               archive's damped score_delta (x0.5 / x0.25 / x0.125) is
               fractional before it reaches here.
        lo:    Inclusive lower bound.
        hi:    Inclusive upper bound.

    Returns:
        The bounded value, truncated to int.
    """
    return int(max(lo, min(hi, value)))


def _modules_reporting_malicious(module_results: list[dict]) -> list[str]:
    """Name every module whose own classification is MALICIOUS.

    Args:
        module_results: Standard module result dicts.

    Returns:
        Module names in execution order, empty when none applies. ALL
        of them, not the first: an archive carrying a malicious document
        has two modules objecting, and naming one would drop the other
        from the report's explanation of its own band.

    Only ``success`` results are read. A module that errored can leave a
    stale ``data`` behind from a partial run, and a classification from
    a run that failed is not a finding.

    ``data`` is read with ``.get`` through an isinstance check rather
    than subscripted. Most modules publish no classification at all —
    ``file_intake`` runs first on every scan and never does — so a
    direct subscript would raise on the first one and take down a scan
    that twelve other modules had completed, which design rule 2
    forbids.
    """
    flagged: list[str] = []
    for result in module_results:
        if not isinstance(result, dict) or result.get("status") != "success":
            continue
        data = result.get("data")
        if not isinstance(data, dict):
            continue
        if data.get("classification") == "MALICIOUS":
            name = result.get("module")
            if name and name not in flagged:
                flagged.append(name)
    return flagged


def _risk_band(score: int) -> str:
    """Map a 0-100 score to its risk band label.

    Args:
        score: An already-clamped 0-100 score.

    Returns:
        One of "CRITICAL", "HIGH", "MEDIUM", "LOW".
    """
    # _BANDS is highest-first, so the first satisfied threshold is the
    # correct band. The trailing return is unreachable for a clamped
    # score (the final entry's threshold is 0) and exists only to keep
    # the function total if a caller ever passes a negative number.
    for threshold, label in _BANDS:
        if score >= threshold:
            return label
    return "LOW"
