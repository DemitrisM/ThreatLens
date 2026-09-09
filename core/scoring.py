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
