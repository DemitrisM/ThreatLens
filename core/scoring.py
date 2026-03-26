"""Confidence scoring engine.

Sums score_delta values from all module results, clamps the total to
0-100, assigns a risk band (LOW / MEDIUM / HIGH / CRITICAL), and
formats a human-readable score breakdown.
"""

import logging

logger = logging.getLogger(__name__)

# Risk band thresholds (inclusive lower bound).
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

        if delta != 0:
            breakdown.append(
                {
                    "module": result.get("module", "unknown"),
                    "score_delta": delta,
                    "reason": result.get("reason", ""),
                }
            )

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
    """Clamp *value* to [lo, hi] and return as int."""
    return int(max(lo, min(hi, value)))


def _risk_band(score: int) -> str:
    """Map a 0-100 score to its risk band label."""
    for threshold, label in _BANDS:
        if score >= threshold:
            return label
    return "LOW"
