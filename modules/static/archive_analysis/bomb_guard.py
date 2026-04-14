"""Decompression-bomb guard.

Evaluated **before** any extraction call on an archive. If any of the
three thresholds trips we set ``triggered=True`` and the orchestrator
aborts extraction — metadata-only analysis continues.
"""

from __future__ import annotations

from .entries import ArchiveEntry


def evaluate_bomb_guard(
    entries: list[ArchiveEntry],
    container_size: int,
    ratio_threshold: float,
    size_threshold_bytes: int,
    count_threshold: int,
) -> dict:
    """Return ``{triggered, reasons, stats}`` for a list of entries."""
    total_uncompressed = sum(e.size_uncompressed for e in entries)
    total_compressed = sum(e.size_compressed for e in entries)
    entry_count = len(entries)
    ratio = (total_uncompressed / total_compressed) if total_compressed > 0 else 0.0

    reasons: list[str] = []

    if ratio > ratio_threshold:
        reasons.append(
            f"BOMB_RATIO: compression ratio {ratio:.1f}:1 "
            f"> {ratio_threshold}:1 threshold"
        )
    if total_uncompressed > size_threshold_bytes:
        reasons.append(
            f"BOMB_SIZE: uncompressed total {total_uncompressed} bytes "
            f"> {size_threshold_bytes} byte threshold"
        )
    if entry_count > count_threshold:
        reasons.append(
            f"BOMB_COUNT: {entry_count} members > {count_threshold} threshold"
        )

    return {
        "triggered": bool(reasons),
        "reasons": reasons,
        "stats": {
            "entry_count": entry_count,
            "total_uncompressed": total_uncompressed,
            "total_compressed": total_compressed,
            "ratio": round(ratio, 2),
            "container_size": container_size,
        },
    }
