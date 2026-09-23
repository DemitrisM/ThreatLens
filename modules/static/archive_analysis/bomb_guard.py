"""Decompression-bomb guard.

Evaluated **before** any extraction call on an archive. If any of the
three thresholds trips we set ``triggered=True`` and the orchestrator
aborts extraction — metadata-only analysis continues.

Design notes
------------
Ordering is the entire point of this module. It reads only the sizes an
archive *declares* in its own index, never the bytes, so it can refuse a
bomb without ever paying to inflate it. Calling it after extraction
would be pointless; calling it after enumeration is only safe because
the enumerators are themselves bounded — a compressed tarball has no
central directory, so walking it to the end to build the entry list is
already decompressing it, which is why `tarball_handler` rejects on
declared size as it iterates rather than calling ``getmembers()``.

The three thresholds cover three different shapes of attack and are
independent by design: a small file that expands enormously (ratio), a
file that expands past what the host can absorb regardless of ratio
(size), and an archive whose damage is member *count* rather than bytes,
which exhausts inodes and directory entries instead of disk.

**The ratio test is silently inert on stored archives.** When nothing is
compressed, ``total_compressed`` can be 0, and rather than divide by
zero the ratio becomes 0.0 — below any sane threshold, so the test
cannot fire. That is deliberate, because an uncompressed archive is not
a decompression bomb by definition, and it is safe because the size and
count tests do not depend on compression at all and still apply.

Both the declared sizes and the member count are attacker-controlled
metadata. That is acceptable *here* — lying about them to get under a
threshold means declaring a small archive, and the enumerator then
refuses to read more than was declared, so the lie costs the attacker
the payload. It is not acceptable everywhere: see the open item in
CLAUDE.md about the OOXML guards trusting the ZIP central directory.

The guard reports rather than raises, so a tripped bomb still produces a
report with its metadata, its indicator flags and a score. Silence would
be the one outcome an analyst cannot act on.
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
    """Decide whether this listing may be extracted.

    Args:
        entries:               Enumerated members. Only their declared
                               sizes are read; nothing is decompressed.
        container_size:        On-disk size of the archive itself.
                               Reported in ``stats`` for context and not
                               used in any threshold test — the ratio is
                               computed from member totals, which is the
                               meaningful comparison for a multi-member
                               container.
        ratio_threshold:       Uncompressed:compressed ratio above which
                               the archive is refused.
        size_threshold_bytes:  Uncompressed total above which the
                               archive is refused. Note this is a
                               per-archive figure: the orchestrator
                               re-reads `max_archive_extracted_size_mb`
                               from config for each archive it descends
                               into and passes the full value, so
                               nothing decrements across a nested tree.
        count_threshold:       Member count above which the archive is
                               refused regardless of size.

    Returns:
        ``{"triggered": bool, "reasons": [str], "stats": {...}}``. Every
        tripped threshold appends its own reason rather than
        short-circuiting on the first, so the report can say which of
        the three shapes was seen — they imply different attacks.
    """
    total_uncompressed = sum(e.size_uncompressed for e in entries)
    total_compressed = sum(e.size_compressed for e in entries)
    entry_count = len(entries)
    # 0.0 rather than a ZeroDivisionError for a fully stored archive.
    # See the module docstring: that value cannot trip the test, which
    # is the correct outcome, and the other two tests still apply.
    ratio = (total_uncompressed / total_compressed) if total_compressed > 0 else 0.0

    # ---- All three thresholds, none short-circuiting ------------------
    # Reasons are phrased with both the observed value and the threshold
    # it broke, because an analyst tuning config.yaml needs the distance
    # between them, not just the verdict.
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
