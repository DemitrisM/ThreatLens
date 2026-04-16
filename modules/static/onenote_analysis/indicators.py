"""Translate typed blobs + parser metadata into a flag set.

Keeps ``scoring.py`` pure — it only ever sees a ``frozenset[str]``.
"""

from __future__ import annotations

from .embedded import DANGEROUS_KINDS, EmbeddedBlob

_LARGE_PAYLOAD_BYTES = 100 * 1024
_BLOB_COUNT_ANOMALY = 20


def derive_flags(
    blobs: list[EmbeddedBlob],
    *,
    has_encrypted_section: bool,
) -> frozenset[str]:
    """Return indicator flags for the scoring engine."""
    flags: set[str] = set()

    kind_to_flag = {
        "pe": "contains_embedded_pe",
        "elf": "contains_embedded_pe",
        "macho": "contains_embedded_pe",
        "msi": "contains_embedded_msi",
        "lnk": "contains_embedded_lnk",
        "hta": "contains_embedded_hta",
        "script": "contains_embedded_script",
        "chm": "contains_embedded_chm",
    }

    dangerous_count = 0
    for b in blobs:
        flag = kind_to_flag.get(b.kind)
        if flag:
            flags.add(flag)
        if b.kind in DANGEROUS_KINDS:
            dangerous_count += 1
            if b.size > _LARGE_PAYLOAD_BYTES:
                flags.add("large_embedded_payload")

    if dangerous_count >= 2:
        flags.add("multiple_dangerous_blobs")

    if len(blobs) > _BLOB_COUNT_ANOMALY:
        flags.add("blob_count_anomaly")

    if has_encrypted_section:
        flags.add("encrypted_section")

    return frozenset(flags)
