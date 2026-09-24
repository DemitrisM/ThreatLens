"""Translate typed blobs + parser metadata into a flag set.

Keeps ``scoring.py`` pure — it only ever sees a ``frozenset[str]``.

Design notes
------------
The flag vocabulary is coarser than the kind vocabulary, deliberately.
``pe``, ``elf`` and ``macho`` all raise ``contains_embedded_pe``: the
finding is "a OneNote page carries a native executable", and which
platform it targets does not change what the analyst does next. The
blob's real kind survives in the report, so nothing is lost — only the
scoring is simplified.

Everything here reads the typed blobs and nothing else. It cannot see
the file, so a kind this module has no flag for is invisible to scoring
however dangerous it is — which is exactly what happened when the LNK
signature was wrong: the blobs were there, typed as ``other``, and no
flag could be raised. A missing kind is a silent gap rather than a
visible one, which is why ``embedded.py`` is where the care belongs.

Thresholds are inline constants rather than config. They are shape
judgements about the format — twenty attachments on one page is a
stacking pattern, not a preference — and the calibration sweep is where
they move.
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
    """Return indicator flags for the scoring engine.

    Args:
        blobs:                 Typed FileDataStoreObject payloads.
        has_encrypted_section: Whether the parser saw an encryption
                               marker anywhere in the file.

    Returns:
        A frozenset of flag names. Frozen because ``scoring.py`` tests
        subset containment against it and must not be able to mutate the
        caller's evidence.

    ``large_embedded_payload`` is raised only for blobs that are already
    dangerous. A 4 MiB image on a OneNote page is a screenshot; the size
    only means something once the thing being sized is a payload.

    ``multiple_dangerous_blobs`` counts blobs rather than distinct kinds,
    so two scripts count as two. Stacking several droppers in one
    notebook is the observed pattern, and requiring them to differ would
    miss the commonest form of it.
    """
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
