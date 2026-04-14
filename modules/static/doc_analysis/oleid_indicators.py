"""High-level OLE indicators via ``oletools.oleid``.

oleid surfaces container-level risk flags (encryption, digital
signatures, declared document type vs. actual content, macro presence
summary, external relationship summary). We capture all of them in
``data["oleid_indicators"]`` so the reporter can render the full list,
and pull out a small number of HIGH-severity flags to contribute
scoring signals.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from oletools.oleid import OleID
    _HAS_OLEID = True
except ImportError:
    _HAS_OLEID = False


def analyse_oleid(file_path: Path) -> dict:
    out: dict = {"indicators": [], "encryption_only": False,
                 "indicator_flags": set()}
    if not _HAS_OLEID:
        return out
    try:
        oid = OleID(str(file_path))
        indicators = oid.check()
    except Exception as exc:  # noqa: BLE001
        logger.debug("oleid failed: %s", exc)
        return out

    encrypted = False
    has_macros = False
    for indicator in indicators:
        row = {
            "id": getattr(indicator, "id", ""),
            "name": getattr(indicator, "name", ""),
            "value": str(getattr(indicator, "value", "")),
            "risk": str(getattr(indicator, "risk", "")),
        }
        out["indicators"].append(row)
        if row["risk"].upper() == "HIGH":
            out["indicator_flags"].add("oleid_high_risk")
        if row["id"] == "encrypted" and row["value"].lower() in ("true", "1"):
            encrypted = True
        if row["id"] in ("vba", "vba_macros") and row["value"].lower() in ("true", "1"):
            has_macros = True

    # "Encryption only" — file is password-protected and has no macros.
    # This is a common evasion pattern; contribute a small score.
    if encrypted and not has_macros:
        out["encryption_only"] = True
        out["indicator_flags"].add("encryption_only")

    return out
