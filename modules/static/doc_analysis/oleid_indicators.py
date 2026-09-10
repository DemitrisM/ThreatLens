"""High-level OLE indicators via ``oletools.oleid``.

oleid surfaces container-level risk flags (encryption, digital
signatures, declared document type vs. actual content, macro presence
summary, external relationship summary). We capture all of them in
``data["oleid_indicators"]`` so the reporter can render the full list,
and pull out a small number of HIGH-severity flags to contribute
scoring signals.

Design notes
------------
This pass is breadth, where the others are depth. oleid answers a dozen
container-level questions in one call — encrypted? signed? declared type
versus actual content? Flash objects? external relationship count? — and
almost none of them overlap with what olevba, rtfobj or the ZIP walk
look at. It is cheap and it is the only pass that sees the container as
a whole.

Only two things are turned into flags. oleid's own HIGH risk rating is
trusted as a signal in itself, and the encryption-without-macros
combination is called out because it is an evasion pattern rather than a
capability: a password-protected document defeats every static scanner
including this one, and the password arrives in the covering email.

Everything oleid reports is carried into the payload whether or not it
scored, because the full indicator table is genuinely useful to a human
reading the report — the declared-type-versus-content row in particular
often explains a sample at a glance.

Indicator values are read through ``str()`` and compared as text. oleid's
value types are not stable across indicators: some are booleans, some
are counts, and some are prose. Any comparison here must account for
that per indicator, not assume a shared shape.
"""

import logging
from pathlib import Path

from ._quiet import quiet_stdout

logger = logging.getLogger(__name__)

try:
    with quiet_stdout(logger, "oletools.oleid"):
        from oletools.oleid import OleID
    _HAS_OLEID = True
except ImportError:
    _HAS_OLEID = False


def analyse_oleid(file_path: Path) -> dict:
    """Run oletools.oleid and translate its indicators into flags.

    Args:
        file_path: An OLE or OOXML document. RTF is excluded upstream —
                   it has no container for oleid to inspect.

    Returns:
        ``{"indicators": [{id, name, value, risk}], "encryption_only":
        bool, "indicator_flags": set}``. Never raises: a missing library
        or a container oleid cannot open yields the empty skeleton, so a
        scan is never lost to this pass.
    """
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

    # Two questions answered from one walk of the indicator list. Both are
    # tracked as plain booleans rather than flags because the interesting
    # signal is their *combination*, decided after the loop.
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

        # oleid's own severity, taken at face value. It is conservative
        # about HIGH — most rows come back "none" or "info" — so a HIGH
        # here is worth the three points the rule set gives it.
        if row["risk"].upper() == "HIGH":
            out["indicator_flags"].add("oleid_high_risk")
        if row["id"] == "encrypted" and row["value"].lower() in ("true", "1"):
            encrypted = True
        if row["id"] in ("vba", "vba_macros") and row["value"].lower() in ("true", "1"):
            has_macros = True

    # "Encryption only" — file is password-protected and has no macros.
    # This is a common evasion pattern; contribute a small score.
    #
    # The two halves are not symmetric in reliability: `encrypted` comes
    # from an indicator whose value really is a boolean, while the macro
    # indicator's value is prose. See the module docstring on value types.
    if encrypted and not has_macros:
        out["encryption_only"] = True
        out["indicator_flags"].add("encryption_only")

    return out
