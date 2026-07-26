"""Exit codes and ``--fail-on`` threshold evaluation.

ThreatLens follows the convention established by scanner CLIs (clamscan,
olevba, trivy, nuclei): the exit status distinguishes "ran fine, found
nothing actionable" from "ran fine, found a threat" from "could not run".

======  ===================================================================
Code    Meaning
======  ===================================================================
``0``   Clean, or the risk band sits below ``--fail-on``.
``1``   A threat at or above ``--fail-on`` was reported.
``2``   Usage error — bad flag, wrong argument type, conflicting options.
        Click raises this itself for every :class:`click.UsageError`.
``3``   Runtime error — pipeline crash, unwritable output path, missing
        external tool that the requested operation cannot proceed without.
======  ===================================================================

Without ``--fail-on`` a scan never exits 1, so adding these codes cannot
silently change the meaning of an existing invocation.
"""

import click

EXIT_OK = 0
EXIT_THREAT = 1
EXIT_USAGE = 2
EXIT_RUNTIME = 3

#: Risk bands from lowest to highest severity. Mirrors ``core.scoring._BANDS``.
BAND_ORDER: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

#: Accepted ``--fail-on`` values, ordered for display in ``--help``.
FAIL_ON_CHOICES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class RuntimeFailure(click.ClickException):
    """A runtime failure that should exit 3.

    Click prints ``Error: <message>`` to stderr and uses ``exit_code``.
    """

    exit_code = EXIT_RUNTIME


def meets_threshold(risk_band: str | None, fail_on: str | None) -> bool:
    """Return True when *risk_band* is at or above the *fail_on* threshold.

    Args:
        risk_band: Band from ``report["scoring"]["risk_band"]``. An
                   unrecognised or missing band is treated as the lowest
                   severity rather than raising — a malformed band must
                   never turn into a nonzero exit on its own.
        fail_on:   Threshold band, or None when ``--fail-on`` was not given.

    Returns:
        False whenever *fail_on* is None, so the default invocation always
        exits 0 on a successful run.
    """
    if not fail_on:
        return False

    threshold = BAND_ORDER.get(fail_on.upper())
    if threshold is None:
        # click.Choice already rejects unknown values; defend the library path.
        raise ValueError(f"Unknown --fail-on band: {fail_on!r}")

    return BAND_ORDER.get((risk_band or "").upper(), 0) >= threshold
