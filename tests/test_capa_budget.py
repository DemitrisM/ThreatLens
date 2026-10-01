"""capa's time budgets, set from a measured distribution.

capa runtime over 12 PEs spanning the corpus size range, bundled binary,
every one measured to completion:

    11.1  17.5  49.4  60.0  95.0  136.6  227.3  235.1  391.1  730.0  731.0  734.0

The old defaults covered 5 of 12 (120s) and 6 of 12 (`-p deep`'s 180s). The
tail is four AutoIt samples at 723-734s, each returning **114 capabilities** —
they are slow because there is a great deal to find, not because capa is
stuck. Every one exits 0 with a full result.

So the old budgets discarded capa's entire contribution on more than half the
PEs tested, and reported it as "capa timed out", which reads as a machine
problem rather than a budget decision.

These values are evidence, not preference. Changing them should mean
re-measuring, which is why the distribution is written down here.
"""

from cli._helpers import _apply_scan_profile
from core.config_loader import DEFAULTS

#: Longest capa run measured on the corpus, on this hardware.
_MEASURED_MAX = 734


def test_the_default_budget_covers_the_common_case():
    """240s: 8 of 12 measured samples, four minutes worst case.

    The ceiling an analyst waits through on a single file.
    """
    assert DEFAULTS["capa_timeout_seconds"] == 240


def test_deep_covers_every_measured_sample():
    """900s clears the 734s maximum with headroom for slower hardware.

    `-p deep` already means "spend the time" — it turns on FLOSS emulation at
    26x cost. A capa ceiling barely above the default was the inconsistency.
    """
    deep = _apply_scan_profile(dict(DEFAULTS), "deep")

    assert deep["capa_timeout_seconds"] == 900
    assert deep["capa_timeout_seconds"] > _MEASURED_MAX, (
        "deep must clear the slowest sample actually measured, or it "
        "re-creates the gap it exists to close"
    )


def test_standard_does_not_raise_the_budget():
    """`standard` leaves the configured value alone.

    The two axes stay separate: `-p` decides cost, and only `deep` opts into
    the expensive end.
    """
    standard = _apply_scan_profile(dict(DEFAULTS), "standard")
    assert standard["capa_timeout_seconds"] == DEFAULTS["capa_timeout_seconds"]


def test_quick_runs_no_capa_at_all():
    """Why a `triage` sweep is unaffected by either number.

    `triage` defaults to `quick`, and `quick` does not run capa — which is
    what makes a generous `deep` budget affordable.
    """
    quick = _apply_scan_profile(dict(DEFAULTS), "quick")
    assert "capa_analysis" not in quick["enabled_modules"]
