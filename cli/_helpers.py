"""Scan-profile presets, module overrides, and logging setup.

ThreatLens separates two axes that other tools keep confused:

- ``--profile`` decides *what runs* — a cost decision.
- ``-v`` / ``-vv`` decide *what prints* — a display decision.

Nothing in this module touches the second axis; verbosity is a plain count
passed straight to the reporter.

Design notes
------------
Order of application is fixed and load-bearing: profile first, then
``--modules``, then ``--skip``. The profile has to come first: it rewrites
``enabled_modules`` wholesale, so applying it after a selection would
reinstate exactly what the user had just removed, and ``-p deep --skip
capa`` would run capa. ``--skip`` comes last so that it subtracts from
whichever list ``--modules`` settled on.

The two selection surfaces are deliberately asymmetric. A name typed on the
command line is explicit intent, so an unknown one is a usage error (exit 2)
— a typo must not quietly change what ran. A name in ``config.yaml`` only
warns and is skipped, because a stale config file written against an older
version must not make the tool unrunnable.

Every path here guards the same invariant, stated in design rule 10: a scan
that ran no analysis module must never report a verdict. An empty
``--modules``, an unknown name, and a selection whose modules are all
skipped are all refused rather than allowed to produce a confident LOW.
"""

import copy
import logging

import click

from core.config_loader import DEFAULTS
from core.pipeline import module_names, resolve_module_name

logger = logging.getLogger(__name__)

# ── Scan profile presets ────────────────────────────────────────────

PROFILES = ("quick", "standard", "deep")

#: ``quick`` is the default profile for ``triage``, so anything omitted
#: here makes a whole file type sweep as LOW across a directory.
#: ``lnk_analysis`` earns its place on the same terms as ``pe_analysis``:
#: pure in-memory parsing, no subprocess, no optional dependency, and
#: sub-millisecond on a file that is almost always under 2 KiB.
_QUICK_MODULES = ["file_intake", "pe_analysis", "lnk_analysis"]

_DEEP_OVERRIDES = {
    "capa_timeout_seconds": 180,
    # FLOSS emulation — the one part of string extraction that is not
    # nearly free. Measured over the 30 corpus PEs: 30.0 minutes against
    # 69 seconds for static-only extraction, and it produced no suspicious
    # -category match on any of them. What it buys is the +10 structural
    # bonus, which fires on 13 of the 30: a binary that builds its strings
    # on the stack has paid to hide them whether or not they match a
    # pattern, and no static extractor can see that. A 26x cost for one
    # signal is exactly what `deep` is for.
    #
    # No timeout override beside it: `floss_timeout_seconds` defaults to
    # 300, which already covers the slowest sample measured (271.1s), and
    # costs nothing on the profiles that do not emulate.
    "floss_emulation": True,
}


def _apply_scan_profile(config: dict, profile: str) -> dict:
    """Override config values based on the selected scan profile.

    ``standard`` and ``deep`` both mean "whatever ``enabled_modules``
    says", so they only fill in the built-in list when the config supplied
    none — overwriting from ``DEFAULTS`` would silently drop modules a user
    enabled in config.yaml. ``quick`` is the one that replaces the list
    outright, which is what makes it cheap.

    Args:
        config: Loaded config, mutated in place.
        profile: One of :data:`PROFILES`. An unrecognised value is a no-op
                 rather than an error, since ``click.Choice`` has already
                 rejected anything else on the CLI path.

    Returns:
        The same dict, for chaining with :func:`_apply_module_overrides`.
    """
    if profile == "quick":
        config["enabled_modules"] = list(_QUICK_MODULES)
        return config

    # `deep` is `standard` plus a longer capa budget, so it takes the same
    # fill-in. Applying only the override left a config that named no
    # modules running none, which made the more thorough profile the one
    # that refused to run. Named explicitly rather than written as "not
    # quick", so an unrecognised profile stays the no-op this promises.
    if profile in ("standard", "deep"):
        if not config.get("enabled_modules"):
            config["enabled_modules"] = copy.deepcopy(DEFAULTS["enabled_modules"])
    if profile == "deep":
        config.update(_DEEP_OVERRIDES)
    return config


#: Every module reads this one's metadata (hashes, type), so it is never
#: optional — it is force-added to --modules and ignored in --skip.
_MANDATORY_MODULE = "file_intake"


def _resolve_list(raw: str, flag: str) -> list[str]:
    """Split a comma-separated flag value into canonical module names.

    Raises:
        click.UsageError: on an unknown name or an empty selection. Both
            are exit 2. Silently accepting either is how ``--modules
            pe,capa,yara`` used to produce ``total_score: 0`` and a
            confident LOW verdict on a scan that never ran.
    """
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    if not tokens:
        raise click.UsageError(
            f"{flag} was given no module names. "
            f"Valid names: {', '.join(module_names())}"
        )

    unknown = [t for t in tokens if resolve_module_name(t) is None]
    if unknown:
        raise click.UsageError(
            f"{flag}: unknown module(s): {', '.join(unknown)}. "
            f"Valid names: {', '.join(module_names())}"
        )

    resolved: list[str] = []
    for token in tokens:
        name = resolve_module_name(token)
        # Aliases can collide (pe and exe both mean pe_analysis), so
        # de-duplicate. Order is imposed afterwards, not taken from here.
        if name not in resolved:
            resolved.append(name)
    return _canonical_order(resolved)


#: The order the pipeline executes in. Each module sees its predecessors'
#: results through ``_module_results_so_far``, so this is a correctness
#: constraint, not a preference: ``virustotal`` looks up the hashes the
#: container modules surfaced and finds none if it runs before them.
_EXECUTION_ORDER = tuple(DEFAULTS["enabled_modules"])


def _canonical_order(names: list[str]) -> list[str]:
    """Sort *names* into pipeline execution order.

    A comma-separated allowlist gives a user no reason to think its order
    matters, so the order typed is discarded rather than honoured —
    ``--modules vt,onenote`` would otherwise run the lookup before the
    module that produces what it looks up, skipping the forward lookup
    for every embedded payload while still reporting success.

    Args:
        names: Canonical module names, already de-duplicated.

    Returns:
        The same names, ordered by ``_EXECUTION_ORDER``. A name absent
        from that table keeps its relative position at the end, which is
        the safe direction — an unrecognised module runs after the ones
        whose output it might want to read.
    """
    known = [n for n in _EXECUTION_ORDER if n in names]
    unknown = [n for n in names if n not in _EXECUTION_ORDER]
    return known + unknown


def _apply_module_overrides(
    config: dict, modules: str | None, skip: str | None
) -> dict:
    """Apply ``--modules`` and ``--skip`` overrides to ``enabled_modules``.

    Both accept registry names and short aliases (``pe``, ``capa``, ``vt``).
    ``--skip`` is applied after ``--modules``, so ``-p deep --skip
    capa_analysis`` behaves as documented.

    Unknown names are a usage error rather than a silent no-op — the CLI is
    explicit intent, so a typo must not quietly change what ran.
    ``enabled_modules`` in config.yaml stays permissive (the pipeline warns
    and skips) so a stale config file cannot make the tool unrunnable.
    """
    # ── --modules: replace the list outright ────────────────────────────
    if modules is not None:
        names = _resolve_list(modules, "--modules")
        # Removed and re-inserted rather than only inserted when absent:
        # a user who names it explicitly should not be able to demote it
        # by typing it second, since every module reads its metadata.
        names = [n for n in names if n != _MANDATORY_MODULE]
        names.insert(0, _MANDATORY_MODULE)
        config["enabled_modules"] = names

    # ── --skip: subtract, after the profile and after --modules ─────────
    if skip is not None:
        to_skip = set(_resolve_list(skip, "--skip"))
        if _MANDATORY_MODULE in to_skip:
            logger.warning(
                "%s cannot be skipped — every module reads its metadata",
                _MANDATORY_MODULE,
            )
            to_skip.discard(_MANDATORY_MODULE)
        config["enabled_modules"] = [
            m for m in config["enabled_modules"] if m not in to_skip
        ]

    # ── Design rule 10: nothing ran is not a clean verdict ──────────────
    # file_intake is excluded from the count deliberately — it is metadata
    # only and always scores 0, so a list holding it alone is a scan that
    # analysed nothing while still producing a report.
    remaining = [m for m in config["enabled_modules"] if m != _MANDATORY_MODULE]
    if not remaining:
        raise click.UsageError(
            "No analysis modules left to run — every module was skipped or "
            "deselected. A scan that runs nothing cannot report a verdict."
        )

    return config


def _setup_logging(log_level: str | None = None, verbosity: int = 0) -> None:
    """Configure the root logger.

    Args:
        log_level: Level name from config, used when no flag overrides it.
        verbosity: ``-v`` count. 1 → INFO, 2+ → DEBUG.

    Called twice per invocation: once before the config is read (so that
    config-loading warnings reach a configured handler) and once after (to
    honour ``log_level``). ``force=True`` makes the second call effective —
    ``logging.basicConfig`` is otherwise a no-op once handlers exist.
    """
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = getattr(logging, (log_level or "WARNING").upper(), logging.WARNING)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        force=True,
    )


def _detail_level(verbosity: int) -> int:
    """Clamp a ``-v`` count to the reporter's 0/1/2 detail levels.

    Click counts every repetition, so ``-vvvv`` arrives as 4. Clamping
    rather than rejecting keeps a harmless habit harmless.
    """
    return min(max(verbosity, 0), 2)
