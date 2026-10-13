"""Detonation state — the three-valued answer to "did it actually run?".

D-2 of the Phase 5 scoring discipline. A dynamic provider reports not
only what it saw but whether it got to look, and the two are different
facts that the report must keep apart.

Design notes
------------
**Why three values and not a boolean.** A sample that detonated and did
nothing is indistinguishable, in the payload, from one whose sandbox
failed: sinkholed C2, egress denied on purpose, an emulator meeting an
unmodelled API, a sample that detected it was being watched. Two states —
ran / did not run — collapse "we looked and saw nothing" into "we never
looked". Scoring those the same way converts "we did not see it" into "it
is not there", which is how a confident clean verdict gets printed for
live malware.

This is the same distinction `doc_analysis` draws with
``performed``/``present`` and `pdf_analysis` with
``javascript_engine.available``/``enabled``/``executed``. Dynamic analysis
needs a third value because it has a failure mode static analysis does
not: **the attempt itself can break.**

**Why this lives in core/ and not in modules/dynamic/provider_base.py.**
``core`` has no static dependency on ``modules`` — the registries hold
dotted strings and ``_load_module`` imports lazily, which is what lets a
machine missing an optional dependency still run everything else. Putting
the vocabulary in ``provider_base`` and importing it from
``core/pipeline.py`` would create exactly the import that design avoids.
Providers import it from here instead; nothing in this module imports
anything of the project's.

**Why a missing state is FAILED rather than NOT_ATTEMPTED.** The provider
ran and returned a dict, so "not attempted" would be false. "Failed" is
also the value D-5 counts toward ``INDETERMINATE``, which is the honest
band for "we cannot tell" — and a provider that does not report its own
state is precisely a case of not being able to tell. The alternative, a
fourth ``unknown`` value, buys nothing: every reader would have to treat
it exactly as it treats ``failed``.

**Why a contradiction is resolved on the STATE, not on the score.** A
provider can make two statements about itself — ``status`` and the
detonation state — and they can disagree: ``status: "error"`` beside
``state: "observed"``. The orchestrator must not pick a winner between
them, so it believes neither and demotes the state to ``FAILED``.

Demoting rather than merely zeroing the score is the whole point, and an
earlier version of this module got it wrong. The state is what the rest
of the system reads: :func:`observed` gates whether a reporter may render
behaviour at all, and D-5 counts ``FAILED`` toward ``INDETERMINATE``.
Zeroing the number while leaving the state at ``OBSERVED`` meant an
errored provider still rendered its findings and still read as a
completed detonation — the exact failure D-2 exists to prevent, surviving
inside D-2 itself.

**Why the score_delta is then zeroed unless the state is OBSERVED.** A
dynamic provider's ``score_delta`` *is* a behavioural finding, expressed
as a number, and a score that moves a verdict is the loudest rendering
there is. Because the contradiction is already resolved above, this rule
needs no second condition: an honest state is enough.
"""

import logging

logger = logging.getLogger(__name__)

#: Behaviour was actually observed. The ONLY state on which a reporter may
#: render a behavioural finding, or a score_delta may survive.
OBSERVED = "observed"

#: No detonation was tried — no provider armed, or the provider declined
#: this format. **Not evidence of anything**, and specifically not
#: evidence of incompleteness: D-5 requires that an inapplicable provider
#: never pushes a verdict toward INDETERMINATE, or every benign file would
#: be branded with it.
NOT_ATTEMPTED = "not_attempted"

#: Detonation was tried and did not produce a usable answer: emulator
#: aborted, egress denied, timed out. Counts toward D-5's INDETERMINATE,
#: because it is the case where something should have been learned and was
#: not.
#:
#: Two reasons an earlier draft listed — "required application absent" and
#: "interaction gate unmet" — left with the document-detonation tier, which
#: is out of scope as of 2026-10-12.
FAILED = "failed"

#: Every valid state. A value outside this set is treated as FAILED.
STATES = frozenset({OBSERVED, NOT_ATTEMPTED, FAILED})

#: Where the state lives inside a provider result's ``data``.
DATA_KEY = "detonation"

# ----------------------------------------------------------------------
# Egress — D-4.
#
# "No C2 contacted" and "no C2 configured" produce the same empty
# network log, and only one of them is a finding. If the sandbox denied
# outbound traffic — which it should — then silence on the wire is a
# property of the harness, not of the sample, and a report that does not
# say so invites exactly the wrong conclusion.
#
# So the denial is recorded as a fact in the report, not left implicit in
# whatever command the operator ran. The blocked-destination list is the
# positive form of the same disclosure: it is both an indicator list and
# a completeness statement, because it says what the sample REACHED for
# while proving nothing reached it.
# ----------------------------------------------------------------------

#: Outbound traffic was possible. Absence of contact is then evidence.
EGRESS_ALLOWED = "allowed"

#: Outbound traffic was blocked. Absence of contact proves NOTHING, and
#: the report must say so rather than leaving a reader to infer it.
EGRESS_DENIED = "denied"

#: The provider did not say. Rendered as nothing at all rather than as a
#: claim — an emulator with no network model has no honest answer here,
#: and inventing one would be the fabrication this rule exists to stop.
EGRESS_UNKNOWN = "unknown"

EGRESS_STATES = frozenset({EGRESS_ALLOWED, EGRESS_DENIED, EGRESS_UNKNOWN})

#: Where the egress block lives inside a provider result's ``data``.
EGRESS_KEY = "egress"


def egress(state: str, blocked: list | None = None) -> dict:
    """Build the egress block a provider puts in its ``data``.

    Args:
        state:   One of :data:`EGRESS_ALLOWED`, :data:`EGRESS_DENIED`,
                 :data:`EGRESS_UNKNOWN`.
        blocked: Destinations the sample tried to reach and did not,
                 when the provider can observe them. Meaningful only
                 with :data:`EGRESS_DENIED`; an allowed run has nothing
                 blocked to list.

    Returns:
        ``{"state": ..., "blocked": [...]}``.

    Raises:
        ValueError: On an unknown state, for the same reason
            :func:`build` does — this is provider code at construction
            time, where a typo is a bug to surface.
    """
    if state not in EGRESS_STATES:
        raise ValueError(
            f"unknown egress state {state!r} — expected one of "
            f"{sorted(EGRESS_STATES)}"
        )
    return {"state": state, "blocked": list(blocked or [])}


def egress_of(result: dict) -> tuple[str, list]:
    """Read a result's egress policy and blocked destinations.

    Args:
        result: A provider result, or absence of one.

    Returns:
        ``(state, blocked)``. Anything unreadable answers
        :data:`EGRESS_UNKNOWN` with an empty list, which renders as no
        claim — never as "allowed", which would invite a reader to treat
        an empty network log as evidence.
    """
    if not isinstance(result, dict):
        return EGRESS_UNKNOWN, []
    data = result.get("data")
    if not isinstance(data, dict):
        return EGRESS_UNKNOWN, []
    block = data.get(EGRESS_KEY)
    if not isinstance(block, dict):
        return EGRESS_UNKNOWN, []
    state = block.get("state")
    if state not in EGRESS_STATES:
        return EGRESS_UNKNOWN, []
    blocked = block.get("blocked")
    return state, list(blocked) if isinstance(blocked, list) else []


def _state_for_missing_block(status: object) -> str:
    """What a result with no detonation block means, from its status.

    One function because two readers ask the same question and must not
    answer it differently — :func:`normalise`, repairing a provider
    result, and :func:`state_of`, reading one. An earlier version let
    them disagree: the same dict read as ``FAILED`` through one and
    ``NOT_ATTEMPTED`` through the other. Raised in review 2026-10-13.

    Args:
        status: The result's ``status`` field, or None if absent.

    Returns:
        :data:`NOT_ATTEMPTED` when the provider declared a skip,
        :data:`FAILED` otherwise.

    A skip is the shape design rule 2 mandates for graceful degradation:
    a provider whose backend is not configured logs, sets status
    ``"skipped"``, and returns empty data. Nothing was attempted, so
    nothing failed — and the difference is load-bearing, because D-5
    counts ``FAILED`` toward ``INDETERMINATE`` and must not count this.
    Branding every unconfigured provider a failure would push ordinary
    static scans toward "could not determine".

    Any other status with no block is a provider that ran and did not say
    whether it got to look, which is a bug, and the honest reading of a
    bug is that nothing was established.
    """
    return NOT_ATTEMPTED if status == "skipped" else FAILED


def build(state: str, reason: str = "") -> dict:
    """Build the detonation block a provider puts in its ``data``.

    Args:
        state:  One of :data:`OBSERVED`, :data:`NOT_ATTEMPTED`,
                :data:`FAILED`.
        reason: Why, in one human-readable clause. Required in practice
                for the two non-observed states — the report prints it,
                and "failed" with no reason tells an analyst nothing.

    Returns:
        ``{"state": ..., "reason": ...}``, ready to assign to
        ``data["detonation"]``.

    Raises:
        ValueError: If *state* is not a member of :data:`STATES`. This is
            the one place in the dynamic path that raises, and
            deliberately: it is called by provider code at construction
            time, not by the orchestrator on untrusted input, so a typo
            here is a bug to surface rather than a hostile value to
            absorb. :func:`normalise` is the forgiving counterpart.
    """
    if state not in STATES:
        raise ValueError(
            f"unknown detonation state {state!r} — expected one of {sorted(STATES)}"
        )
    return {"state": state, "reason": reason}


#: Why a state had to be repaired, from :func:`_resolve_state`. None
#: means the provider's own state was accepted unchanged.
_MISSING = "missing"
_MALFORMED = "malformed"
_UNKNOWN = "unknown"
_CONTRADICTION = "contradiction"


def _resolve_state(result: dict) -> tuple[str, str | None]:
    """The one rule for what a result's detonation state actually is.

    Both :func:`normalise`, which repairs a result, and :func:`state_of`,
    which reads one, go through here — so reading a result before and
    after normalisation cannot give two different answers. That invariant
    is asserted exhaustively in ``tests/test_detonation.py``.

    It did not hold when the two functions each decided for themselves,
    and it half-held when only the missing-block case was shared: an
    unknown state string, a malformed block and a status/state
    contradiction still resolved differently depending on which function
    was asked. A documented invariant that holds in some cases is worse
    than none, because callers rely on it. Raised in review 2026-10-13.

    Args:
        result: A provider result dict.

    Returns:
        ``(state, repair)``. *state* is always a member of
        :data:`STATES`. *repair* is None when the provider's own state
        was accepted, or one of the ``_MISSING`` / ``_MALFORMED`` /
        ``_UNKNOWN`` / ``_CONTRADICTION`` constants naming why it was
        overridden — which is what lets :func:`normalise` log and explain
        while :func:`state_of` stays silent.
    """
    status = result.get("status")
    data = result.get("data")

    if not isinstance(data, dict):
        return _state_for_missing_block(status), _MISSING

    block = data.get(DATA_KEY)
    if block is None:
        return _state_for_missing_block(status), _MISSING

    # Present but not a dict: the provider tried to report a block and
    # got it wrong. That is a bug, not a graceful skip, so it resolves to
    # FAILED whatever the status says — unlike an absent block, where a
    # "skipped" status is design rule 2's correct shape.
    if not isinstance(block, dict):
        return FAILED, _MALFORMED

    state = block.get("state")
    # The isinstance test is not redundant with the membership test, and
    # removing it reintroduces a crash. `x not in STATES` hashes x, and a
    # frozenset lookup of an unhashable value raises TypeError rather than
    # answering False — so a provider returning {"state": ["observed"]} or
    # a nested dict took the whole scan down from inside the one function
    # whose docstring promises it never raises. Design rule 2. Found by
    # the review gate 2026-10-13 and reproduced before fixing.
    if not isinstance(state, str) or state not in STATES:
        # Same reasoning as above: a typo'd, wrongly typed or corrupted
        # state is a provider bug.
        return FAILED, _UNKNOWN

    if state == OBSERVED and status != "success":
        return FAILED, _CONTRADICTION

    return state, None


def normalise(result: dict, provider_name: str) -> None:
    """Enforce D-2 on a provider result, in place.

    Guarantees four things about *result* once it returns:

    1. ``data["detonation"]`` exists and its ``state`` is a member of
       :data:`STATES`.
    2. A non-observed state carries a reason naming why.
    3. A state of :data:`OBSERVED` is demoted to :data:`FAILED` when
       ``status`` is not ``"success"``, because the two claims
       contradict each other.
    4. ``score_delta`` is 0 unless the state is :data:`OBSERVED`.

    Args:
        result:        A provider result, already normalised by the
                       caller's ``setdefault`` block, so ``data``,
                       ``status`` and ``score_delta`` are present.
        provider_name: Named in every warning, so a non-conforming
                       provider is attributable.

    Returns:
        None. Mutates *result*.

    Never raises — design rule 2. A provider returning nonsense is logged
    and corrected toward the safe reading, never allowed to end the scan.
    """
    # ------------------------------------------------------------------
    # Step 1: Make sure the state has somewhere to live.
    #
    # The caller's setdefault only fills a MISSING key, so a provider that
    # returned data as a list or a string still has to be handled.
    # ------------------------------------------------------------------
    data = result.get("data")
    if not isinstance(data, dict):
        logger.warning(
            "Dynamic provider %s returned non-dict data (%s) — replacing it, "
            "so the detonation state has somewhere to live",
            provider_name,
            type(data).__name__,
        )
        data = {}
        result["data"] = data

    # ------------------------------------------------------------------
    # Step 2: Resolve the state, and say out loud when the provider's own
    # answer had to be overridden.
    #
    # The decision itself is _resolve_state's, shared with state_of. What
    # belongs here is only the logging and the repaired reason text —
    # state_of must stay silent, since reading a result is not an event.
    # ------------------------------------------------------------------
    state, repair = _resolve_state(result)
    block = data.get(DATA_KEY)
    if not isinstance(block, dict):
        # Captured BEFORE the replacement below, which is the whole point.
        # Reading the type afterwards reported "dict" every time — the
        # type of the empty replacement, never the offending value — so
        # the one detail the warning exists to carry was the one thing it
        # could not say. Found by the review gate 2026-10-13.
        malformed_type = type(block).__name__
        block = {}
        data[DATA_KEY] = block
    else:
        malformed_type = type(block).__name__

    if repair == _MISSING and state == NOT_ATTEMPTED:
        # Not warned: this is design rule 2's prescribed shape for a
        # provider that cannot run — status "skipped", empty data. The
        # provider is behaving correctly, and warning on correct
        # behaviour trains a reader to ignore the log.
        own_reason = result.get("reason")
        block["state"] = state
        block["reason"] = (
            own_reason
            if isinstance(own_reason, str) and own_reason.strip()
            else "provider reported a skip"
        )
    elif repair is not None:
        # Each warning names the offending value, not just the outcome.
        # "treating as failed" alone tells a provider author nothing
        # about which of their fields was wrong.
        reported = block.get("state")
        message, args, repaired_reason = {
            _MISSING: (
                "Dynamic provider %s reported no detonation state — treating "
                "as %s. A provider must say whether it got to look.",
                (provider_name, state),
                "provider reported no detonation state",
            ),
            _MALFORMED: (
                "Dynamic provider %s reported a malformed detonation block "
                "(%s) — treating as %s",
                (provider_name, malformed_type, state),
                "provider reported a malformed detonation block",
            ),
            _UNKNOWN: (
                "Dynamic provider %s reported unknown detonation state %r — "
                "treating as %s",
                (provider_name, reported, state),
                f"provider reported unrecognised state {reported!r}",
            ),
            _CONTRADICTION: (
                "Dynamic provider %s reported state=%s with status=%r — "
                "demoted to %s. A provider that did not complete cannot also "
                "have observed behaviour.",
                (provider_name, OBSERVED, result.get("status"), state),
                f"provider claimed observed behaviour while reporting "
                f"status {result.get('status')!r}",
            ),
        }[repair]
        logger.warning(message, *args)
        block["state"] = state
        # A provider's own reason is kept when it gave one: it is more
        # specific than anything written here. The exception is a
        # contradiction, where the provider's reason describes the
        # observation it is no longer credited with.
        existing = block.get("reason")
        if (
            repair == _CONTRADICTION
            or not isinstance(existing, str)
            or not existing.strip()
        ):
            block["reason"] = repaired_reason
    else:
        block["state"] = state

    # ------------------------------------------------------------------
    # Step 3: A non-observed state must say why.
    #
    # The report prints this string. "Detonation failed" with no reason
    # leaves an analyst unable to tell a denied network from a crashed
    # emulator, which is the distinction the whole rule exists to
    # preserve.
    # ------------------------------------------------------------------
    reason = block.get("reason")
    if not isinstance(reason, str):
        reason = ""
        block["reason"] = ""
    if state != OBSERVED and not reason.strip():
        logger.warning(
            "Dynamic provider %s reported state %s with no reason — the "
            "report cannot explain the gap",
            provider_name,
            state,
        )
        block["reason"] = "provider gave no reason"

    # ------------------------------------------------------------------
    # Step 4: Nothing observed, nothing scored.
    #
    # A dynamic score_delta IS a behavioural finding, expressed as a
    # number — and a number that moves a verdict is the loudest rendering
    # there is. Guarded on a non-zero delta so the ordinary
    # "detonation failed, scored nothing" case stays silent; warning there
    # would bury the real provider bugs under the commonest outcome.
    # ------------------------------------------------------------------
    delta = result.get("score_delta", 0)
    if delta and state != OBSERVED:
        logger.warning(
            "Dynamic provider %s scored %s while reporting state=%s — "
            "zeroed. A score is a behavioural finding, and nothing was "
            "observed.",
            provider_name,
            delta,
            state,
        )
        result["score_delta"] = 0


def observed(result: dict) -> bool:
    """Whether *result* may be rendered as behaviour.

    The single predicate every reporter asks before printing a
    behavioural finding, so the rule is expressed once rather than
    re-derived at each call site.

    Args:
        result: A provider result that has been through :func:`normalise`.

    Returns:
        True only when the detonation state is :data:`OBSERVED`.

        ``None`` answers False, which is what ``report["dynamic"]`` holds
        on every scan that armed no provider — the common case, not an
        edge one, and a reporter asking this question unconditionally
        must not have to guard the call.

        Note what this does NOT check: whether :func:`normalise` ran. A
        hand-built result claiming ``state: "observed"`` beside
        ``status: "error"`` answers True here, because the contradiction
        is resolved during normalisation and this function only reads the
        result of that. The pipeline normalises every provider result
        before anything can read it; a caller inventing one has
        bypassed the gate, not found a hole in it.
    """
    if not isinstance(result, dict):
        return False
    data = result.get("data")
    if not isinstance(data, dict):
        return False
    block = data.get(DATA_KEY)
    if not isinstance(block, dict):
        return False
    return block.get("state") == OBSERVED


def state_of(result: dict) -> str:
    """The detonation state of *result*, or :data:`NOT_ATTEMPTED`.

    Args:
        result: A provider result, or ``None``-ish absence of one.

    Returns:
        The state string. Absence — ``None``, or anything that is not a
        dict — reads as :data:`NOT_ATTEMPTED`, which is what
        ``report["dynamic"]`` holds on every scan that armed no provider.

        A *result* with no detonation block is resolved by
        :func:`_state_for_missing_block`, the same rule
        :func:`normalise` applies, so reading a result before and after
        normalisation cannot give two different answers. An earlier
        version defaulted here independently and they disagreed.
    """
    if not isinstance(result, dict):
        return NOT_ATTEMPTED
    state, _ = _resolve_state(result)
    return state
