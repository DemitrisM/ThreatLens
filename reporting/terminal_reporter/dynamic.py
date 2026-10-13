"""Dynamic Analysis section — D-3 and D-4 of the Phase 5 discipline.

Until now nothing rendered ``report["dynamic"]`` at all. The JSON
reporter passed it through; the terminal and HTML reports did not
mention it. A provider's result reached the score through
``module_results`` and was otherwise invisible, which is the worst of
both worlds: it could move a verdict without ever explaining itself.

Design notes
------------
**The section renders whenever a provider ran, including — especially —
when it failed.** That is D-3. A detonation that did not happen is the
single most misleading thing a dynamic report can omit, because the
payload of a failed run and the payload of a clean run are identical:
empty. The notice is not an error message, it is the finding.

**Prepended, never appended.** The ``Pass unavailable`` rows in
``doc_analysis`` earned this: a notice at the end of a section is the
first thing truncation eats, and the reader who most needs it is the one
reading a default report. Same reason it is not gated on
``detail_level``.

**The count goes in the reason, the names go in rows.** Also from
``doc_analysis``: the reason line is cut at about 120 characters, and
naming things there pushed out the findings that identify the sample.

**Nothing is rendered as behaviour unless the state is ``observed``.**
That is D-2, and :func:`core.detonation.observed` is the one predicate
that decides it, so the rule is not re-derived here.

**Egress is stated, not implied.** D-4. "No C2 contacted" and "no C2
configured" produce the same empty network log; if the harness denied
outbound traffic then silence proves nothing about the sample, and a
report that stays quiet about the denial invites the wrong conclusion.
``unknown`` renders as nothing at all rather than as a claim.

**The provider result comes from ``report["dynamic"]``, not from
``module_results``.** It is in both — the pipeline appends it — but
finding it in the list means matching the ``dynamic_`` name prefix, and
a rule resting on a string prefix is one rename from silently lapsing.
D-1 rejected that same shortcut.
"""

from core import detonation as det

from ._common import console
from ._render import Row, render_indicators

#: Rows that must survive the detail-0 filter. The detonation state is
#: the point of the section: hiding it when nothing louder fired would
#: leave a reader with a dynamic section that says nothing about whether
#: dynamic analysis happened.
_ALWAYS_SHOW = frozenset({"Detonation", "Network egress"})

#: How a non-observed state reads. Deliberately not "bad": a detonation
#: that failed is a gap in the analysis, not evidence against the
#: sample, and colouring it as a threat finding would be its own kind of
#: lie. "not_attempted" is quieter still — no provider was armed, which
#: is the default posture and not a shortcoming.
_STATE_SEVERITY = {
    det.OBSERVED: "info",
    det.FAILED: "warn",
    det.NOT_ATTEMPTED: "info",
}

#: Human text for each state, written for someone who did not read the
#: plan. Each says what it means for the verdict, because that is the
#: question a reader actually has.
_STATE_TEXT = {
    det.OBSERVED: "observed — the sample ran and its behaviour was recorded",
    det.FAILED: "FAILED — nothing was observed, so this report is static only",
    det.NOT_ATTEMPTED: "not attempted — no provider was armed for this file",
}

#: Cap on named blocked destinations, matching the section-cap habit
#: elsewhere in the reporters. The count always appears, so truncation
#: never hides the scale.
_BLOCKED_LIMIT = 5


def dynamic_rows(dynamic: dict | None, detail_level: int = 0) -> list[Row]:
    """Build the Dynamic Analysis rows from a provider result.

    Args:
        dynamic:      ``report["dynamic"]`` — a normalised provider
                      result, or None when no provider was armed.
        detail_level: 0 summary, 1 expanded, 2 full.

    Returns:
        Rows in render order, the detonation state first. Empty when no
        provider ran, so the section disappears entirely rather than
        printing "not attempted" on every static scan — which would be
        true, useless, and on every report this tool has ever produced.
    """
    if not isinstance(dynamic, dict):
        return []

    rows: list[Row] = []
    state = det.state_of(dynamic)

    # ------------------------------------------------------------------
    # The notice, first. See the module docstring for why it is
    # prepended and why it ignores detail_level.
    # ------------------------------------------------------------------
    rows.append(
        Row("Detonation", _STATE_TEXT.get(state, state),
            _STATE_SEVERITY.get(state, "warn"))
    )

    # The reason, as its own row rather than inside the state text. A
    # failed detonation with no stated cause leaves an analyst unable to
    # tell a denied network from a crashed emulator, and those lead to
    # opposite next steps.
    # `data` is the provider's, so it is not assumed to be a dict —
    # core.detonation.normalise repairs that, but a reporter can be
    # handed a result that never went through it (a fixture, a replayed
    # JSON report), and design rule 2 reaches the reporters too.
    data = dynamic.get("data")
    block = data.get(det.DATA_KEY) if isinstance(data, dict) else None
    reason = block.get("reason") if isinstance(block, dict) else None
    # Falling back to the TOP-LEVEL reason, which is where design rule 1
    # puts a module's human-readable explanation and where design rule 2
    # leaves the cause of a graceful skip — that shape has `data: {}` and
    # so carries no detonation block at all. normalise() copies it across
    # for a skip, but a result that never went through normalise (a
    # fixture, a replayed JSON report) would otherwise lose the only
    # sentence explaining the gap. Raised in review.
    if not (isinstance(reason, str) and reason.strip()):
        reason = dynamic.get("reason")
    if state != det.OBSERVED and isinstance(reason, str) and reason.strip():
        rows.append(Row("Reason", reason.strip(), "warn"))

    # removeprefix, not startswith. The orchestrator labels a provider
    # with `setdefault("module", f"dynamic_{name}")`, so a provider that
    # names ITSELF keeps its own name and never gains the prefix —
    # gating the row on the prefix dropped it silently for exactly those
    # providers. Raised in review.
    provider = dynamic.get("module")
    if isinstance(provider, str) and provider.strip():
        rows.append(Row("Provider", provider.removeprefix("dynamic_"), "info"))

    # ------------------------------------------------------------------
    # D-4: the egress policy, stated.
    # ------------------------------------------------------------------
    egress_state, blocked = det.egress_of(dynamic)
    if egress_state == det.EGRESS_DENIED:
        rows.append(
            Row(
                "Network egress",
                # Short on purpose. The first draft ran to two wrapped
                # lines and the decisive phrase landed split across the
                # break, which is how a reader skims past the one claim
                # that matters.
                "DENIED — absence of C2 contact is not evidence",
                "warn",
            )
        )
    elif egress_state == det.EGRESS_ALLOWED:
        rows.append(
            Row(
                "Network egress",
                "allowed — absence of C2 contact is meaningful",
                "info",
            )
        )

    # Gated on `observed`, because a blocked destination is a statement
    # about what the SAMPLE did — it reached for that host — and D-2
    # forbids rendering a behavioural finding on any other state. The
    # egress policy row above is not gated, because that is a fact about
    # the harness and true regardless of whether the sample ran.
    #
    # This cuts against the project's standing preference for noise over
    # a missed IOC, and the trade is deliberate: a destination recovered
    # from a run that did not complete is exactly the half-observed
    # evidence D-2 exists to keep out of a report, and an analyst cannot
    # tell from the page that it is unverified. A provider with
    # pre-failure observations worth surfacing can put them in its
    # reason, where they read as narrative rather than as finding.
    if blocked and det.observed(dynamic):
        # Count in the label's value, names in their own rows — the
        # doc_analysis lesson. A reader sees the scale even when the
        # list is cut.
        rows.append(
            Row("Blocked destinations", f"{len(blocked)} reached for", "warn")
        )
        shown = blocked if detail_level >= 1 else blocked[:_BLOCKED_LIMIT]
        rows.extend(Row("Blocked", str(dest), "warn") for dest in shown)
        hidden = len(blocked) - len(shown)
        if hidden > 0:
            # "warn", not "info": at detail 0 an info row is hidden
            # whenever something louder fired, which is exactly when a
            # blocked list is long enough to need cutting. The notice
            # would have announced itself only on reports where nothing
            # had been truncated. Caught by reading the rendered table.
            rows.append(
                Row("Blocked", f"+{hidden} more — use -v to show all", "warn")
            )

    return rows


def print_dynamic_section(dynamic: dict | None, detail_level: int) -> None:
    """Dynamic Analysis section.

    Args:
        dynamic:      ``report["dynamic"]``, or None.
        detail_level: 0 summary, 1 expanded, 2 full.

    Prints nothing when no provider ran. Note the asymmetry with the
    other sections, which skip on a non-success status: this one renders
    a failed provider deliberately, because a failure is the thing D-3
    exists to disclose.
    """
    rows = dynamic_rows(dynamic, detail_level)
    if not rows:
        return
    render_indicators(
        "Dynamic Analysis",
        rows,
        detail_level,
        always_show=_ALWAYS_SHOW,
        console=console,
    )
