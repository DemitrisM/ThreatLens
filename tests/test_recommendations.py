"""Recommendations must not tell an analyst to run something that fails.

A recommendation is the one part of a report that asks the reader to type
a command. A wrong flag there is worse than no advice: the reader trusts
it, runs it, and gets exit 2 from the tool that just told them to.

The HTML reporter had drifted twice. `--dynamic speakeasy` was removed in
CLI redesign Pass 1 and the terminal copy was fixed with a comment saying
so, while the HTML mirror kept advertising it. `--deep` never existed in
the new surface at all — the profile axis is `-p deep`. Both survived
because nothing checked rendered advice against the actual command line.

So these tests do not pin the three strings that were wrong. They parse
every flag out of every recommendation in both reporters and check it
against Click's own parameter list, which means the next one cannot drift
either.
"""

import re

import pytest

from cli import cli as cli_group
from reporting.html_reporter import recommendations as html_recs
from reporting.terminal_reporter import recommendations as term_recs

# Options as they appear in prose: --skip, --fail-on, -p, -v.
#
# Short flags are included, and omitting them was a real blind spot: this
# very change replaced `--deep` with `-p deep`, so the only flag the fix
# introduced was the one the test could not see. Raised in review.
#
# The lookarounds keep a short flag from matching inside ordinary text —
# a hyphenated word, a negative number, or the "-p" of an em-dash clause
# — by requiring the flag to stand alone.
#
# Digits are allowed in a long option and the boundary applies to both
# branches. Without either, `--sha256` matched as `--sha` and then failed
# the existence check as a flag nobody wrote. Both raised in review.
#
# `-vv` deliberately matches nothing: it is `-v` repeated, not an option
# Click registers, so asserting it exists would fail on correct advice.
# The cost is that a recommendation naming `-vv` goes unchecked, which is
# the safe direction for a test that must not cry wolf.
_FLAG_RE = re.compile(r"(?<![\w-])(?:--[a-z][a-z0-9-]*|-[a-z])(?![\w-])")


def _real_flags() -> set[str]:
    """Every long option Click actually accepts, across every verb.

    Read from the command objects rather than from `--help` text, so the
    set cannot drift from what the CLI really parses.
    """
    flags = {"--help", "-h"}
    # The root group's own options, which are NOT reachable through
    # .commands — `--version` lives here. Missing them meant a
    # recommendation naming a global option would fail as though the
    # option did not exist. Raised in review.
    for param in cli_group.params:
        flags.update(o for o in param.opts if o.startswith("-"))
    for command in cli_group.commands.values():
        for param in command.params:
            flags.update(o for o in param.opts if o.startswith("-"))
        # `rules` is a group with its own subcommands.
        for sub in getattr(command, "commands", {}).values():
            for param in sub.params:
                flags.update(o for o in param.opts if o.startswith("-"))
    return flags


def _recommendation_strings(module) -> list[str]:
    """Every string literal in a recommendations module's source.

    Parsing the source rather than running the builder, because reaching
    a given recommendation needs a report shaped to trigger it, and the
    point is to catch the branch nobody exercised.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(module))

    # Docstrings are excluded. They are prose ABOUT the code, and the
    # natural place to write "`--dynamic` was removed in Pass 1" — which
    # under a blanket scan would fail the very test that records the
    # removal. Comments are already invisible here, since they never
    # reach the AST; this puts docstrings on the same footing. Raised in
    # review.
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))

    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


@pytest.mark.parametrize("module", [term_recs, html_recs],
                         ids=["terminal", "html"])
def test_every_flag_a_recommendation_names_actually_exists(module):
    real = _real_flags()
    for text in _recommendation_strings(module):
        for flag in _FLAG_RE.findall(text):
            assert flag in real, (
                f"{module.__name__} recommends {flag!r}, which is not a flag "
                f"this CLI accepts. Real flags: {sorted(real)}"
            )


def test_the_dynamic_provider_is_not_advertised_as_a_flag():
    """It is config-only by design — `core/pipeline.py` says arming a
    sandbox should not be something a user trips over on a command line.
    Advice that implies a flag contradicts the design as well as failing."""
    for module in (term_recs, html_recs):
        for text in _recommendation_strings(module):
            lowered = text.lower()
            if "dynamic analysis" in lowered:
                assert "--dynamic" not in lowered, f"{module.__name__}: {text}"


@pytest.mark.parametrize("module", [term_recs, html_recs],
                         ids=["terminal", "html"])
def test_no_recommendation_quotes_a_stale_capa_budget(module):
    """`-p deep` raised capa's budget from 180s to 900s when the budgets
    were set from a measured distribution. Both reporters still told the
    reader 180s, which under-promises by five minutes and would make a
    user think the retry had hung."""
    from cli._helpers import _DEEP_OVERRIDES

    deep = _DEEP_OVERRIDES["capa_timeout_seconds"]
    quoted = [
        text for text in _recommendation_strings(module)
        if "capa" in text.lower() and re.search(r"\d+s", text)
    ]
    assert quoted, f"{module.__name__} no longer quotes a capa budget at all"
    for text in quoted:
        # Asserted POSITIVELY against the real override, not by banning
        # the one stale number. An earlier version only failed on "180",
        # which passed for any other wrong value and would have passed
        # silently the next time the budget moved — the same vacuous
        # shape this file exists to catch. Raised in review.
        assert f"{deep}s" in text, (
            f"{module.__name__} quotes a capa budget that is not the real "
            f"one ({deep}s): {text!r}"
        )


def test_both_reporters_name_the_same_flags():
    """The HTML reporter mirrors the terminal one, and every defect in
    this pair so far has been the mirror drifting rather than both being
    wrong together.

    Their outputs cannot be compared directly — the terminal module
    PRINTS (`print_recommendations`) while the HTML module RETURNS a list
    (`recommendations`). That asymmetry is itself why the mirror drifts:
    there is no shared builder to keep them honest, so the advice is
    written twice. Comparing the flags they name is the part that can be
    checked mechanically, and it is where both known defects lived.

    Wording is allowed to differ — the terminal copy says "set
    dynamic_provider in config.yaml" where HTML says something else — but
    a flag named in one and not the other means one of them is stale."""
    term_flags = {f for s in _recommendation_strings(term_recs)
                  for f in _FLAG_RE.findall(s)}
    html_flags = {f for s in _recommendation_strings(html_recs)
                  for f in _FLAG_RE.findall(s)}
    assert term_flags == html_flags, (
        "the two reporters name different flags — one has drifted:\n"
        f"  terminal only: {sorted(term_flags - html_flags)}\n"
        f"  html only:     {sorted(html_flags - term_flags)}"
    )
