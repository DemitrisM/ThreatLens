"""The palette is the single source of colour for both reporters."""

import re
from pathlib import Path

from reporting.theme import CLASS_SEVERITY, TOKENS, css_root, rich_style


def test_every_token_has_both_representations():
    for name, token in TOKENS.items():
        assert "rich" in token, f"{name} has no rich key"
        assert re.fullmatch(r"#[0-9a-f]{6}", token["css"]), (
            f"{name} css value {token['css']!r} is not a 6-digit hex colour"
        )


def test_rich_style_returns_the_token_value():
    assert rich_style("critical") == "bold red"
    assert rich_style("bad") == "red"


def test_rich_style_falls_back_for_unknown_names():
    """A colour typo must not kill a completed analysis."""
    assert rich_style("no_such_token") == ""


def test_css_root_emits_a_variable_per_token():
    css = css_root()
    assert css.startswith(":root {")
    assert css.rstrip().endswith("}")
    for name, token in TOKENS.items():
        assert f"--{name.replace('_', '-')}:" in css
        assert token["css"] in css


def test_css_root_preserves_the_shipped_palette():
    """These lines ship in report.html.j2 today and must not drift."""
    css = css_root()
    for expected in (
        "--bg:           #0f1115;",
        "--bg-panel:     #181b22;",
        "--bg-panel-2:   #1f232c;",
        "--border:       #2a2f3a;",
        "--text:         #e6e8ee;",
        "--text-dim:     #9aa3b2;",
        "--text-faint:   #6b7280;",
        "--accent:       #4cc9f0;",
        "--critical:     #ff4d4f;",
        "--high:         #ff8c1a;",
        "--medium:       #ffd93d;",
        "--low:          #5cb85c;",
        "--success:      #5cb85c;",
        "--skipped:      #d4a017;",
        "--error:        #ff4d4f;",
        "--code-bg:      #0b0d12;",
    ):
        assert expected in css, f"missing or misaligned: {expected!r}"


def test_css_root_covers_every_variable_the_template_uses():
    """No CSS var may reference a token that css_root does not emit."""
    template = Path("reporting/templates/report.html.j2").read_text()
    used = set(re.findall(r"var\((--[a-z0-9-]+)\)", template))
    emitted = {f"--{name.replace('_', '-')}" for name in TOKENS}
    assert used <= emitted, f"template uses undefined vars: {sorted(used - emitted)}"


def test_derived_rich_maps_match_the_pre_refactor_literals():
    """Snapshots render with no_color=True and cannot catch colour drift,
    so pin the rich styles that _common.py used to hardcode."""
    from reporting.terminal_reporter._common import BAND_COLOURS, STATUS_COLOURS

    assert BAND_COLOURS == {
        "CRITICAL": "bold red",
        "HIGH": "bold orange1",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }
    assert STATUS_COLOURS == {
        "success": "green",
        "skipped": "dim yellow",
        "error": "red",
    }


def test_severity_styles_match_the_pre_refactor_literals():
    """_SEV_STYLES was declared byte-identically in pe.py and doc.py."""
    assert {sev: rich_style(sev) for sev in ("bad", "warn", "info")} == {
        "bad": "red",
        "warn": "yellow",
        "info": "dim",
    }


def test_classification_colours_match_the_pre_refactor_literals():
    """_CLASS_COLOURS was declared byte-identically in archive.py and onenote.py."""
    assert {
        cls: rich_style(cls.lower())
        for cls in ("MALICIOUS", "SUSPICIOUS", "INFORMATIONAL", "CLEAN")
    } == {
        "MALICIOUS": "bold red",
        "SUSPICIOUS": "bold yellow",
        "INFORMATIONAL": "cyan",
        "CLEAN": "green",
    }


def test_class_severity_holds_no_risk_bands():
    """onenote.py fed a risk_band into this map, so it never matched."""
    assert set(CLASS_SEVERITY) == {
        "MALICIOUS",
        "SUSPICIOUS",
        "INFORMATIONAL",
        "CLEAN",
    }
    for band in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        assert band not in CLASS_SEVERITY


def test_class_severity_values_are_valid_severities():
    assert set(CLASS_SEVERITY.values()) <= {"bad", "warn", "info"}


# ── Design rule 8: colour comes from the palette ────────────────────


#: Every module that resolves a style, plus the one CLI file that builds
#: a coloured table. `theme.py` is excluded — it owns the colours.
_COLOUR_OWNERS = tuple(
    p
    for p in sorted(Path("reporting").rglob("*.py")) + [Path("cli/compare.py")]
    if p.name != "theme.py"
)


#: Bare rich colour names. A compound style like "bold red" is out of
#: scope: those are still written inline in a few section builders and
#: moving them all is its own job. This guards the *fallbacks*, which is
#: where the design-rule-8 violation actually was.
_BARE_COLOURS = frozenset(
    {"white", "black", "red", "green", "yellow", "blue", "magenta", "cyan"}
)


def _bare_colour_fallbacks(path: Path) -> list[str]:
    """Every `x.get(k, "red")` and `x or "red"` in one file.

    Parsed rather than grepped: the fix left comments that name the
    colour while explaining why it is wrong, and a substring search
    cannot tell those from the code they replaced.
    """
    import ast

    offences: list[str] = []

    def _flag(node, value: str) -> None:
        offences.append(
            f"{path}:{node.lineno} falls back to the bare colour "
            f"{value!r} instead of theme.NEUTRAL"
        )

    for node in ast.walk(ast.parse(path.read_text())):
        # `styles.get(key, "white")`
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and len(node.args) == 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in _BARE_COLOURS
        ):
            _flag(node, node.args[1].value)
        # `rich_style(name) or "white"` — the other spelling, and the one
        # that was missed when only `.get` was checked.
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            for value in node.values[1:]:
                if isinstance(value, ast.Constant) and value.value in _BARE_COLOURS:
                    _flag(node, value.value)
    return offences


def test_no_reporter_falls_back_to_a_bare_colour_name():
    """`.get(key, "white")` is a colour literal outside the palette.

    Design rule 8 puts every colour in theme.py, and nine call sites
    spelled their fallback inline. Rich reads "white" as ANSI colour 7
    (#c0c0c0), not as the terminal default, so on a light background it
    is a real choice and a poor one.
    """
    offences = [o for path in _COLOUR_OWNERS for o in _bare_colour_fallbacks(path)]

    assert not offences, "\n".join(offences)


def test_the_neutral_style_is_the_terminal_default():
    """Not "white", which is a colour; not "", which rich refuses in markup."""
    from reporting.theme import NEUTRAL

    assert NEUTRAL == "default"


def test_an_unknown_ioc_type_renders_neutrally():
    from reporting.theme import NEUTRAL, ioc_style

    label, style = ioc_style("no_such_type")

    assert label == "no_such_type"
    assert style == NEUTRAL
