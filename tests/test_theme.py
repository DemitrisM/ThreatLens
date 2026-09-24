"""The palette is the single source of colour for both reporters."""

import re
from pathlib import Path

from reporting.theme import CLASS_SEVERITY, TOKENS, css_root, rich_style


def test_every_token_has_both_representations():
    """A token carries a rich style, a CSS colour, or both.

    ``css`` is None for a composed rich style such as "bold cyan", where
    the weight is the point and the hue already has a token of its own —
    the HTML report styles its headings with its own rules, so emitting
    a variable for it would put an unused declaration in `:root`.
    """
    for name, token in TOKENS.items():
        assert "rich" in token, f"{name} has no rich key"
        assert "css" in token, f"{name} has no css key"
        assert token["rich"] or token["css"], f"{name} carries neither half"
        if token["css"] is not None:
            assert re.fullmatch(r"#[0-9a-f]{6}", token["css"]), (
                f"{name} css value {token['css']!r} is not a 6-digit hex colour"
            )


def test_rich_style_returns_the_token_value():
    assert rich_style("critical") == "bold red"
    assert rich_style("bad") == "red"


def test_rich_style_falls_back_for_unknown_names():
    """A colour typo must not kill a completed analysis."""
    assert rich_style("no_such_token") == ""


def test_css_root_emits_a_variable_per_coloured_token():
    """And nothing for a rich-only one, which has no colour to emit."""
    css = css_root()
    assert css.startswith(":root {")
    assert css.rstrip().endswith("}")
    for name, token in TOKENS.items():
        var = f"--{name.replace('_', '-')}:"
        if token["css"] is None:
            assert var not in css, f"{name} is rich-only but reached the CSS"
            continue
        assert var in css
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


#: Everything that renders. `theme.py` is excluded — it owns the colours,
#: and it is the one file where a hue is supposed to be spelled out.
_COLOUR_OWNERS = tuple(
    p
    for p in sorted(Path("reporting").rglob("*.py")) + sorted(Path("cli").rglob("*.py"))
    if p.name != "theme.py"
)


#: Bare rich colour names, in any combination with a weight. `[dim]` and
#: `[bold]` are deliberately absent: they carry no hue, they are emphasis
#: rather than colour, and design rule 8 is about colour.
_BARE_COLOURS = frozenset(
    {
        "white", "black", "red", "green", "yellow", "blue", "magenta",
        "cyan", "orange1",
    }
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


#: Rich markup naming a hue, with or without a weight: `[red]`,
#: `[bold red]`, `[/dim red]`. The palette is registered as a
#: `rich.Theme` on both consoles, so the semantic name is what belongs
#: here — `[bad]`, `[brand]`, `[error_dim]`.
_COLOUR_MARKUP_RE = re.compile(
    r"\[/?(?:[a-z]+ )*(?:" + "|".join(sorted(_BARE_COLOURS)) + r")(?: [a-z]+)*\]"
)


def _colour_markup(path: Path) -> list[str]:
    """Every string constant in *path* that spells a hue in markup.

    Docstrings are skipped: they explain the rule, and several of them
    quote the very markup they are telling the reader not to write.
    """
    import ast

    tree = ast.parse(path.read_text())
    docstrings = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }

    offences: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if node in docstrings:
            continue
        for hit in _COLOUR_MARKUP_RE.findall(node.value):
            offences.append(
                f"{path}:{node.lineno} writes {hit!r} — use the semantic "
                f"token, which the console's rich.Theme resolves"
            )
    return offences


def test_no_reporter_spells_a_colour_in_markup():
    """The other half of design rule 8, and the half that was untrue.

    Twenty-nine call sites wrote `[red]`, `[bold cyan]`, `[dim red]` and
    the like directly. The rule said none existed. Registering the
    palette as a `rich.Theme` on both consoles is what makes the
    semantic name work in markup, so there is now no reason to spell a
    hue anywhere but `theme.py` — and this test says so mechanically
    rather than leaving the rule to be believed.
    """
    offences = [o for path in _COLOUR_OWNERS for o in _colour_markup(path)]

    assert not offences, "\n".join(offences)


def test_every_style_name_used_in_markup_is_a_real_token():
    """A typo in a semantic tag renders as literal text, not as colour.

    That is the risk the Theme introduces: `[bad]` is checked by nobody
    at runtime, and `[badd]` would print the brackets. Rich's own style
    names stay legal — `dim`, `bold`, and combinations of them.
    """
    import ast

    from reporting.theme import TOKENS

    # Only tokens with a rich half: `rich_theme()` registers those and
    # skips the CSS-only ones, so `[code_bg]` is not an error but it is
    # not a style either — it renders as plain text while the author
    # believes a colour was applied. That silent no-op is the same shape
    # as the `"white"` fallback this rule was written for.
    allowed = {name for name, token in TOKENS.items() if token["rich"]} | {
        "dim", "bold", "italic", "underline", "reverse", "blink", "strike",
    }
    tag = re.compile(r"\[/?([a-z_][a-z0-9_ ]*)\]")

    unknown: list[str] = []
    for path in _COLOUR_OWNERS:
        tree = ast.parse(path.read_text())
        docstrings = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if node in docstrings:
                continue
            for name in tag.findall(node.value):
                if all(word in allowed for word in name.split()):
                    continue
                unknown.append(f"{path}:{node.lineno} uses unknown style {name!r}")

    assert not unknown, "\n".join(unknown)


def test_the_neutral_style_is_the_terminal_default():
    """Not "white", which is a colour; not "", which rich refuses in markup."""
    from reporting.theme import NEUTRAL

    assert NEUTRAL == "default"


def test_an_unknown_ioc_type_renders_neutrally():
    from reporting.theme import NEUTRAL, ioc_style

    label, style = ioc_style("no_such_type")

    assert label == "no_such_type"
    assert style == NEUTRAL
