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
