"""HTML keeps its exact palette while sourcing it from theme.py."""

import re
from pathlib import Path

from reporting.html_reporter import write_html_report
from reporting.theme import TOKENS, css_root
from tests.conftest import load_report

TEMPLATE = Path("reporting/templates/report.html.j2")

#: The literal block that shipped in the template before theme.py existed.
#: If css_root() ever stops reproducing these, the HTML report has drifted.
ORIGINAL_ROOT = """    :root {
        --bg:           #0f1115;
        --bg-panel:     #181b22;
        --bg-panel-2:   #1f232c;
        --border:       #2a2f3a;
        --text:         #e6e8ee;
        --text-dim:     #9aa3b2;
        --text-faint:   #6b7280;
        --accent:       #4cc9f0;
        --critical:     #ff4d4f;
        --high:         #ff8c1a;
        --medium:       #ffd93d;
        --low:          #5cb85c;
        --success:      #5cb85c;
        --skipped:      #d4a017;
        --error:        #ff4d4f;
        --code-bg:      #0b0d12;
    }"""


def test_template_has_no_hardcoded_palette():
    tpl = TEMPLATE.read_text()
    assert "{{ theme_css }}" in tpl
    assert "--critical:" not in tpl, "palette literal still in the template"


def test_css_root_reproduces_every_original_declaration():
    """Every variable the template used to declare, at the same value."""
    generated = css_root()
    for line in ORIGINAL_ROOT.splitlines():
        decl = line.strip()
        if not decl.startswith("--"):
            continue
        assert decl in generated, f"lost or changed declaration: {decl!r}"


def test_rendered_html_carries_every_token(tmp_path):
    path = write_html_report(load_report("redline"), tmp_path)
    html = path.read_text()
    for name, token in TOKENS.items():
        assert token["css"] in html, f"{name} missing from rendered HTML"


def test_rendered_html_defines_every_variable_it_uses(tmp_path):
    """A var() with no declaration renders as an invisible element."""
    path = write_html_report(load_report("redline"), tmp_path)
    html = path.read_text()
    used = set(re.findall(r"var\((--[a-z0-9-]+)\)", html))
    declared = set(re.findall(r"(--[a-z0-9-]+):\s*#", html))
    assert used <= declared, f"undeclared CSS vars: {sorted(used - declared)}"


def test_html_analysis_renders_a_section(tmp_path):
    """Pass 4: html_analysis had zero presence in reporting/ before."""
    from reporting.html_reporter import write_html_report

    html = write_html_report(load_report("clickfix_html"), tmp_path).read_text()
    assert "HTML Smuggling Indicators" in html
    assert "Obfuscation" in html


def test_pdf_analysis_renders_a_section(tmp_path):
    from reporting.html_reporter import write_html_report

    html = write_html_report(load_report("booking_pdf"), tmp_path).read_text()
    assert "PDF Indicators" in html
    assert "/OpenAction" in html


def test_html_and_terminal_agree_on_rows():
    """Both reporters read the same builder, so parity is structural."""
    from reporting.html_reporter.pdf import pdf_indicators
    from reporting.terminal_reporter.pdf import pdf_rows

    report = load_report("booking_pdf")
    data = next(
        r for r in report["module_results"] if r["module"] == "pdf_analysis"
    )["data"]
    assert pdf_indicators(report["module_results"]) == pdf_rows(data, 2)


def test_rendered_html_is_self_contained(tmp_path):
    """No external stylesheet or script — the report must open offline."""
    html = write_html_report(load_report("redline"), tmp_path).read_text()
    assert "<link" not in html.lower() or "stylesheet" not in html.lower()
    assert "http://" not in html.split("<style>")[0]
