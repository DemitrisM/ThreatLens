"""Shared fixtures for report-rendering tests.

Rendered rich output is only deterministic when width, colour and clock are
pinned, so every rendering test goes through the helpers here.
"""

import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from rich.console import Console

FIXTURE_DIR = Path(__file__).parent / "fixtures"
SNAPSHOT_DIR = Path(__file__).parent / "snapshots"

#: Frozen clock for the report footer.
FROZEN_NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def load_report(name: str) -> dict:
    """Return a frozen pipeline report dict by fixture stem."""
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text())


def make_console(width: int = 100, *, file=None) -> Console:
    """A console that renders identically on every machine and in CI."""
    return Console(
        file=file,
        width=width,
        no_color=True,
        highlight=False,
        force_terminal=False,
        legacy_windows=False,
    )


def render_report(report: dict, detail_level: int = 0, width: int = 100) -> str:
    """Render a full terminal report to a string."""
    from reporting.terminal_reporter import print_terminal_report

    buf = io.StringIO()
    print_terminal_report(
        report,
        detail_level=detail_level,
        console=make_console(width, file=buf),
        now=FROZEN_NOW,
    )
    return buf.getvalue()


@pytest.fixture
def report_redline() -> dict:
    return load_report("redline")


@pytest.fixture
def report_rar() -> dict:
    return load_report("netsupport_rar")


@pytest.fixture
def report_onenote() -> dict:
    return load_report("onenote")


@pytest.fixture
def report_xlsm() -> dict:
    return load_report("giftedcrook_xlsm")


@pytest.fixture
def report_html() -> dict:
    return load_report("clickfix_html")


@pytest.fixture
def report_pdf() -> dict:
    return load_report("booking_pdf")


@pytest.fixture
def console() -> Console:
    return make_console()
