"""stdout carries results, stderr carries everything else — design rule 8."""

import pytest
import sys

from reporting.console import err, out


def test_out_writes_to_stdout():
    assert out.file is sys.stdout


def test_err_writes_to_stderr():
    assert err.file is sys.stderr


def test_cli_reexports_the_same_objects():
    """One stdout Console in the tree, not two competing ones."""
    from cli import _console

    assert _console.out is out
    assert _console.err is err


def test_terminal_reporter_defaults_to_the_shared_console():
    from reporting.terminal_reporter._common import current_console

    assert current_console() is out


def test_use_console_is_scoped_and_restores():
    from reporting.terminal_reporter._common import current_console, use_console

    pinned = object()
    with use_console(pinned):
        assert current_console() is pinned
    assert current_console() is out


def test_use_console_none_keeps_the_current_binding():
    from reporting.terminal_reporter._common import current_console, use_console

    with use_console(None):
        assert current_console() is out


def test_console_proxy_forwards_to_the_bound_console():
    """Section modules import the proxy; it must resolve at call time."""
    import io

    from reporting.terminal_reporter._common import console, use_console
    from tests.conftest import make_console

    buf = io.StringIO()
    with use_console(make_console(file=buf)):
        console.print("hello")
    assert "hello" in buf.getvalue()


# ── machine output is exact ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("emoji shortcode", '{"file": "report:100:final:x:.exe"}'),
        ("markup bracket", '{"note": "[bold red]not a style[/bold red]"}'),
        ("long line", '{"file": "' + "x" * 400 + '"}'),
        ("numbers", '{"score": 60, "ratio": "47/75"}'),
    ],
)
def test_machine_output_is_written_byte_for_byte(label, payload, monkeypatch):
    """Four rich behaviours, any one of which corrupts a payload.

    `soft_wrap` stops the line being folded at the console width;
    `markup=False` stops a `[` being read as a style tag; `emoji=False`
    stops a colon-delimited run becoming a character — a sample named
    `report:100:final:x:.exe` rendered as `report💯final❌.exe`, and a
    malware filename is attacker-controlled; `highlight=False` stops
    escape sequences reaching a redirected file.

    They are easy to forget one at a time, which is why `print_machine`
    exists rather than a convention.
    """
    import io

    from reporting import console as console_module

    buf = io.StringIO()
    monkeypatch.setattr(console_module.out, "file", buf)
    console_module.print_machine(payload)

    assert buf.getvalue() == payload + "\n", label
