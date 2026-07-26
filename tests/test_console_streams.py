"""stdout carries results, stderr carries everything else — CLAUDE.md rule 8."""

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
