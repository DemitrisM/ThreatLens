"""Shared rich objects + colour maps used across the terminal package.

Kept in a separate module (rather than in ``__init__.py``) so section
submodules can import the ``console`` singleton without triggering a
circular import back through the package's orchestrator.

``console`` is a context-local proxy rather than a bare ``Console``. Every
section module already does ``from ._common import console``, so binding
the real console per-render through a :class:`contextvars.ContextVar`
lets tests render to a pinned, reproducible console without threading a
parameter through all nine section modules — and without mutating global
state, so concurrent renders cannot clobber each other.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Final, Iterator

from rich.console import Console

from reporting.console import out
from reporting.theme import rich_style

_console_var: ContextVar[Console] = ContextVar(
    "terminal_reporter_console", default=out
)


class _ConsoleProxy:
    """Forwards every attribute access to the context's current console."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_console_var.get(), name)

    def __repr__(self) -> str:
        return f"<ConsoleProxy -> {_console_var.get()!r}>"


#: Import this, not a concrete Console. Resolves at call time.
console = _ConsoleProxy()


def current_console() -> Console:
    """The console this render is writing to."""
    return _console_var.get()


@contextmanager
def use_console(target: Console | None) -> Iterator[Console]:
    """Bind ``target`` as the console for the duration of the block.

    ``None`` keeps whatever is already bound, so callers can pass an
    optional console straight through.
    """
    if target is None:
        yield _console_var.get()
        return
    token = _console_var.set(target)
    try:
        yield target
    finally:
        _console_var.reset(token)


#: Risk-band colours. Derived from the theme — no literals live here.
BAND_COLOURS: Final[dict[str, str]] = {
    "CRITICAL": rich_style("critical"),
    "HIGH": rich_style("high"),
    "MEDIUM": rich_style("medium"),
    "LOW": rich_style("low"),
}

STATUS_COLOURS: Final[dict[str, str]] = {
    "success": rich_style("success"),
    "skipped": rich_style("skipped"),
    "error": rich_style("error"),
}

#: Row caps per section. Every one of these was an unnamed literal at its
#: use site before Pass 2a. ``archive_members`` and ``archive_execs`` rise
#: from a silent 20 and 10 — that truncation printed no hint at all, so an
#: analyst could not tell rows had been dropped.
LIMITS: Final[dict[str, int]] = {
    "attack_mappings": 10,
    "iocs_per_type": 5,
    "suspicious_strings": 10,
    "capabilities": 10,
    "onenote_blobs": 20,
    "archive_members": 50,
    "archive_execs": 50,
    "html_members": 50,
    "reason_chars": 120,
    "pdb_chars": 90,
}

__all__ = [
    "BAND_COLOURS",
    "LIMITS",
    "STATUS_COLOURS",
    "console",
    "current_console",
    "use_console",
]
