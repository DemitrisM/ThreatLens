"""Stream-separated ``rich`` consoles, created once for the whole tool.

stdout carries results and nothing else, so ``threatlens scan -f json``
can be piped straight into ``jq``. Progress spinners, warnings and any
other diagnostic chatter go to stderr, where redirecting stdout leaves
them visible.

The singletons live in ``reporting`` rather than ``cli`` because
``reporting`` is the lower layer — ``cli`` imports it, never the reverse.
``cli/_console.py`` re-exports these, so exactly one stdout ``Console``
exists in the tree. That matters: each ``Console`` keeps its own
terminal-detection and colour state, so two instances writing to the same
stream can disagree about width and about whether colour is enabled.
"""

from rich.console import Console

from reporting.theme import rich_theme

#: The palette, registered as rich styles on both consoles. This is what
#: lets a reporter write ``[bad]…[/bad]`` rather than ``[red]…[/red]``:
#: the markup carries a meaning, the hue lives in one table, and a test
#: can reject any bare colour name it finds in the source. Built once —
#: a Theme is immutable in use and both consoles share it.
_THEME = rich_theme()

#: Results — reports, tables, machine output.
out = Console(theme=_THEME)

#: Diagnostics — progress, warnings, saved-path notices, errors.
err = Console(stderr=True, theme=_THEME)


def print_machine(payload: str) -> None:
    """Write a machine-readable payload to stdout, exactly as given.

    Args:
        payload: A complete JSON document or JSON Lines block.

    The three arguments are all load-bearing and all easy to forget,
    which is why this exists instead of a convention:

    - ``soft_wrap=True`` stops rich folding the line at the console
      width. Without it a JSON document longer than the terminal is
      broken across lines and ``threatlens scan … -f json | jq`` fails.
      Verified: identical to the payload with it, corrupted without.
    - ``markup=False`` stops a ``[`` inside a string being read as a
      style tag. JSON is full of them.
    - ``highlight=False`` stops rich colouring numbers and quotes, which
      would put escape sequences into a redirected file.
    - ``emoji=False`` stops a colon-delimited run being substituted for a
      character. Rich does this independently of markup, so the other
      three flags do not cover it: a sample named
      ``report:100:final:x:.exe`` was rendered ``report💯final❌.exe``.
      A malware filename is attacker-controlled, so this is the one of
      the four that can be triggered deliberately.

    Design rule 7 puts results on stdout and nothing else there, and
    rule 6 keeps output off bare ``print``. This is the one path that
    satisfies both for machine formats.
    """
    out.print(
        payload, markup=False, highlight=False, emoji=False, soft_wrap=True
    )


__all__ = ["err", "out", "print_machine"]
