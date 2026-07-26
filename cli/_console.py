"""Stream-separated ``rich`` consoles.

stdout carries results and nothing else, so ``threatlens scan -f json``
can be piped straight into ``jq``. Progress spinners, warnings and any
other diagnostic chatter go to stderr, where redirecting stdout leaves
them visible.

Import these singletons rather than constructing a ``Console`` locally —
each ``Console`` keeps its own terminal-detection and colour state, so
multiple instances writing to the same stream can disagree about width
and about whether colour is enabled.
"""

from rich.console import Console

#: Results — reports, tables, machine output.
out = Console()

#: Diagnostics — progress, warnings, saved-path notices, errors.
err = Console(stderr=True)

__all__ = ["out", "err"]
