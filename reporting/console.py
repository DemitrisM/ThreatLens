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

#: Results — reports, tables, machine output.
out = Console()

#: Diagnostics — progress, warnings, saved-path notices, errors.
err = Console(stderr=True)

__all__ = ["err", "out"]
