"""Re-export of the shared console singletons.

The objects themselves live in :mod:`reporting.console` because
``reporting`` is the lower layer — ``cli`` imports it, never the reverse.
Importing them here keeps every existing ``from cli._console import out,
err`` call site working while guaranteeing there is exactly one stdout
``Console`` in the tree.
"""

from reporting.console import err, out

__all__ = ["err", "out"]
