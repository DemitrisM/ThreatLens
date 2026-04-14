"""Shared rich objects + colour maps used across the terminal package.

Kept in a separate module (rather than in ``__init__.py``) so section
submodules can import the ``console`` singleton without triggering a
circular import back through the package's orchestrator.
"""

from rich.console import Console


console = Console()

BAND_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
}

STATUS_COLOURS = {
    "success": "green",
    "skipped": "dim yellow",
    "error": "red",
}
