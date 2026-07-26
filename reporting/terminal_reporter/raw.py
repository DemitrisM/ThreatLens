"""Raw per-module data for ``-vv``.

This is the payload that makes detail level 2 different from level 1. Every
``detail_level`` site in the reporter tested ``>= 1``; none tested ``>= 2``,
so ``-vv`` was byte-identical to ``-v`` apart from the Python logging level.

Credentials are stripped recursively via :func:`reporting.shared.sanitise_secrets`
before anything is printed — the same helper the JSON and HTML reporters use.
"""

import json
import logging

from rich.console import Console
from rich.syntax import Syntax

from reporting.shared import sanitise_secrets

from ._common import console as default_console

logger = logging.getLogger(__name__)


def module_json(result: dict) -> str:
    """One module result as sanitised, indented JSON."""
    try:
        return json.dumps(sanitise_secrets(result), indent=2, default=str)
    except (TypeError, ValueError) as exc:
        logger.warning(
            "Could not serialise module %s for raw view: %s",
            result.get("module", "unknown"),
            exc,
        )
        return f"<unserialisable: {exc}>"


def print_raw_modules(
    module_results: list[dict], *, console: Console | None = None
) -> None:
    """Dump every module's full result. Only reached at ``-vv``."""
    con = console or default_console
    if not module_results:
        return

    con.print()
    con.print("  [bold]RAW MODULE DATA[/bold]")
    for result in module_results:
        name = result.get("module", "unknown")
        status = result.get("status", "unknown")
        con.print()
        con.print(f"  [bold cyan]{name}[/bold cyan] [dim]({status})[/dim]")
        con.print(
            Syntax(
                module_json(result),
                "json",
                theme="ansi_dark",
                word_wrap=True,
                background_color="default",
            )
        )


__all__ = ["module_json", "print_raw_modules"]
