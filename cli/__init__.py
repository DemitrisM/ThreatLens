"""ThreatLens CLI — multi-command Click application.

Subcommands are defined in dedicated modules and registered via
``add_command`` to avoid circular imports.
"""

import click

__all__ = ["cli"]


@click.group()
@click.version_option(version="0.2.0", prog_name="ThreatLens")
def cli() -> None:
    """ThreatLens — static malware analysis with transparent confidence scoring."""


from .analyse import analyse  # noqa: E402
from .compare import compare  # noqa: E402
from .update_rules import update_rules  # noqa: E402

cli.add_command(analyse)
cli.add_command(compare)
cli.add_command(update_rules)
