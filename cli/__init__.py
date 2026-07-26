"""ThreatLens CLI — four verbs, two axes.

- ``scan``    — one file
- ``triage``  — a directory
- ``compare`` — two files, side by side
- ``rules``   — YARA rule source management

``--profile`` decides what runs, ``-v``/``-vv`` decide what prints. Results go
to stdout, diagnostics to stderr, and the exit status is meaningful: 0 clean,
1 threat at or above ``--fail-on``, 2 usage error, 3 runtime error.

Subcommands live in dedicated modules and are registered via ``add_command``
so that nothing in this package imports it back.
"""

import click

#: Single source of truth for the tool version — read by ``pyproject.toml``
#: (``dynamic.version``), the JSON reporter, and the HTML reporter.
__version__ = "0.2.0"

CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 100,
}

__all__ = ["cli", "__version__"]


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=__version__, prog_name="ThreatLens")
def cli() -> None:
    """ThreatLens — static malware analysis with transparent confidence scoring."""


@click.command("analyse", hidden=True)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def _analyse_moved(args: tuple[str, ...]) -> None:
    """Removed — kept only to point older invocations at the new verbs."""
    raise click.UsageError(
        "'analyse' has been split: use 'threatlens scan FILE' for a single file "
        "or 'threatlens triage DIRECTORY' for a directory"
    )


from .compare import compare  # noqa: E402
from .rules import rules  # noqa: E402
from .scan import scan  # noqa: E402
from .triage import triage  # noqa: E402

cli.add_command(scan)
cli.add_command(triage)
cli.add_command(compare)
cli.add_command(rules)
cli.add_command(_analyse_moved)
