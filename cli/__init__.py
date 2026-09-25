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

Design notes
------------
**The subcommand imports sit at the bottom of the file on purpose.** Each
one imports ``cli._console`` and ``cli._helpers``, which are submodules of
this package, so importing them at the top would run those imports while
this module is still half-initialised. Defining :data:`cli` and
``__version__`` first and importing afterwards means the package is
complete by the time anything reaches back into it. The ``E402`` suppressions
mark that as deliberate rather than an oversight.

**``analyse`` is kept as a hidden command that only fails.** Removing it
outright would make an older invocation print Click's generic "no such
command", which does not say where the behaviour went; this exits 2 with
the two verbs that replaced it. ``UNPROCESSED`` so that the arguments of
the old form — paths, flags — are swallowed rather than re-parsed into a
different error about an unknown option.

**``max_content_width`` is 100.** Help output is the one place the tool
does not adapt to the terminal: the option tables are written to line up at
that width, and the values quoted in ``--help`` are chosen to fit it.
"""

import click

#: Single source of truth for the tool version — read by ``pyproject.toml``
#: (``dynamic.version``), the JSON reporter, and the HTML reporter.
__version__ = "0.5.13"

CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 100,
}

__all__ = ["cli", "__version__"]


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=__version__, prog_name="ThreatLens")
def cli() -> None:
    """ThreatLens — static malware analysis with transparent confidence scoring."""
    # Deliberately empty: the group exists to host the four verbs and to
    # carry --version and -h. Any setup done here would run for every
    # subcommand, including the ones that must not touch the config.


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
