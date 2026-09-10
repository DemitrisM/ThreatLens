"""stdout capture for third-party imports that print at import time.

``XLMMacroDeobfuscator.deobfuscator`` prints an unconditional
``XLMMacroDeobfuscator: pywin32 is not installed …`` notice to stdout at
module scope, and ``oletools.olevba`` imports it transitively. That notice
would otherwise be the first line of ThreatLens' stdout, corrupting
``-f json`` output.

We fix this at our own import sites rather than patching the virtualenv:
wrap the import in :func:`quiet_stdout` and the captured text is
re-emitted through ``logging`` at DEBUG, where it belongs.

Design notes
------------
This exists to enforce design rule 7 — stdout carries results only — at
the one place the project does not control: third-party module scope.
``threatlens scan … -f json | jq`` is the concrete thing being protected;
one stray notice ahead of the JSON document breaks the pipe, and the
failure looks like a ThreatLens bug rather than an oletools one.

It has to wrap the *import*, not the call. The offending print runs at
module scope, so it fires exactly once, on whichever import happens
first, and nothing at call time can suppress it. Every module in this
package that touches oletools therefore imports through this guard even
when its own library is quiet, because import order across the package
is not fixed and any one of them may be the first to pull the chain in.

Capturing rather than discarding is deliberate: a library that starts
printing something worth reading stays discoverable under ``-vv``.
"""

import contextlib
import io
import logging
from collections.abc import Iterator


@contextlib.contextmanager
def quiet_stdout(logger: logging.Logger, source: str) -> Iterator[None]:
    """Redirect stdout to a buffer for the duration of the block.

    Yields:
        None. Used purely for its side effect on sys.stdout.


    Captured output is logged at DEBUG rather than discarded, so a library
    that starts printing something we care about stays discoverable under
    ``-vv``. Exceptions (notably ``ImportError``) propagate unchanged, and
    the captured text is still logged on that path.

    Args:
        logger: Logger of the calling module, so the DEBUG line is
                attributed to the import site rather than to this helper.
        source: Short label for the captured text, e.g. ``"oletools.olevba"``.
    """
    # The finally block is what makes this safe around an import: an
    # ImportError propagates unchanged to the caller's try/except, and the
    # text the library printed before failing is still logged rather than
    # lost with the exception.
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            yield
    finally:
        chatter = buffer.getvalue().strip()
        if chatter:
            logger.debug("Suppressed import-time stdout from %s: %s", source, chatter)
