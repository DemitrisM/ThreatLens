"""stdout capture for third-party imports that print at import time.

``XLMMacroDeobfuscator.deobfuscator`` prints an unconditional
``XLMMacroDeobfuscator: pywin32 is not installed …`` notice to stdout at
module scope, and ``oletools.olevba`` imports it transitively. That notice
would otherwise be the first line of ThreatLens' stdout, corrupting
``-f json`` output.

We fix this at our own import sites rather than patching the virtualenv:
wrap the import in :func:`quiet_stdout` and the captured text is
re-emitted through ``logging`` at DEBUG, where it belongs.
"""

import contextlib
import io
import logging
from collections.abc import Iterator


@contextlib.contextmanager
def quiet_stdout(logger: logging.Logger, source: str) -> Iterator[None]:
    """Redirect stdout to a buffer for the duration of the block.

    Captured output is logged at DEBUG rather than discarded, so a library
    that starts printing something we care about stays discoverable under
    ``-vv``. Exceptions (notably ``ImportError``) propagate unchanged, and
    the captured text is still logged on that path.

    Args:
        logger: Logger of the calling module.
        source: Short label for the captured text, e.g. ``"oletools.olevba"``.
    """
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            yield
    finally:
        chatter = buffer.getvalue().strip()
        if chatter:
            logger.debug("Suppressed import-time stdout from %s: %s", source, chatter)
