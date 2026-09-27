"""Shared containment for the PyInstaller one-file binaries in ``bin/``.

Both external tools ThreatLens shells out to — FLOSS and capa — are
PyInstaller one-file bundles rather than native binaries. Verified: neither
carries a Go section, and each embeds its own interpreter (``libpython3.8``
in FLOSS, ``libpython3.10`` in capa). The bootloader unpacks the whole
application into ``$TMPDIR/_MEIxxxxxx`` at startup and removes it on a clean
exit.

Design notes
------------
The contract this module exists for: **a bundle that is killed never cleans
up after itself.** ``subprocess.run(timeout=...)`` ends a late child with
``Popen.kill()``, which is ``SIGKILL``, and no process can trap that. So the
extraction directory survives the run. Measured against ``bin/floss`` with a
3-second budget: ``TimeoutExpired`` raised and 62.5 MB left behind.

That is not a rare path. ``floss_timeout_seconds`` defaults to 300 because
the slowest corpus sample emulates for 271.1 s, so the budget is genuinely
reachable, and ``triage`` repeats the loss once per file until the disk
fills.

The fix deliberately does **not** try to make the child exit gracefully —
installing a ``SIGTERM`` handler, or escalating TERM-then-KILL, still loses
the race whenever the child is wedged inside the emulator, which is exactly
when a timeout fires. Instead the child is given a private ``TMPDIR`` that
this module owns and removes unconditionally. What the bundle did or did not
manage to clean up stops mattering, and the guarantee holds for a crash, a
kill and an ``OSError`` alike.

Ordering matters at one point only: the directory must be created *before*
``subprocess.run`` and removed *after* it returns or raises. Because
``subprocess.run`` reaps the child before propagating ``TimeoutExpired``,
nothing is still writing into the directory by the time the ``finally``
runs, so the removal cannot race the process it is cleaning up after.

Per design rule 2, failing to create the directory is not allowed to cost
the analysis: the context manager yields ``None``, the caller runs with the
inherited environment, and the only thing lost is the containment that was
absent before this module existed anyway.
"""

import contextlib
import logging
import os
import shutil
import tempfile

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def private_extraction_dir(prefix: str):
    """Yield an environment whose ``TMPDIR`` is a directory we delete.

    Args:
        prefix: Directory-name prefix, used only to make a stray directory
                attributable to a tool if one is ever found on disk.

    Yields:
        A copy of ``os.environ`` with ``TMPDIR`` pointing at a fresh
        directory, suitable for passing straight to ``subprocess.run`` as
        ``env=``. Yields ``None`` instead when the directory could not be
        created, which means "run with the inherited environment".

    Raises:
        Nothing. Exceptions from the caller's body propagate unchanged, but
        the directory is removed first.
    """
    # ------------------------------------------------------------------
    # Create. A failure here is survivable, so it degrades to the old
    # behaviour rather than aborting a scan over a temp directory.
    # ------------------------------------------------------------------
    try:
        tmp_dir = tempfile.mkdtemp(prefix=prefix)
    except OSError as exc:
        logger.warning(
            "could not create a private extraction directory (%s) — "
            "running with the inherited TMPDIR, which may leak on a timeout",
            exc,
        )
        yield None
        return

    # ------------------------------------------------------------------
    # Hand it over, then remove it whatever happened. The env is a copy:
    # mutating os.environ would redirect every other tempfile user in the
    # process, including the archive extractors running in the same scan.
    # ------------------------------------------------------------------
    try:
        env = dict(os.environ)
        env["TMPDIR"] = tmp_dir
        yield env
    finally:
        # ignore_errors because this runs on the exception path too, and
        # design rule 2 forbids a cleanup failure replacing the real cause.
        shutil.rmtree(tmp_dir, ignore_errors=True)
