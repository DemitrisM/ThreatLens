"""Finding and containing the two external tools ThreatLens shells out to.

Two concerns, both belonging to "how do we invoke FLOSS and capa":

``resolve_tool`` finds the executable. ``private_extraction_dir`` contains
what it leaves behind.

The tools can arrive two ways, and both must keep working. Historically they
were **PyInstaller one-file bundles** placed by hand in ``bin/`` — a Python
program plus its own private interpreter (``libpython3.8`` in FLOSS,
``libpython3.10`` in capa; neither is the 3.12 this project runs on). From
0.6.0 they are also installable from PyPI as ``flare-floss`` and
``flare-capa``, which put ordinary console scripts on ``PATH``. Same tools,
same versions, different delivery.

Design notes
------------
**Resolution is security-relevant, which is why it lives in one function.**
A configured value with no path separator is a *command name* and is looked
up with ``shutil.which`` only — never with ``Path(name).exists()``. The
reason is concrete: the container sets its working directory to the folder of
samples under analysis, so a sample named ``capa`` sitting there would
satisfy an existence check against the CWD and ThreatLens would execute the
malware instead of the tool. A name is not a path.

**Containment exists because a killed bundle never cleans up after itself.**
``subprocess.run(timeout=...)`` ends a late child with
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
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_tool(name: str | None) -> Path | None:
    """Resolve a configured tool setting to an executable path.

    Args:
        name: The configured value — either a command name to look up on
              ``PATH`` (``"capa"``) or a path to use directly
              (``"./bin/capa"``). ``None`` or empty means unconfigured.

    Returns:
        The resolved path, or ``None`` when nothing usable was found. The
        caller is expected to treat ``None`` as a graceful skip per design
        rule 2, never as an error.

    Raises:
        Nothing.
    """
    if not name:
        return None

    # Coerce before inspecting. This value comes from config.yaml, so YAML
    # decides its type: `capa_binary: true` arrives as a bool and
    # `capa_binary: 123` as an int, and both make the separator test below
    # raise `TypeError: argument of type 'bool' is not iterable`. That would
    # kill the pipeline over a typo, which design rule 2 forbids. A
    # non-string cannot name a tool, so treating it as unset and letting the
    # caller skip is the correct outcome for a misconfiguration.
    if not isinstance(name, str):
        logger.warning(
            "tool setting is %s, not a string — treating it as unset",
            type(name).__name__,
        )
        return None

    # A separator makes it a path, and a path is checked directly so that a
    # hand-placed ./bin/capa keeps working after the PyPI move.
    separators = [os.sep] + ([os.altsep] if os.altsep else [])
    if any(s in name for s in separators):
        candidate = Path(name)
        # is_file(), not exists(): a directory of that name is not a tool,
        # and subprocess would fail with a confusing EACCES/EISDIR later.
        if not candidate.is_file():
            return None
        # Absolute, so what will actually be executed is unambiguous and can
        # be logged as one string. It also means a later change of working
        # directory cannot redirect an already-resolved tool.
        return candidate.resolve()

    # No separator: a command name. shutil.which searches PATH and, on
    # POSIX, does NOT consult the working directory — which is the whole
    # point. Never substitute an existence check here; see Design notes.
    found = shutil.which(name)
    return Path(found).resolve() if found else None


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
