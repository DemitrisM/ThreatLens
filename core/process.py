"""Run an external tool so that its timeout bounds the work, not the wait.

Why this exists
---------------
``subprocess.run(timeout=...)`` enforces a timeout by calling
``Popen.kill()`` — SIGKILL to the single process it started. That is enough
for a tool that is one process, and wrong for one that forks.

``bin/capa`` and ``bin/floss`` are PyInstaller bundles: the executable is a
*bootloader* which unpacks itself and then forks the real application as its
own child. The signal reaches the bootloader; the analysis process is
orphaned, reparented to PID 1, and keeps running. Measured: one ``floss``
left at 100% CPU for ~10 s after a timeout, and before the private-TMPDIR fix
it could have run to completion — up to the 271 s a real corpus sample
emulates for.

So the timeout design rule 5 requires was bounding how long ThreatLens
*waited*, not how long the sample's analysis *ran*, and ``triage`` repeated
the loss once per file.

Design notes
------------
**The child gets its own session, and that is the whole mechanism.**
``start_new_session=True`` makes the child call ``setsid()``, so it becomes
the leader of a new process group whose id is exactly its pid. Every process
it forks inherits that group, so one ``killpg`` reaches the bootloader and
the payload together.

**The group id is never looked up.** Under ``setsid`` the pgid is known to
equal ``p.pid``, so ``os.getpgid(p.pid)`` would be redundant — and actively
harmful: if the leader has already exited while grandchildren are still
running, the lookup raises ``ProcessLookupError``, a guard around it skips
the kill, and the orphans this module exists to reap survive untouched. A
process *group* lives as long as any member does, so killing by ``p.pid``
works precisely where the lookup fails.

**Waiting on the child is not waiting on the group.** ``Popen.wait()`` and
``communicate()`` call ``waitpid(p.pid)`` and so reap only the immediate
child; a grandchild reparented to PID 1 cannot be waited on from here at all.
Signal delivery is asynchronous, so ``wait()`` returns the moment the
bootloader dies while its children may still be terminating. That window
matters because ``_bundled_tool.private_extraction_dir`` removes the
extraction directory as soon as control returns, and a grandchild still
holding files open in that tree makes the removal race a live writer. Hence
:func:`_await_group_exit`, which polls the *group* with signal 0 until it is
gone.

**A zombie is not a live member.** ``killpg(pgid, 0)`` succeeds for a
process that is dead but unreaped, and inside the image PID 1 is the analysis
process rather than an init — ``/proc/1/comm`` reads ``python`` — so nothing
reaps a grandchild whose parent was just killed. Counting those as alive made
every containerised timeout burn the whole grace budget and log a warning
about a race that was not happening. :func:`_group_has_live_members` reads
``/proc`` to tell the difference.

**That poll is bounded, and the trade is deliberate.** Rule 5 forbids an
unbounded wait anywhere, including on a failure path. If the budget expires
with members still alive — realistically, uninterruptible sleep on I/O — this
module logs and returns. A bounded race on ``rmtree`` is strictly better than
hanging the scan, and the caller removes the directory with
``ignore_errors=True``, so the worst case is a leftover directory rather than
an exception.

**``capture_output`` and ``check`` are consumed here, not forwarded.** Both
are :func:`subprocess.run` parameters and ``Popen`` rejects them outright
(``Popen.__init__() got an unexpected keyword argument 'capture_output'``).
Six of the seven call sites pass ``capture_output=True``, and forwarding it
blind would raise ``TypeError`` inside modules that catch only
``TimeoutExpired`` and ``OSError`` — an unhandled exception killing the scan,
which is design rule 2 breached by the function meant to enforce rule 5.

**Do not wrap the child in ``with Popen(...)``, even though
:func:`subprocess.run` does.** ``Popen.__exit__`` closes the three streams
and then calls ``self.wait()`` with **no timeout**, which would put an
unbounded wait back on the failure path — the precise thing rule 5 forbids
and this module exists to remove. The streams do not leak without it:
measured on this machine, 50 clean runs and 5 timed-out runs with
``capture_output=True`` each left the process's open-descriptor count
unchanged, because ``communicate()`` closes what it opened on both paths.

**Partial output is never re-read.** On POSIX, ``communicate(timeout=...)``
has already attached whatever it captured to the ``TimeoutExpired`` it
raises; CPython's own ``subprocess.run`` relies on this and calls
``process.wait()`` rather than ``communicate()`` after the kill. Calling
``communicate()`` a second time would return only the bytes that arrived
*after* the timeout and discard everything before it.
"""

import logging
import os
import signal
import subprocess
import time

logger = logging.getLogger(__name__)

#: Seconds allowed for a SIGKILLed group to actually disappear, and
#: separately for the leader to be reaped. Short because SIGKILL cannot be
#: trapped: anything still alive after this is blocked in the kernel, which
#: more waiting will not fix.
_GRACE_SECONDS = 5.0

#: Gap between group-existence probes. Small enough that the common case
#: (everything dies at once) costs one sleep, large enough not to spin.
_POLL_SECONDS = 0.05


def _kill_group(pid: int) -> None:
    """SIGKILL the process group led by `pid`, tolerating its absence.

    Args:
        pid: The direct child's pid, which under ``start_new_session=True``
             is also its process-group id.

    Raises:
        Nothing. A group that has already gone is the success case, not an
        error — and the guard is around the ``killpg`` itself rather than a
        pgid lookup, deliberately: see the module docstring.
    """
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError) as exc:
        # ProcessLookupError: nothing left in the group. PermissionError
        # should be impossible for a group we created, and is tolerated
        # rather than raised because failing to clean up must not become a
        # second failure on top of the timeout that got us here.
        logger.debug("killpg(%d) did not apply: %s", pid, exc)


def _group_has_live_members(pgid: int) -> bool:
    """Whether `pgid` contains any process that is not already a zombie.

    Args:
        pgid: The process-group id to inspect.

    Returns:
        True if at least one member is in a state other than ``Z``. False if
        the group is empty or holds nothing but zombies.

    Why this is needed, and it is specific to the container
    ------------------------------------------------------
    ``os.killpg(pgid, 0)`` succeeds for a **zombie**, because a zombie is
    still a process-table entry until somebody reaps it. On a normal host
    that barely matters: the orphan reparents to init, which reaps it within
    milliseconds. Inside the image it matters a great deal, because PID 1 is
    the analysis process itself rather than an init — measured, ``/proc/1/comm``
    reads ``python`` — so nothing reaps a grandchild whose parent we just
    killed, and it stays a zombie indefinitely.

    Without this check the existence probe therefore never goes false in the
    container, :func:`_await_group_exit` burns its entire budget on every
    timeout, and it logs a warning about a race that is not happening. The
    processes are dead; only their table entries remain, and a zombie holds
    no file handles, so it cannot interfere with the directory removal this
    wait exists to protect.

    Reads ``/proc`` directly because there is no portable call for "list the
    members of a process group". Linux-only, which this project already is.
    """
    try:
        pids = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        # No /proc to read. Fall back to assuming the group is live, which
        # is the conservative answer: it costs a wait, not a wrong result.
        return True

    for entry in pids:
        try:
            with open(f"/proc/{entry}/stat", "rb") as handle:
                fields = handle.read().split()
        except (OSError, ValueError):
            continue            # exited between listdir and open

        # Field layout: pid (comm) state ppid pgrp ... — and `comm` can
        # contain spaces and parentheses, so the fields after it are located
        # from the LAST ')' rather than by splitting from the left.
        try:
            raw = b" ".join(fields)
            tail = raw[raw.rindex(b")") + 2:].split()
            state, pgrp = tail[0], int(tail[2])
        except (ValueError, IndexError):
            continue

        if pgrp == pgid and state != b"Z":
            return True

    return False


def _await_group_exit(pgid: int, budget: float = _GRACE_SECONDS) -> bool:
    """Wait until no process remains in `pgid`, or the budget expires.

    Args:
        pgid:   The process-group id to watch.
        budget: Seconds to wait before giving up.

    Returns:
        True if the group is gone, False if the budget expired with members
        still alive. The caller decides what to do about False; this function
        never raises and never waits longer than `budget`.

    Signal 0 is an existence check rather than a signal, so this observes the
    group without disturbing it. It is the only way to wait on grandchildren,
    which ``waitpid`` cannot see.
    """
    deadline = time.monotonic() + budget
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True                      # group gone entirely
        except PermissionError:
            pass                             # exists, not ours — treat as there

        # The group still has an entry, but entries are not necessarily live
        # processes: see _group_has_live_members. Zombies cannot hold a file
        # open, so they do not threaten what this wait protects.
        if not _group_has_live_members(pgid):
            return True

        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)


def _tear_down(proc: subprocess.Popen) -> None:
    """Kill the child's whole group and wait for it to be gone.

    Args:
        proc: The child, which leads its own group.

    Ordering is the point of this function and is not interchangeable:
    kill the group, reap the direct child so it is not left a zombie, then
    wait for the *group* — because reaping the child says nothing about its
    descendants.
    """
    _kill_group(proc.pid)

    try:
        proc.wait(timeout=_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        # SIGKILLed and still not reaped means the kernel is holding it, most
        # likely uninterruptible sleep. Nothing further to try here.
        logger.warning(
            "child %d did not exit within %.0fs of SIGKILL", proc.pid, _GRACE_SECONDS
        )

    if not _await_group_exit(proc.pid):
        # Said out loud rather than swallowed: the caller is about to remove a
        # directory that something in this group may still be writing to.
        logger.warning(
            "process group %d still had members after %.0fs — a scratch "
            "directory removal may race them",
            proc.pid,
            _GRACE_SECONDS,
        )


def run_contained(
    argv,
    *,
    timeout,
    capture_output: bool = False,
    check: bool = False,
    **popen_kwargs,
) -> subprocess.CompletedProcess:
    """Run `argv` so a timeout kills everything it forked.

    A drop-in for :func:`subprocess.run` for the subset of its interface this
    project uses, differing in one respect: when the timeout fires, the
    child's entire process group is killed and waited for, rather than only
    the direct child.

    Args:
        argv:           The command, as a list. Never a string, and never
                        with ``shell=True`` — several call sites build this
                        from config values.
        timeout:        Seconds to allow before killing the group.
        capture_output: As ``subprocess.run``: sets both streams to pipes.
                        Consumed here because ``Popen`` rejects it. An
                        explicit ``stdout``/``stderr`` in `popen_kwargs`
                        wins, which is what lets a caller stream a child's
                        stderr to a file instead of buffering it.
        check:          As ``subprocess.run``: raise
                        :class:`subprocess.CalledProcessError` on a non-zero
                        exit. Consumed here for the same reason.
        **popen_kwargs: Passed through to :class:`subprocess.Popen` —
                        ``cwd``, ``env``, ``text``, ``stdin``, ``stdout``,
                        ``stderr``.

    Returns:
        A :class:`subprocess.CompletedProcess`.

    Raises:
        subprocess.TimeoutExpired: The original exception from
            ``communicate``, with the output captured before the timeout
            still attached — re-raised bare so callers' existing handlers are
            unaffected.
        subprocess.CalledProcessError: Only when `check` is true.
        OSError: From ``Popen`` itself, including the ``FileNotFoundError``
            that two call sites branch on to report a missing tool.
    """
    # ------------------------------------------------------------------
    # Step 1: translate the run()-only arguments, then start the child in
    # its own session so that one signal can reach everything it forks.
    # ------------------------------------------------------------------
    # A missing budget would make `communicate` block forever, which is the
    # failure this module exists to prevent — so it is refused rather than
    # accepted and quietly inherited. Every call site passes a number.
    if timeout is None:
        raise ValueError("run_contained requires a timeout; None would wait forever")

    if capture_output:
        # setdefault, not assignment: an explicit redirect is a deliberate
        # choice by the caller and must not be overridden.
        popen_kwargs.setdefault("stdout", subprocess.PIPE)
        popen_kwargs.setdefault("stderr", subprocess.PIPE)

    proc = subprocess.Popen(argv, start_new_session=True, **popen_kwargs)

    # ------------------------------------------------------------------
    # Step 2: wait, and on any way out other than a clean return, take the
    # whole group down with us.
    #
    # BaseException rather than Exception, because KeyboardInterrupt is the
    # case that matters most: start_new_session detaches the child from the
    # terminal's foreground group, so Ctrl-C no longer reaches it. Without
    # this branch the fix would trade orphans-on-timeout for
    # orphans-on-Ctrl-C.
    # ------------------------------------------------------------------
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except BaseException:
        _tear_down(proc)
        raise

    # ------------------------------------------------------------------
    # Step 3: the run() return contract.
    # ------------------------------------------------------------------
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, argv, output=stdout, stderr=stderr
        )

    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)
