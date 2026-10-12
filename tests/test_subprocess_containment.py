"""A timeout must bound the child's *running*, not just the parent's waiting.

Why this file exists
--------------------
``subprocess.run(timeout=...)`` enforces a timeout with ``Popen.kill()`` —
SIGKILL to the one process it started. ``bin/capa`` and ``bin/floss`` are
PyInstaller bundles: the executable is a *bootloader* that unpacks itself and
then forks the real application as its own child. The signal reaches the
bootloader and the analysis process is orphaned, reparented to PID 1, and
keeps running with its CPU and whatever file handles it held.

So the timeout that design rule 5 requires bounds how long ThreatLens
*waits*, not how long the sample's analysis *runs*. A sample that makes FLOSS
emulate for 271 seconds still gets its 271 seconds; the tool merely stops
watching. ``triage`` repeats that once per file.

The first test here proves the premise rather than asserting it, so that the
second test is measuring something real. The second is the contract
``core.process.run_contained`` has to meet.

Test hygiene
------------
These tests deliberately start processes designed to outlive their parent, so
every one of them registers a finalizer that kills by recorded pid. A test
file that leaked what it was written to detect would be worse than no test.
"""

import os
import signal
import subprocess
import time

import pytest

#: Long enough that a surviving grandchild is unambiguous, short enough that a
#: leaked one cannot sit on the machine for long if a finalizer ever fails.
GRANDCHILD_LIFETIME = 30

#: The parent waits this long before giving up on the fake tool.
TIMEOUT = 2


def _forking_tool(tmp_path):
    """Write a script that behaves like a PyInstaller bootloader.

    It forks a grandchild that records its own pid and then sleeps, and the
    script itself waits. Killing only the script leaves the grandchild alive,
    which is exactly the bundle behaviour under test.

    Returns:
        ``(script_path, pidfile_path)``. The pidfile holds the grandchild's
        pid once it has started.
    """
    pidfile = tmp_path / "grandchild.pid"
    script = tmp_path / "faketool.sh"
    script.write_text(
        "#!/bin/sh\n"
        # `exec` so the recorded pid is the sleep itself and not a shell that
        # would exit first, leaving the pid pointing at nothing.
        f"sh -c 'echo $$ > {pidfile}; exec sleep {GRANDCHILD_LIFETIME}' &\n"
        "wait\n"
    )
    script.chmod(0o755)
    return script, pidfile


def _alive(pid):
    """Whether `pid` is a live process, without reaping or signalling it."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:          # exists, owned by someone else
        return True
    return True


def _read_pid(pidfile, deadline=5.0):
    """Wait for the grandchild to record its pid, then return it."""
    end = time.time() + deadline
    while time.time() < end:
        if pidfile.exists():
            text = pidfile.read_text().strip()
            if text.isdigit():
                return int(text)
        time.sleep(0.05)
    pytest.fail("the fake tool never recorded a grandchild pid")


@pytest.fixture
def forking_tool(tmp_path, request):
    """A forking fake tool, with a guaranteed kill of whatever it leaves."""
    script, pidfile = _forking_tool(tmp_path)

    def _cleanup():
        if not pidfile.exists():
            return
        text = pidfile.read_text().strip()
        if not text.isdigit():
            return
        try:
            os.kill(int(text), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    request.addfinalizer(_cleanup)
    return script, pidfile


def test_stdlib_run_leaks_a_grandchild_on_timeout(forking_tool):
    """The premise: this is what the call sites do today, and it leaks.

    Not a test of ThreatLens — a test of the behaviour ThreatLens currently
    relies on, kept so the next reader can see that the helper solves a real
    problem rather than a theoretical one. If CPython ever changes this, this
    test fails and the helper's rationale needs rereading.
    """
    script, pidfile = forking_tool

    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run([str(script)], timeout=TIMEOUT)

    pid = _read_pid(pidfile)
    # Give the kernel a moment, so a pass cannot come from merely being early.
    time.sleep(0.5)
    assert _alive(pid), (
        "expected the stdlib behaviour to orphan the grandchild; if this "
        "fails, re-read why core.process.run_contained exists"
    )


def test_run_contained_reaps_the_whole_group_on_timeout(forking_tool):
    """The contract: no member of the group survives the timeout.

    This is the test that must fail before the fix and pass after it.
    """
    from core.process import run_contained

    script, pidfile = forking_tool

    with pytest.raises(subprocess.TimeoutExpired):
        run_contained([str(script)], timeout=TIMEOUT)

    pid = _read_pid(pidfile)
    time.sleep(0.5)
    assert not _alive(pid), f"grandchild {pid} survived the timeout"


# --------------------------------------------------------------------------
# The edge cases, each of which is a way the fix could be wrong while the
# test above still passed.
# --------------------------------------------------------------------------


def test_the_group_is_reaped_even_when_the_leader_exited_first(tmp_path, request):
    """The case that makes an `os.getpgid` lookup the wrong instrument.

    A bootloader that forks and exits immediately leaves a live grandchild
    and a *dead group leader*. `os.getpgid(leader)` then raises
    ProcessLookupError, so an implementation that guarded the lookup would
    skip the kill and leak exactly what it was written to catch. Killing by
    the leader's pid still works, because a process group outlives its
    leader as long as any member remains.

    Note what the group id actually is, because an earlier version of this
    test got it wrong: only the process started with `start_new_session=True`
    calls `setsid`, so **the pgid is the leader's pid**. The grandchild
    merely inherits that group — its own pid is not a group id, and
    `killpg(grandchild_pid)` targets a group that does not exist.
    """
    from core.process import _await_group_exit, _kill_group

    pidfile = tmp_path / "gc.pid"
    script = tmp_path / "exits_first.sh"
    script.write_text(
        "#!/bin/sh\n"
        f"sh -c 'echo $$ > {pidfile}; exec sleep {GRANDCHILD_LIFETIME}' &\n"
        "exit 0\n"
    )
    script.chmod(0o755)

    # Started the same way run_contained starts it, so the leader's pid is
    # the group id — and kept, because that is the value under test.
    proc = subprocess.Popen([str(script)], start_new_session=True)
    leader_pgid = proc.pid

    def _cleanup():
        _kill_group(leader_pgid)
        if pidfile.exists() and pidfile.read_text().strip().isdigit():
            try:
                os.kill(int(pidfile.read_text().strip()), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    request.addfinalizer(_cleanup)

    grandchild = _read_pid(pidfile)
    proc.wait(timeout=10)                  # the leader exits 0 at once
    time.sleep(0.3)

    # The precondition that makes this test worth having.
    assert _alive(grandchild), "the grandchild should outlive the leader"
    with pytest.raises(ProcessLookupError):
        os.getpgid(leader_pgid)            # the leader really is gone

    _kill_group(leader_pgid)
    assert _await_group_exit(leader_pgid, budget=5.0) is True
    assert not _alive(grandchild), "killing by the leader's pid must reach the group"


def test_the_parent_survives_the_group_kill(forking_tool):
    """A pgid mistake would kill the scan itself.

    Killing by `p.pid` under setsid cannot reach us, because we are in a
    different group. A bug that passed the parent's pgid would take the whole
    run down, so this pins that we are still here afterwards.
    """
    from core.process import run_contained

    script, _ = forking_tool
    my_pid, my_pgid = os.getpid(), os.getpgid(0)

    with pytest.raises(subprocess.TimeoutExpired):
        run_contained([str(script)], timeout=TIMEOUT)

    assert os.getpid() == my_pid
    assert os.getpgid(0) == my_pgid, "the parent's process group changed"


def test_partial_output_survives_the_timeout(tmp_path):
    """Output captured before the timeout must still reach the caller.

    Re-reading the streams after the kill would return only bytes that
    arrived afterwards and discard everything before — the regression a
    second `communicate()` would cause.
    """
    from core.process import run_contained

    script = tmp_path / "chatty.sh"
    script.write_text(
        "#!/bin/sh\n"
        "echo BEFORE_TIMEOUT\n"
        f"sleep {GRANDCHILD_LIFETIME}\n"
    )
    script.chmod(0o755)

    with pytest.raises(subprocess.TimeoutExpired) as caught:
        run_contained([str(script)], timeout=TIMEOUT, capture_output=True)

    assert caught.value.output is not None, "partial stdout was discarded"
    assert b"BEFORE_TIMEOUT" in caught.value.output


def test_capture_output_is_translated_rather_than_forwarded():
    """`Popen` rejects `capture_output`; forwarding it would raise TypeError.

    Six of the seven call sites pass it, and they catch only TimeoutExpired
    and OSError — so a TypeError here would kill the scan.
    """
    from core.process import run_contained

    proc = run_contained(["/bin/echo", "hello"], timeout=10, capture_output=True)

    assert proc.returncode == 0
    assert proc.stdout == b"hello\n"
    assert proc.stderr == b""


def test_an_explicit_redirect_beats_capture_output(tmp_path):
    """A caller that redirects on purpose must not be overridden.

    `pdf_analysis` streams its child's stderr to a file precisely so a
    chatty hostile PDF cannot be buffered in the orchestrator.
    """
    from core.process import run_contained

    errfile = tmp_path / "err.log"
    with open(errfile, "wb") as handle:
        proc = run_contained(
            ["/bin/sh", "-c", "echo to_stderr >&2"],
            timeout=10,
            capture_output=True,
            stderr=handle,
        )

    assert proc.stderr is None, "the explicit file redirect was overridden"
    assert b"to_stderr" in errfile.read_bytes()


def test_text_mode_is_forwarded():
    """Three call sites pass `text=True` and index the result as str."""
    from core.process import run_contained

    proc = run_contained(["/bin/echo", "hi"], timeout=10,
                         capture_output=True, text=True)
    assert proc.stdout == "hi\n"


def test_check_raises_like_subprocess_run():
    """`check` is consumed here too, and must behave as advertised."""
    from core.process import run_contained

    with pytest.raises(subprocess.CalledProcessError) as caught:
        run_contained(["/bin/false"], timeout=10, check=True)
    assert caught.value.returncode != 0

    # And the default must not raise on a non-zero exit, since every current
    # call site passes check=False and branches on returncode itself.
    proc = run_contained(["/bin/false"], timeout=10)
    assert proc.returncode != 0


def test_a_missing_tool_still_raises_filenotfound():
    """Two call sites branch on this to report a tool that is not installed."""
    from core.process import run_contained

    with pytest.raises(FileNotFoundError):
        run_contained(["/nonexistent/tool-xyz"], timeout=10)


def test_a_clean_run_is_not_disturbed():
    """The common path: no timeout, no kill, ordinary result."""
    from core.process import run_contained

    proc = run_contained(["/bin/sh", "-c", "exit 3"], timeout=10)
    assert proc.returncode == 3


def test_the_group_wait_reports_failure_instead_of_hanging():
    """An expiring budget must return False, not block.

    The bounded poll is what keeps a failure path from becoming an unbounded
    wait, which rule 5 forbids. Driven against our own live process group,
    which by definition never disappears.
    """
    from core.process import _await_group_exit

    started = time.monotonic()
    result = _await_group_exit(os.getpgid(0), budget=0.3)
    elapsed = time.monotonic() - started

    assert result is False, "our own group cannot have exited"
    assert elapsed < 3.0, f"the bounded wait took {elapsed:.1f}s"


def test_a_missing_timeout_is_refused():
    """`timeout=None` would block forever, so it is rejected not inherited."""
    from core.process import run_contained

    with pytest.raises(ValueError, match="requires a timeout"):
        run_contained(["/bin/true"], timeout=None)


def test_no_descriptors_leak_across_runs():
    """`communicate()` closes the pipes, so no `with Popen` block is needed.

    This matters because adding one would look like a tidy-up and would
    actually reintroduce an unbounded `wait()` on the failure path via
    `Popen.__exit__`. The invariant that makes omitting it safe is pinned
    here so the "fix" is visibly unnecessary.
    """
    import os

    from core.process import run_contained

    def _open_fds():
        return len(os.listdir(f"/proc/{os.getpid()}/fd"))

    baseline = _open_fds()
    for _ in range(20):
        run_contained(["/bin/echo", "x"], timeout=10, capture_output=True)
    assert _open_fds() == baseline, "clean runs leaked descriptors"

    for _ in range(3):
        with pytest.raises(subprocess.TimeoutExpired):
            run_contained(["/bin/sh", "-c", "echo hi; sleep 30"],
                          timeout=1, capture_output=True)
    assert _open_fds() == baseline, "timed-out runs leaked descriptors"


# --------------------------------------------------------------------------
# Every call site must go through the contained runner.
#
# These exist because four of the seven sites — the two cabextract calls,
# pcodedmp and git — had **no** subprocess patches in the suite at all. So a
# migration that missed one, or a later edit that reverted one to
# `subprocess.run`, would leave the orphan behaviour in place with every test
# still green. Asserting on the module attribute is deliberate: it catches a
# reverted call without needing the external tool installed.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module_path",
    [
        "modules.static.capa_analysis",
        "modules.static.string_analysis",
        "modules.static.pdf_analysis",
        "modules.static.archive_analysis.other_handlers",
        "modules.static.doc_analysis.vba_macros",
        "core.rule_updater",
    ],
)
def test_the_module_imports_the_contained_runner(module_path):
    """Each module that launches a tool must hold a reference to it."""
    import importlib

    module = importlib.import_module(module_path)
    assert hasattr(module, "run_contained"), (
        f"{module_path} does not import run_contained, so any "
        f"subprocess.run left in it would orphan a forked child"
    )


def test_no_module_still_calls_subprocess_run():
    """A whole-tree sweep, so a reverted call site cannot hide.

    Parsed rather than grepped: a docstring mentioning `subprocess.run` is
    legitimate and this file's own module docstring does it, so a text search
    would either miss real calls or flag prose.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []

    for path in list((root / "modules").rglob("*.py")) + list((root / "core").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
            ):
                offenders.append(f"{path.relative_to(root)}:{node.lineno}")

    assert offenders == [], (
        "these call sites still use subprocess.run, whose timeout kills only "
        f"the direct child: {offenders}"
    )


def test_git_is_launched_through_the_contained_runner(monkeypatch):
    """`rule_updater` is the one site outside `modules/`, so it is pinned too."""
    from core import rule_updater

    calls = []

    def _fake(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(rule_updater, "run_contained", _fake)
    rule_updater._run_git(["status"])

    assert calls and calls[0][0] == "git"
