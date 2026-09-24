"""Rich spinner progress-callback factory for the analysis pipeline.

The pipeline reports progress through a plain callable rather than owning a
widget, so that the only code that knows rich exists is this file and the
reporters. A library caller passes ``progress_cb=None`` and gets silence.

Design notes
------------
The spinner is **stderr-bound and conditional**. It draws on ``err`` because
stdout carries results, and a rich ``Live`` writing there would corrupt
``-f json`` piped into ``jq``; the caller additionally gates the whole thing
on ``err.is_terminal``, so a redirected stderr gets no escape sequences
either. ``transient=True`` erases the spinner line when it stops, leaving the
report as the first thing on the terminal.

Construction starts the ``Live`` immediately, which makes the returned
``finalise`` mandatory rather than optional: the caller must invoke it in a
``finally``, or a pipeline exception leaves the cursor hidden and the render
thread running. That is a deliberate trade — starting lazily on the first
callback would leave the common no-module-ran path with nothing to stop, and
an unbalanced start is the more visible failure of the two.

Only the ``"start"`` event is rendered. ``"done"`` arrives with the same
index, so acting on it would either repaint an identical line or blank the
spinner between modules; the last module therefore reads as "Running" until
the pipeline returns, which is accurate — it is still running.

The rich imports are function-local on purpose. Importing rich costs tens of
milliseconds, and ``--hash-only`` with a redirected stderr never needs it.
"""


def _make_progress_cb(show: bool):
    """Build the pipeline's progress callback and its matching teardown.

    Args:
        show: False produces a no-op pair, for a non-terminal stderr or a
              caller that wants silence. Nothing is imported or started in
              that case.

    Returns:
        A ``(progress_cb, finalise)`` pair. ``progress_cb`` matches the
        pipeline's ``(index, total, name, event)`` contract; ``finalise``
        stops the live display and **must** be called in a ``finally``,
        since the display is already running when this returns.
    """
    if not show:
        return None, lambda: None

    # ── Deferred imports ────────────────────────────────────────────────
    # Only reached when a spinner will actually be drawn, so the import
    # cost lands on interactive runs rather than on piped ones.
    from rich.live import Live  # noqa: PLC0415
    from rich.spinner import Spinner  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    from ._console import err  # noqa: PLC0415

    # The initial text matters: the first module can take seconds (capa,
    # a large archive), and a spinner with no label reads as a hang.
    spinner = Spinner("dots", text="Initialising…", style="cyan")
    live = Live(spinner, console=err, refresh_per_second=10, transient=True)
    live.start()

    import time as _time  # noqa: PLC0415
    _start = _time.time()

    def _cb(idx: int, total: int, name: str, event: str) -> None:
        if event == "start":
            # Elapsed is whole-run, not per-module: the question a user
            # asks a spinner is how long this scan has been going, and a
            # per-module timer resets to zero exactly when a slow module
            # begins, which is the moment it is least reassuring.
            elapsed = _time.time() - _start
            txt = Text.assemble(
                (f"[{idx + 1}/{total}] ", "bold cyan"),
                ("Running ", "dim"),
                (name, "bold"),
                (f"  ({elapsed:.0f}s elapsed)", "dim"),
            )
            spinner.update(text=txt)

    def _fin() -> None:
        live.stop()

    return _cb, _fin
