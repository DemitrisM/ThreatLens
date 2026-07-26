"""Rich spinner progress-callback factory for the analysis pipeline."""


def _make_progress_cb(show: bool):
    """Return a (progress_cb, finalise) pair.

    ``progress_cb`` is passed to the pipeline; ``finalise()`` must be
    called after the pipeline returns to stop the spinner.
    """
    if not show:
        return None, lambda: None

    from rich.live import Live  # noqa: PLC0415
    from rich.spinner import Spinner  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    from ._console import err  # noqa: PLC0415

    spinner = Spinner("dots", text="Initialising…", style="cyan")
    live = Live(spinner, console=err, refresh_per_second=10, transient=True)
    live.start()

    import time as _time  # noqa: PLC0415
    _start = _time.time()

    def _cb(idx: int, total: int, name: str, event: str) -> None:
        if event == "start":
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
