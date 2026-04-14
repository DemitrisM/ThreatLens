"""ThreatLens header banner, file-information table, and run footer."""

from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reporting.shared import human_size

from ._common import console


def print_header() -> None:
    title = Text("ThreatLens", style="bold cyan")
    subtitle = Text("  Static Malware Analysis  ", style="dim")
    console.print()
    console.print(Panel(title + subtitle, style="cyan", padding=(0, 2)))


def print_file_info(module_results: list[dict], file_path: str) -> None:
    """Print file metadata from the file_intake module result."""
    intake = next(
        (r for r in module_results if r.get("module") == "file_intake"), None
    )

    table = Table(
        title="[bold]File Information[/bold]",
        box=box.ROUNDED,
        show_header=False,
        padding=(0, 1),
    )
    table.add_column("Key", style="bold dim", no_wrap=True)
    table.add_column("Value", overflow="fold")

    if intake and intake.get("status") == "success":
        data = intake.get("data", {})
        hashes = data.get("hashes", {})
        ft = data.get("file_type", {})

        table.add_row("File", data.get("file_name", Path(file_path).name))
        table.add_row("Path", data.get("file_path", file_path))
        table.add_row("Size", human_size(data.get("file_size", 0)))
        table.add_row("Type", ft.get("description", "Unknown"))
        table.add_row("MIME", ft.get("mime_type", "Unknown"))
        table.add_row("MD5", hashes.get("md5") or "N/A")
        table.add_row("SHA256", hashes.get("sha256") or "N/A")
        if hashes.get("tlsh"):
            table.add_row("TLSH", hashes["tlsh"])
        if hashes.get("ssdeep"):
            table.add_row("ssdeep", hashes["ssdeep"])
    else:
        table.add_row("File", Path(file_path).name)
        table.add_row("Path", str(file_path))
        if intake and intake.get("status") == "error":
            table.add_row("[red]Error[/red]", intake.get("reason", "File intake failed"))

    console.print()
    console.print(table)


def print_footer(timing: dict) -> None:
    elapsed = timing.get("elapsed_seconds")
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    parts = [f"[dim]Analysis complete[/dim]  [dim]{ts}[/dim]"]
    if elapsed is not None:
        parts.append(f"  [dim]({elapsed:.2f}s)[/dim]")
    console.print()
    console.print("".join(parts))
    console.print()
