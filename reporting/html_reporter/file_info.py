"""File-info block + slimmed module-results rows for the HTML template."""

from pathlib import Path

from reporting.shared import human_size


def file_info(module_results: list[dict], file_path: str) -> dict:
    """Flatten file_intake data into the dict the template expects."""
    intake = next(
        (r for r in module_results if r.get("module") == "file_intake"), None
    )
    fallback = {
        "file_name": Path(file_path).name,
        "file_path": str(file_path),
        "file_size_human": "—",
        "type_description": "Unknown",
        "mime_type": "Unknown",
        "md5": "N/A",
        "sha256": "N/A",
        "tlsh": "",
        "ssdeep": "",
    }
    if not intake or intake.get("status") != "success":
        return fallback

    data = intake.get("data", {}) or {}
    hashes = data.get("hashes", {}) or {}
    ft = data.get("file_type", {}) or {}

    return {
        "file_name": data.get("file_name") or Path(file_path).name,
        "file_path": data.get("file_path") or str(file_path),
        "file_size_human": human_size(data.get("file_size", 0)),
        "type_description": ft.get("description", "Unknown"),
        "mime_type": ft.get("mime_type", "Unknown"),
        "md5": hashes.get("md5") or "N/A",
        "sha256": hashes.get("sha256") or "N/A",
        "tlsh": hashes.get("tlsh") or "",
        "ssdeep": hashes.get("ssdeep") or "",
    }


def module_results_for_template(module_results: list[dict]) -> list[dict]:
    """Slim module results to only the fields the module table needs."""
    return [
        {
            "module": r.get("module", "unknown"),
            "status": r.get("status", "unknown"),
            "score_delta": r.get("score_delta", 0),
            "reason": r.get("reason", ""),
        }
        for r in module_results
    ]
