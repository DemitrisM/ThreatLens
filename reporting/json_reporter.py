"""JSON report generator.

Serialises the full analysis results (file metadata, module outputs,
score breakdown) to a structured JSON file for machine consumption
and pipeline integration.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def write_json_report(report: dict, output_dir: Path) -> Path:
    """Write the pipeline report to a JSON file.

    The filename is derived from the analysed file's name and a
    timestamp so that multiple runs never overwrite each other.

    Args:
        report:     Complete report dict returned by ``run_pipeline()``.
        output_dir: Directory to write the JSON file into (created if
                    it does not exist).

    Returns:
        Path to the written JSON file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build a safe, descriptive filename.
    source_name = Path(report.get("file", "unknown")).stem
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{source_name}_{timestamp}.json"
    out_path = output_dir / filename

    serialisable = _prepare(report)

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(serialisable, fh, indent=2, default=str)

    logger.info("JSON report written to %s", out_path)
    return out_path


def _prepare(report: dict) -> dict:
    """Return a copy of *report* with a metadata header added.

    Non-serialisable values (Path objects, bytes, etc.) are converted
    to strings by the ``default=str`` fallback in ``json.dump``, so
    this function only needs to add top-level metadata.
    """
    return {
        "meta": {
            "tool": "ThreatLens",
            "version": "0.1.0",
            "generated_utc": datetime.now(tz=timezone.utc).isoformat(),
        },
        "file": report.get("file"),
        "scoring": report.get("scoring"),
        "module_results": report.get("module_results", []),
        "dynamic": report.get("dynamic"),
        "timing": report.get("timing"),
    }
