"""JSON report generator.

Serialises the full analysis results (file metadata, module outputs,
score breakdown) to a structured JSON document for machine consumption
and pipeline integration.

Two entry points:

- :func:`build_json_report` returns the report as a dict, for callers that
  want to write it themselves — ``-f json`` streams it to stdout, ``-f jsonl``
  writes it as a single compact line.
- :func:`write_json_report` writes a timestamped file into a directory.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

#: Keys stripped from module data before a report leaves the process.
_SENSITIVE_KEYS = frozenset({"api_key", "virustotal_api_key"})


def build_json_report(report: dict) -> dict:
    """Return *report* re-keyed, sanitised, and stamped with tool metadata.

    Args:
        report: Complete report dict returned by ``run_pipeline()``.

    Returns:
        A JSON-serialisable dict. Values that ``json`` cannot encode
        natively (``Path``, ``bytes``, ``set``) still rely on the caller
        passing ``default=str``.
    """
    from cli import __version__  # noqa: PLC0415  (avoids a circular import at module scope)

    return {
        "meta": {
            "tool": "ThreatLens",
            "version": __version__,
            "generated_utc": datetime.now(tz=timezone.utc).isoformat(),
        },
        "file": report.get("file"),
        "scoring": report.get("scoring"),
        "module_results": _sanitise_results(report.get("module_results", [])),
        "dynamic": report.get("dynamic"),
        "timing": report.get("timing"),
    }


def dumps_json_report(report: dict, *, compact: bool = False) -> str:
    """Serialise *report* to a JSON string.

    Args:
        report:  Complete report dict returned by ``run_pipeline()``.
        compact: When True, emit a single line with no indentation — the
                 ``jsonl`` format, one report per line.
    """
    payload = build_json_report(report)
    if compact:
        return json.dumps(payload, separators=(",", ":"), default=str)
    return json.dumps(payload, indent=2, default=str)


def write_json_report(report: dict, output_dir: Path) -> Path:
    """Write the pipeline report to a timestamped JSON file.

    The filename is derived from the analysed file's name and a timestamp
    so that multiple runs never overwrite each other.

    Args:
        report:     Complete report dict returned by ``run_pipeline()``.
        output_dir: Directory to write the JSON file into (created if it
                    does not exist).

    Returns:
        Path to the written JSON file.

    Raises:
        OSError: If the directory cannot be created or the file written.
                 Callers in ``cli/`` translate this into exit code 3.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    source_name = Path(report.get("file", "unknown")).stem
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = output_dir / f"{source_name}_{timestamp}.json"

    out_path.write_text(dumps_json_report(report), encoding="utf-8")

    logger.info("JSON report written to %s", out_path)
    return out_path


def _sanitise_results(results: list[dict]) -> list[dict]:
    """Strip credentials from module results before serialisation.

    Only the top level of each module's ``data`` dict is filtered — Pass 5
    of the CLI redesign makes this recursive.
    """
    sanitised = []
    for result in results:
        r = dict(result)
        data = r.get("data")
        if isinstance(data, dict):
            r["data"] = {k: v for k, v in data.items() if k not in _SENSITIVE_KEYS}
        sanitised.append(r)
    return sanitised
