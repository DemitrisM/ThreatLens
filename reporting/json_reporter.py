"""JSON report generator.

Serialises the full analysis results (file metadata, module outputs,
score breakdown) to a structured JSON document for machine consumption
and pipeline integration.

Two entry points:

- :func:`build_json_report` returns the report as a dict, for callers that
  want to write it themselves — ``-f json`` streams it to stdout, ``-f jsonl``
  writes it as a single compact line.
- :func:`write_json_report` writes a timestamped file into a directory.

Design notes
------------
Every path out of here runs through ``sanitise_secrets`` before anything
is written or returned. That is not belt-and-braces: a VirusTotal result
carries the request that produced it, and this is the format most likely
to be committed to a ticket or a shared drive.

The report is re-keyed rather than passed through. ``run_pipeline``
returns internal bookkeeping alongside the results, so naming the five
keys that belong in a report is what stops an internal field becoming
part of a documented output by accident.

``default=str`` is the only reason ``Path`` and ``set`` values survive
serialisation, and it is passed at every ``json.dumps`` here. A module
returning one of those is not an error — ``file_intake`` returns paths —
so dropping it would turn a working scan into a ``TypeError`` at the last
step, after all the analysis had been paid for.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Sits below `logger` rather than with the imports above it, which is
# only untidy — it is an ordinary module-scope import of a sibling in the
# same package, with no circular-import problem to work around. (The one
# import here that does have one is `cli.__version__`, inside
# `build_json_report`.)
#
# What was here before was a `#:` doc-comment reading "Keys stripped from
# module data before a report leaves the process" — a description of
# `shared.SECRET_KEYS`, a constant this module does not define, attached
# to an import statement. Rule 4: a comment that describes something
# other than the code under it is worse than no comment.
from reporting.shared import sanitise_secrets


def build_json_report(report: dict) -> dict:
    """Return *report* re-keyed, sanitised, and stamped with tool metadata.

    Args:
        report: Complete report dict returned by ``run_pipeline()``.

    Returns:
        A JSON-serialisable dict. Values that ``json`` cannot encode
        natively (``Path``, ``bytes``, ``set``) still rely on the caller
        passing ``default=str``.

    The ``meta`` block is stamped here rather than by each caller so that
    a report read back later can be attributed to a tool version. The
    timestamp is the moment of *serialisation*, not of the scan — the two
    differ by the time the pipeline took, which the ``timing`` key
    already records.
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

    Returns:
        A complete JSON document. Compact output must contain no newline,
        since ``jsonl`` gives one report per line and an embedded newline
        would split one record into two malformed ones — which is also
        why the separators are given explicitly rather than left to the
        default, whose ``", "`` would not break it but wastes bytes on a
        format nothing reads by eye.
    """
    payload = build_json_report(report)
    if compact:
        return json.dumps(payload, separators=(",", ":"), default=str)
    return json.dumps(payload, indent=2, default=str)


def write_json_report(report: dict, output_dir: Path) -> Path:
    """Write the pipeline report to a timestamped JSON file.

    The filename is derived from the analysed file's name and a timestamp
    so that multiple runs never overwrite each other. Second resolution,
    so two scans of one sample inside the same second still collide —
    accepted, because the alternative is a filename an analyst cannot
    read, and the saved-path notice names what was written.

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

    Recursive: a nested ``{"request": {"api_key": ...}}`` used to survive
    because only the top level of ``data`` was filtered.
    """
    return [sanitise_secrets(result) for result in results]
