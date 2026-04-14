"""HTML report generator using Jinja2.

Renders a self-contained HTML report (inline CSS, no external deps)
with summary header, score breakdown, MITRE ATT&CK table, IOC table,
suspicious strings, capa capabilities, VirusTotal results, module
timing, recommendations, and collapsible raw module data sections.

Mirrors the structure and section ordering of the terminal reporter
so the two outputs stay in sync.  Context-building helpers live in
dedicated submodules — this ``__init__.py`` only wires them into the
template render.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from reporting.shared import build_verdict

from .debug import raw_modules
from .doc import doc_indicators
from .file_info import file_info, module_results_for_template
from .findings import capabilities, scored_categories, suspicious_strings, virustotal
from .pe import pe_indicators
from .recommendations import recommendations
from .tables import attack_mappings, ioc_total, iocs_flat, timing_rows

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_TEMPLATE_NAME = "report.html.j2"
_TOOL_VERSION = "0.2.0"


def write_html_report(report: dict, output_dir: Path) -> Path:
    """Render *report* as a self-contained HTML file in *output_dir*.

    Args:
        report:     Complete report dict returned by ``run_pipeline()``.
        output_dir: Directory to write the HTML file into (created if
                    it does not exist).

    Returns:
        Path to the written HTML file.

    Raises:
        ImportError: If Jinja2 is not installed.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:
        logger.error("jinja2 not installed — cannot generate HTML report")
        raise ImportError(
            "jinja2 is required for HTML reports. Install with: pip install jinja2"
        ) from exc

    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2", "html.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(_TEMPLATE_NAME)

    context = _build_context(report)
    html = template.render(**context)

    source_name = Path(report.get("file", "unknown")).stem
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = output_dir / f"{source_name}_{timestamp}.html"

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info("HTML report written to %s", out_path)
    return out_path


def _build_context(report: dict) -> dict:
    """Translate the raw pipeline report into the template context dict."""
    module_results = report.get("module_results", [])
    scoring = report.get("scoring", {}) or {}
    timing = report.get("timing", {}) or {}
    file_path = report.get("file", "unknown")

    return {
        "tool_version": _TOOL_VERSION,
        "generated_utc": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "elapsed_seconds": timing.get("elapsed_seconds", 0.0),
        "file_name": Path(file_path).name,

        "file_info": file_info(module_results, file_path),
        "scoring": scoring,
        "verdict": build_verdict(module_results, scoring),
        "module_results": module_results_for_template(module_results),
        "pe_indicators": pe_indicators(module_results),
        "doc_indicators": doc_indicators(module_results),

        "attack_mappings": attack_mappings(module_results),
        "iocs_flat": iocs_flat(module_results),
        "ioc_total": ioc_total(module_results),
        "suspicious_strings": suspicious_strings(module_results),
        "capabilities": capabilities(module_results),
        "scored_categories": scored_categories(module_results),
        "virustotal": virustotal(module_results),
        "timing_rows": timing_rows(module_results),
        "recommendations": recommendations(module_results, scoring),
        "raw_modules": raw_modules(module_results),
    }


__all__ = ["write_html_report"]
