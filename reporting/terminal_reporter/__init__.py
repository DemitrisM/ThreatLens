"""Terminal report generator using ``rich``.

Displays colour-coded threat scores, formatted tables for IOCs and
MITRE ATT&CK mappings, a human-readable score breakdown, and the
PE/Office structural indicator panels.  Section printers live in
dedicated submodules — this ``__init__.py`` only orchestrates the
call order.
"""

import logging

from .archive import print_archive_indicators
from .doc import print_doc_indicators
from .findings import print_capabilities, print_suspicious_strings, print_virustotal
from .header import print_file_info, print_footer, print_header
from .onenote import print_onenote_indicators
from .pe import print_pe_indicators
from .recommendations import print_recommendations
from .score import print_module_table, print_score_banner, print_score_breakdown
from .tables import print_attack_table, print_ioc_table, print_timing_table

logger = logging.getLogger(__name__)


def print_terminal_report(report: dict, *, detail_level: int = 0) -> None:
    """Render a complete threat report to the terminal using rich.

    Args:
        report:       Complete report dict returned by ``run_pipeline()``.
        detail_level: 0 = summary, 1 = expanded (-v), 2 = full (--debug).
    """
    scoring = report.get("scoring", {})
    module_results = report.get("module_results", [])
    timing = report.get("timing", {})
    file_path = report.get("file", "unknown")

    print_header()
    print_file_info(module_results, file_path)
    print_score_banner(scoring, module_results)
    print_module_table(module_results, file_path)

    if scoring.get("breakdown"):
        print_score_breakdown(scoring["breakdown"])

    print_pe_indicators(module_results, detail_level)
    print_doc_indicators(module_results, detail_level)
    print_archive_indicators(module_results, detail_level)
    print_onenote_indicators(module_results, detail_level)
    print_attack_table(module_results, detail_level)
    print_ioc_table(module_results, detail_level)
    print_suspicious_strings(module_results, detail_level)
    print_capabilities(module_results, detail_level)
    print_virustotal(module_results, detail_level)

    if detail_level >= 1:
        print_timing_table(module_results, timing)

    print_recommendations(module_results, scoring, file_path)
    print_footer(timing)


__all__ = ["print_terminal_report"]
