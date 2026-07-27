"""Terminal report generator using ``rich``.

Displays colour-coded threat scores, formatted tables for IOCs and
MITRE ATT&CK mappings, a human-readable score breakdown, and the
PE/Office structural indicator panels.  Section printers live in
dedicated submodules — this ``__init__.py`` only orchestrates the
call order.

Three detail levels, and they are genuinely different:

===== ================================================================
Level Adds
===== ================================================================
0     Everything an analyst needs to triage: score bar, verdict,
      FINDINGS, indicator tables, members and hashes in full, IOCs,
      strings, recommendations.
1     Per-module timing, the full module table including skipped
      modules, ``info``-severity indicator rows, and every cap lifted.
2     Raw per-module JSON and untruncated reasons.
===== ================================================================
"""

import logging
from datetime import datetime

from rich.console import Console

from ._common import use_console
from .archive import print_archive_indicators
from .doc import print_doc_indicators
from .findings import print_capabilities, print_suspicious_strings, print_virustotal
from .header import print_file_info, print_footer, print_header
from .lnk import print_lnk_indicators
from .onenote import print_onenote_indicators
from .pdf import print_pdf_indicators
from .pe import print_pe_indicators
from .raw import print_raw_modules
from .recommendations import print_recommendations
from .score import (
    print_findings,
    print_module_errors,
    print_module_strip,
    print_module_table,
    print_score_banner,
)
from .tables import print_attack_table, print_ioc_table, print_timing_table
from .web import print_html_indicators

logger = logging.getLogger(__name__)


def print_terminal_report(
    report: dict,
    *,
    detail_level: int = 0,
    console: Console | None = None,
    now: datetime | None = None,
) -> None:
    """Render a complete threat report to the terminal using rich.

    Args:
        report:       Complete report dict returned by ``run_pipeline()``.
        detail_level: 0 = summary, 1 = expanded (-v), 2 = full (-vv).
        console:      Console to render to. Defaults to the package
                      singleton; tests inject a pinned one so output is
                      reproducible.
        now:          Frozen clock for the footer timestamp. Tests pass
                      this so snapshots do not change every second.
    """
    scoring = report.get("scoring", {})
    module_results = report.get("module_results", [])
    timing = report.get("timing", {})
    file_path = report.get("file", "unknown")

    with use_console(console):
        print_header()
        print_file_info(module_results, file_path)

        print_score_banner(scoring, module_results)
        print_findings(scoring, module_results, detail_level)

        # A module that crashed is never hidden — an error is not a clean
        # result, and at detail 0 the strip alone would not say so.
        print_module_errors(module_results)

        print_pe_indicators(module_results, detail_level)
        print_doc_indicators(module_results, detail_level)
        print_archive_indicators(module_results, detail_level)
        print_onenote_indicators(module_results, detail_level)
        print_lnk_indicators(module_results, detail_level)
        print_html_indicators(module_results, detail_level)
        print_pdf_indicators(module_results, detail_level)
        print_attack_table(module_results, detail_level)
        print_ioc_table(module_results, detail_level)
        print_suspicious_strings(module_results, detail_level)
        print_capabilities(module_results, detail_level)
        print_virustotal(module_results, detail_level)

        if detail_level >= 1:
            print_module_table(module_results, detail_level)
            print_timing_table(module_results, timing)
        else:
            print_module_strip(module_results)

        print_recommendations(module_results, scoring, file_path)

        if detail_level >= 2:
            print_raw_modules(module_results)

        print_footer(timing, now=now)


__all__ = ["print_terminal_report"]
