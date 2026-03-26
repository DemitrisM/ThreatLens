"""Analysis pipeline orchestrator.

Discovers and runs enabled analysis modules in sequence (or parallel),
collects their standardised result dicts, feeds them to the scoring
engine, and passes everything to the selected reporter.
"""
