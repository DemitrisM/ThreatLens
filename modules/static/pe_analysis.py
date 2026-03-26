"""PE file analysis module.

Uses pefile to extract headers, sections with per-section Shannon entropy,
imports/exports, digital signature status, and packer detection.
Returns a standard module result dict with score_delta and reason.
"""
