"""Capability detection module using Mandiant capa.

Invokes capa via subprocess, parses the JSON output to extract detected
capabilities, and maps them to MITRE ATT&CK tactics, technique IDs, and
technique names. Returns score_delta for high-risk capabilities.
"""
