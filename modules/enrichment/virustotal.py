"""VirusTotal hash lookup module.

Queries the VirusTotal v3 API using the file's SHA256 hash (never the file
itself). Parses detection ratio, threat labels, and first-seen date.
Gracefully skips if no API key is configured.
"""
