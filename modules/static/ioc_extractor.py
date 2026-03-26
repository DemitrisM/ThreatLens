"""Indicator of Compromise (IOC) extraction module.

Applies regex patterns against extracted strings to identify IPv4 addresses,
URLs, domains, Windows file paths, registry keys, email addresses, and other
IOCs. Filters known false positives.
"""
