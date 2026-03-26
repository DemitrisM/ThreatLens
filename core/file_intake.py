"""File intake module — type detection and hashing.

Uses python-magic for true file-type identification (not extension-based),
generates MD5, SHA256, and TLSH fuzzy hashes, and returns structured
file metadata for downstream modules.
"""
