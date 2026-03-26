"""YARA rule matching module.

Loads YARA rule files from the configured rules directory, compiles and
matches them against the target sample. Each match contributes to the
confidence score with the rule name as reason.
"""
