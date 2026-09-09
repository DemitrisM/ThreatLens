"""Enrichment modules — external threat intelligence lookups.

Everything in this package reaches the network, which makes it the one place
in the tool where design rule 3 applies directly: **the sample itself is never
sent anywhere.** Only hashes leave the machine. A malware sample often contains
the victim's data — documents, credentials, internal hostnames — and uploading
it to a third party would leak that, as well as tipping off an operator who
monitors VirusTotal for their own payloads appearing.

That constraint shapes the module: it hashes locally, queries by hash, and
treats "not found" as unknown rather than clean.
"""
