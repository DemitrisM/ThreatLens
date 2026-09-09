"""Core components: pipeline orchestration, file intake, scoring, and config.

This package holds everything the tool cannot run without. Anything that can
be absent on a given machine — a PE parser, a YARA engine, a sandbox — lives
under ``modules/`` instead and is imported lazily.

Modules
-------
``pipeline``       Orchestrator. Loads and runs the enabled analysis modules
                   in order, times each, and assembles the report dict that
                   every reporter consumes.
``file_intake``    Always the first module to run. Content-based type
                   detection plus MD5/SHA256/TLSH/ssdeep hashing. Scores
                   nothing; every later module depends on what it publishes.
``scoring``        Sums the modules' ``score_delta`` values, clamps the total
                   to 0-100 once, and maps it to a risk band.
``config_loader``  Four-location config search chain, defaults for every key,
                   non-fatal validation, and the credential handling rules.
``rule_updater``   Git-backed YARA rule source manager behind ``rules update``.

The module result contract
--------------------------
Every analysis module in this project — in ``core/`` or under ``modules/`` —
returns exactly this shape, and the pipeline adds ``elapsed_seconds`` to each
static module's result::

    {
        "module": "module_name",
        "status": "success" | "skipped" | "error",
        "data": {...},
        "score_delta": <int>,
        "reason": "<why this module moved the score>",
    }

``skipped`` and ``error`` are distinct on purpose: the first means the module
did not apply or a dependency was absent, the second means something went
wrong. Both carry ``score_delta: 0``, so a module that did not run can never
move the verdict in either direction.
"""
