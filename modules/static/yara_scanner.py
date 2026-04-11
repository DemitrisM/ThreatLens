"""YARA rule matching module.

Loads YARA rule files from the configured rules directory, compiles and
matches them against the target sample. Each match contributes to the
confidence score with the rule name as reason.

Neo23x0 signature-base rules use external variables (`filepath`,
`filename`, `extension`) for file-context rules. These are passed at
compile time via `yara.compile(externals={...})`. Bulk compilation is
attempted first; on failure it falls back to per-file compilation to
isolate broken rules. Severity scoring is taken from rule metadata
(`critical=30`, `high=25`, `medium=15`, `low=5`, default=20). Total
YARA contribution capped at 60. See `docs/scoring.md`.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity scoring — maps YARA rule metadata or naming conventions to scores.
# ---------------------------------------------------------------------------

# If a rule has a "severity" meta field, use this mapping.
_SEVERITY_SCORES: dict[str, int] = {
    "critical": 30,
    "high": 25,
    "medium": 15,
    "low": 5,
}

# Default score when no severity metadata is present.
_DEFAULT_MATCH_SCORE = 20

# Cap total YARA contribution so it doesn't dominate the pipeline.
_MAX_SCORE = 60

# Maximum number of match details to store in the report.
_MAX_MATCHES_REPORTED = 100


def run(file_path: Path, config: dict) -> dict:
    """Run YARA rules against a file.

    Loads all .yar/.yara files from the configured rules directory,
    compiles them, and scans the target file. Scores based on rule
    severity metadata or a default weight.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict.

    Returns:
        Standard module result dict.
    """
    try:
        import yara  # noqa: PLC0415
    except ImportError:
        logger.warning("yara-python not installed — skipping YARA scanning")
        return _result("skipped", {}, 0, "yara-python library not installed")

    rules_dir = Path(config.get("yara_rules_dir", "./rules/yara"))
    timeout = config.get("module_timeout_seconds", 60)

    if not rules_dir.is_dir():
        logger.info("YARA rules directory not found at %s — skipping", rules_dir)
        return _result("skipped", {}, 0, "YARA rules directory not found")

    # Discover rule files.
    rule_files = _find_rule_files(rules_dir)
    if not rule_files:
        logger.info("No YARA rule files found in %s — skipping", rules_dir)
        return _result("skipped", {}, 0, "No YARA rule files in rules directory")

    # Compile rules with external variables for community rule sets.
    externals = _build_externals(file_path)
    compiled_rules, compile_errors = _compile_rules(yara, rule_files, externals)
    if compiled_rules is None:
        return _result(
            "error", {"compile_errors": compile_errors}, 0,
            f"All YARA rules failed to compile ({len(compile_errors)} errors)",
        )

    # Scan the file.
    matches, scan_error = _scan_file(compiled_rules, file_path, timeout)
    if scan_error is not None:
        return _result("error", {}, 0, f"YARA scan failed: {scan_error}")

    # Score and format results.
    match_details, score_delta, reasons = _process_matches(matches)

    data = {
        "total_rules_loaded": len(rule_files) - len(compile_errors),
        "total_matches": len(matches),
        "matches": match_details[:_MAX_MATCHES_REPORTED],
        "compile_errors": compile_errors if compile_errors else [],
    }

    if not matches:
        reason_text = (
            f"No YARA rules matched ({data['total_rules_loaded']} rules loaded)"
        )
    else:
        reason_text = "; ".join(reasons)

    return _result("success", data, score_delta, reason_text)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(status: str, data: dict, score_delta: int, reason: str) -> dict:
    """Build a standard module result dict."""
    return {
        "module": "yara_scanner",
        "status": status,
        "data": data,
        "score_delta": score_delta,
        "reason": reason,
    }


def _find_rule_files(rules_dir: Path) -> list[Path]:
    """Recursively find all .yar and .yara files in the rules directory."""
    rule_files: list[Path] = []
    for ext in ("*.yar", "*.yara"):
        rule_files.extend(rules_dir.rglob(ext))
    # Sort for deterministic ordering.
    rule_files.sort()
    return rule_files


def _build_externals(file_path: Path) -> dict:
    """Build a dict of external variables for YARA rules.

    Many community rule sets (e.g. Neo23x0 signature-base) use external
    variables like ``filepath``, ``filename``, and ``extension`` to scope
    rules to specific file types or locations.
    """
    return {
        "filepath": str(file_path),
        "filename": file_path.name,
        "extension": file_path.suffix.lstrip(".").lower(),
        "filetype": "",  # populated by THOR; empty is safe default
        "owner": "",
    }


def _compile_rules(yara, rule_files: list[Path], externals: dict):
    """Compile YARA rules from a list of files.

    Uses yara's filepaths dict to compile all rules at once. If bulk
    compilation fails (one bad rule breaks all), falls back to compiling
    each file individually and collecting the working ones.

    Args:
        yara:      The imported yara module.
        rule_files: List of .yar/.yara file paths.
        externals: Dict of external variables to pass to the compiler.

    Returns:
        (compiled_rules_object_or_None, list_of_error_strings)
    """
    compile_errors: list[str] = []

    # Build the filepaths dict: {namespace: filepath_string}
    filepaths = {}
    for rule_file in rule_files:
        # Use the stem as namespace to avoid collisions.
        namespace = rule_file.stem
        # Handle duplicate stems by appending parent dir name.
        if namespace in filepaths:
            namespace = f"{rule_file.parent.name}_{namespace}"
        filepaths[namespace] = str(rule_file)

    # Try bulk compilation first (fastest path).
    try:
        compiled = yara.compile(
            filepaths=filepaths, externals=externals,
        )
        logger.debug("Compiled %d YARA rule files successfully", len(filepaths))
        return compiled, compile_errors
    except yara.SyntaxError as exc:
        logger.info(
            "Bulk YARA compilation failed: %s — falling back to per-file compilation",
            exc,
        )
    except yara.Error as exc:
        logger.info(
            "YARA compilation error: %s — falling back to per-file compilation",
            exc,
        )

    # Per-file fallback: compile each file individually, skip broken ones.
    working_filepaths = {}
    for namespace, filepath in filepaths.items():
        try:
            yara.compile(filepath=filepath, externals=externals)
            working_filepaths[namespace] = filepath
        except yara.SyntaxError as exc:
            error_msg = f"{Path(filepath).name}: {exc}"
            compile_errors.append(error_msg)
            logger.debug("Skipping YARA rule file %s: %s", filepath, exc)
        except yara.Error as exc:
            error_msg = f"{Path(filepath).name}: {exc}"
            compile_errors.append(error_msg)
            logger.debug("Skipping YARA rule file %s: %s", filepath, exc)

    if not working_filepaths:
        logger.warning("No YARA rule files compiled successfully")
        return None, compile_errors

    try:
        compiled = yara.compile(
            filepaths=working_filepaths, externals=externals,
        )
        logger.debug(
            "Compiled %d/%d YARA rule files (skipped %d with errors)",
            len(working_filepaths),
            len(filepaths),
            len(compile_errors),
        )
        return compiled, compile_errors
    except yara.Error as exc:
        logger.error("YARA compilation failed even after filtering: %s", exc)
        compile_errors.append(f"Final compilation: {exc}")
        return None, compile_errors


def _scan_file(compiled_rules, file_path: Path, timeout: int):
    """Scan a file with compiled YARA rules.

    Returns:
        (list_of_matches, error_string_or_None)
    """
    try:
        matches = compiled_rules.match(str(file_path), timeout=timeout)
        logger.debug("YARA scan complete — %d matches", len(matches))
        return matches, None
    except Exception as exc:  # noqa: BLE001
        logger.error("YARA scan failed on %s: %s", file_path.name, exc)
        return [], str(exc)


def _process_matches(matches) -> tuple[list[dict], int, list[str]]:
    """Extract match details and compute score contribution.

    Each unique rule match contributes a score based on its severity
    metadata. The total is capped at ``_MAX_SCORE``.

    Returns:
        (list_of_match_dicts, total_score_delta, list_of_reason_strings)
    """
    match_details: list[dict] = []
    reasons: list[str] = []
    total_score = 0

    for match in matches:
        # Extract metadata from the rule match.
        meta = match.meta if hasattr(match, "meta") else {}

        # Determine severity and score.
        severity = str(meta.get("severity", "")).lower().strip()
        score = _SEVERITY_SCORES.get(severity, _DEFAULT_MATCH_SCORE)

        # Extract useful metadata fields.
        detail: dict = {
            "rule": match.rule,
            "namespace": match.namespace if hasattr(match, "namespace") else "",
            "tags": list(match.tags) if hasattr(match, "tags") else [],
            "score": score,
        }

        # Include selected meta fields if present.
        for meta_key in ("description", "author", "reference", "severity",
                         "date", "malware_family", "threat_name"):
            if meta_key in meta:
                detail[meta_key] = str(meta[meta_key])

        match_details.append(detail)
        total_score += score
        reasons.append(f"YARA: {match.rule} (+{score})")

    # Cap the total score.
    capped_score = min(total_score, _MAX_SCORE)

    if total_score > _MAX_SCORE:
        logger.debug(
            "YARA score %d exceeds cap — clamped to %d", total_score, _MAX_SCORE
        )

    return match_details, capped_score, reasons
