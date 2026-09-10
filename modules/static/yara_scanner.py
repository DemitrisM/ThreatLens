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

Design notes
------------
The two-stage compilation is the whole difficulty of this module. YARA
compiles a *set* of rule files as one unit, so a single syntax error — or
one rule using a module this build of libyara lacks — fails the entire
compile and takes several thousand working rules with it. Community rule
sets are updated by `threatlens rules update` from upstream git repos, so
that is not hypothetical: it happens whenever upstream adopts a feature
the installed libyara predates. Stage one therefore attempts the fast bulk
compile, and stage two falls back to compiling file by file to find and
exclude the offenders, reporting them in ``compile_errors`` rather than
hiding them.

External variables must be supplied at *compile* time even though they are
values about the sample, because a rule referencing an undefined external
fails to compile. So the rule set is recompiled per scan rather than
cached — an accepted cost, since caching would require the externals to be
identical across samples, which defeats the point of file-context rules.

An unknown severity in rule metadata scores the default rather than zero.
Most community rules carry no severity field at all, and treating "not
labelled" as "harmless" would silently discard the majority of the corpus.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity scoring — maps YARA rule metadata or naming conventions to scores.
# ---------------------------------------------------------------------------

# Read from the rule's own metadata, so these weights are only as
# trustworthy as the rule author. They are deliberately compressed into a
# narrow band (5-30): a YARA hit is strong evidence whatever its label, and
# the gap between "medium" and "critical" in one author's convention does
# not mean the same as in another's.
_SEVERITY_SCORES: dict[str, int] = {
    "critical": 30,
    "high": 25,
    "medium": 15,
    "low": 5,
}

# Default score when no severity metadata is present.
# Sits between "medium" and "high" on purpose: an unlabelled rule that
# fired is a real detection, and most of signature-base is unlabelled.
_DEFAULT_MATCH_SCORE = 20

# Cap total YARA contribution so it doesn't dominate the pipeline.
# Three matches reach it. Beyond that the marginal rule adds confidence,
# not information — and packer and generic rules match in clusters.
_MAX_SCORE = 60

# Maximum number of match details to store in the report.
# Applies to the stored details only; total_matches always reports the
# true figure, so a truncated report still states how many fired.
_MAX_MATCHES_REPORTED = 100


def run(file_path: Path, config: dict) -> dict:
    """Run YARA rules against a file.

    Loads all .yar/.yara files from the configured rules directory,
    compiles them, and scans the target file. Scores based on rule
    severity metadata or a default weight.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict. Read for ``yara_rules_dir``
                   and ``module_timeout_seconds``.

    Returns:
        Standard module result dict. "skipped" when the library, the rules
        directory or the rules themselves are absent — none of which says
        anything about the sample — and "error" only when rules existed and
        could not be used.
    """
    # Imported inside the function, not at module import, so that a missing
    # yara-python degrades this one module instead of breaking the import
    # of the whole registry (design rule 2). The same reason the import sits
    # before the config reads: there is nothing to configure without it.
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

    # An empty or missing rules directory is a skip rather than an error:
    # a fresh clone has no rules until `threatlens rules update` runs, and
    # that is a setup state, not a failure.
    rule_files = _find_rule_files(rules_dir)
    if not rule_files:
        logger.info("No YARA rule files found in %s — skipping", rules_dir)
        return _result("skipped", {}, 0, "No YARA rule files in rules directory")

    # Compiled per scan because the externals describe *this* file — see
    # the module docstring. compile_errors is carried into the result even
    # on success, so a partially broken rule set is visible rather than
    # silently reducing coverage.
    externals = _build_externals(file_path)
    compiled_rules, compile_errors = _compile_rules(yara, rule_files, externals)
    if compiled_rules is None:
        return _result(
            "error", {"compile_errors": compile_errors}, 0,
            f"All YARA rules failed to compile ({len(compile_errors)} errors)",
        )

    # A scan failure is an error, not a skip: the rules compiled, so the
    # sample should have been checked and was not.
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
    """Build a standard module result dict (design rule 1).

    Args:
        status:      "success", "skipped" or "error".
        data:        Module payload; empty dict for skips and errors.
        score_delta: Score contribution, always 0 unless status is success.
        reason:      Human-readable explanation for the module strip.

    Returns:
        The result dict. Centralised here because this module has seven
        distinct exit points and the shape must be identical at each.
    """
    return {
        "module": "yara_scanner",
        "status": status,
        "data": data,
        "score_delta": score_delta,
        "reason": reason,
    }


def _find_rule_files(rules_dir: Path) -> list[Path]:
    """Recursively find all .yar and .yara files in the rules directory.

    Args:
        rules_dir: Directory to walk. Both upstream rule repos are cloned
                   underneath it, hence the recursive glob.

    Returns:
        Sorted paths. The sort is not cosmetic: it fixes the namespace
        assignment below, which in turn fixes which file wins a stem
        collision, so scans stay reproducible across filesystems whose
        directory order differs.
    """
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

    Args:
        file_path: The sample under analysis.

    Returns:
        The external variable map passed to yara.compile().

    ``filetype`` and ``owner`` are supplied empty because THOR, the
    commercial scanner these rules are authored against, defines them and
    ThreatLens does not. They must still be *present*: a rule referencing an
    undeclared external fails to compile, and an empty string simply makes
    those rules' conditions false rather than erroring.
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
        yara:      The imported yara module. Passed in rather than imported
                   here so that the absence of the library is handled once,
                   in run(), instead of at every use site.
        rule_files: List of .yar/.yara file paths.
        externals: Dict of external variables to pass to the compiler.

    Returns:
        (compiled_rules_object_or_None, list_of_error_strings). None means
        nothing compiled at all; a non-empty error list alongside a valid
        object means the scan proceeds with reduced coverage, which the
        caller reports rather than swallows.
    """
    compile_errors: list[str] = []

    # Build the filepaths dict: {namespace: filepath_string}
    #
    # Namespaces are what keep two rule sets from colliding on a rule name —
    # signature-base and ESET both define rules with the same names, and
    # without distinct namespaces the second definition is a compile error.
    filepaths = {}
    for rule_file in rule_files:
        # Use the stem as namespace to avoid collisions.
        namespace = rule_file.stem
        # Two files may share a stem across the two rule repos, so the
        # parent directory name disambiguates. A collision surviving even
        # that (identical stem AND parent) silently drops the later file —
        # rare enough to accept, and the sorted input makes which one loses
        # deterministic rather than filesystem-dependent.
        if namespace in filepaths:
            namespace = f"{rule_file.parent.name}_{namespace}"
        filepaths[namespace] = str(rule_file)

    # Bulk compilation first: one compile of several thousand files is
    # dramatically faster than several thousand compiles, and it is the
    # path taken on every healthy rule set. SyntaxError and the broader
    # yara.Error are caught separately only to log which kind occurred —
    # both fall through to the same fallback.
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
    #
    # This compiles every surviving file twice — once here to test it, once
    # in the bulk compile below. That is deliberate: the test compile is the
    # only way to attribute a failure to a specific file, and the second
    # bulk compile is needed because per-file compiles produce independent
    # rule objects that cannot be matched in one pass.
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

    Args:
        compiled_rules: The object returned by yara.compile().
        file_path:      Sample to scan.
        timeout:        Seconds, passed to libyara itself rather than
                        enforced here — libyara aborts its own matching,
                        which a Python-level timer could not do.

    Returns:
        (list_of_matches, error_string_or_None)

    The blanket catch covers yara.TimeoutError and yara.Error alike; both
    are reported as scan failures, since a partial match set from an
    aborted scan cannot be distinguished from a complete one.
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

    Args:
        matches: yara.Match objects from a completed scan.

    Returns:
        (list_of_match_dicts, total_score_delta, list_of_reason_strings)
        The details are uncapped here — run() applies _MAX_MATCHES_REPORTED
        when it builds the payload, so the score always reflects every
        match even when the report shows a subset.

    Every attribute access is guarded with hasattr because yara.Match gained
    fields across yara-python versions and this module must work against
    whichever build the host distribution provides.
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

    # Cap after summing, never per match, so the raw total stays available
    # for the log line — three generic packer rules and one family rule
    # both reach 60, and the log is where that difference survives.
    capped_score = min(total_score, _MAX_SCORE)

    if total_score > _MAX_SCORE:
        logger.debug(
            "YARA score %d exceeds cap — clamped to %d", total_score, _MAX_SCORE
        )

    return match_details, capped_score, reasons
