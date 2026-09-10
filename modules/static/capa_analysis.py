"""Capability detection module using Mandiant capa.

Invokes capa via subprocess, parses the JSON output to extract detected
capabilities, and maps them to MITRE ATT&CK tactics, technique IDs, and
technique names. Returns score_delta for high-risk capabilities.

Design notes
------------
capa is an *external binary*, not a library, so every failure mode it has
is a subprocess failure mode: absent, timing out, exiting non-zero,
printing nothing, printing something that is not JSON. All five collapse
to the same graceful skip (design rule 2) — the module never raises and
never lets a broken capa install fail a scan that eleven other modules
completed.

Exit codes are the subtle part. capa returns 0 when rules matched and 1
when none did, and *both* are successful analyses; 14 is the file-limitation
warning it emits for AutoIt and .NET binaries, where it often still writes
usable JSON to stdout. So the exit code is treated as advisory only —
stdout is parsed whatever the code was, and the presence of parseable JSON
is what decides success. Anything else would throw away the AutoIt results.

Scoring is category-based rather than capability-based, and that is
deliberate. capa routinely reports a dozen capabilities that all mean
"this injects code"; scoring each one would let a single behaviour
dominate the 0-100 budget. Instead each category contributes once, at the
highest score any of its matching capabilities earned, and the sum is
capped at ``_MAX_SCORE``. One capability may feed several categories,
which is why the match loop does not break on its first hit.
"""

import json
import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Capability → risk scoring rules
# ---------------------------------------------------------------------------

# Each entry: (compiled regex matching capability/namespace, category label, score).
# Evaluated against every capability name found; each category is counted once
# at its maximum score across all matching capabilities.
#
# The patterns match capa's *human-readable rule names* ("inject APC",
# "receive and write data from server to file"), not its namespaces, because
# the namespace is absent from the rule key and only some rules carry one.
# That makes the patterns deliberately loose — a rule name is prose, and the
# same behaviour is spelled a dozen ways across the ruleset. Over-matching
# costs at most one extra category at its fixed weight; under-matching loses
# the signal entirely, and the cap below bounds the damage either way.
#
# Scores are per category, not per capability. Ordering is presentational
# only: _score_capabilities() sorts by score before building the report.
_CAPABILITY_RULES: list[tuple[re.Pattern, str, int]] = [
    # Process injection / code injection — highest risk
    (
        re.compile(
            r"inject|process.*hollow|shellcode|dll.*inject|hollowing"
            r"|allocate.*shellcode|write.*shellcode",
            re.IGNORECASE,
        ),
        "Process injection",
        20,
    ),
    # Anti-analysis / sandbox / VM evasion
    (
        re.compile(
            r"anti.?debug|anti.?analys|anti.?sandbox|anti.?vm|anti.?emulat"
            r"|evad.*detect|check.*debugger|detect.*sandbox|detect.*vm"
            r"|check.*virtual|obfuscat.*call",
            re.IGNORECASE,
        ),
        "Anti-analysis / anti-debug",
        15,
    ),
    # Credential access — browser data, LSASS, keystroke logging
    (
        re.compile(
            r"credential|lsass|sam.database|keylog|steal.*password|steal.*credential"
            r"|dump.*hash|mimikatz|browser.*password|browser.*cookie"
            r"|browser.*history|read.*browser|access.*browser",
            re.IGNORECASE,
        ),
        "Credential access",
        15,
    ),
    # Persistence
    (
        re.compile(
            r"persist|autorun|run.key|startup|scheduled.task|registry.*run"
            r"|install.*service|create.*service|boot.*logon|logon.*autostart",
            re.IGNORECASE,
        ),
        "Persistence mechanism",
        10,
    ),
    # Network / C2 / data transfer — broad to catch capa's human-readable names
    (
        re.compile(
            r"download|upload|receive.*data|send.*data|read.*internet"
            r"|write.*internet|http|socket|connect.*server|dns|beacon"
            r"|network.*communicat|c2|command.*control|url|ftp|smtp"
            r"|receive and write|download.*file|get.*url",
            re.IGNORECASE,
        ),
        "Network communication",
        10,
    ),
    # Data collection / reconnaissance
    (
        re.compile(
            r"screenshot|clipboard|exfil|access.*wmi|reference.*wmi"
            r"|collect.*system|gather.*system|enumerate.*process"
            r"|list.*process|take.*screenshot|capture.*screen",
            re.IGNORECASE,
        ),
        "Data collection / reconnaissance",
        10,
    ),
    # Privilege escalation / token manipulation
    (
        re.compile(
            r"privilege.*escalat|elevat.*privilege|impersonat.*token|bypass.*uac"
            r"|uac.*bypass|token.*impersonat|adjust.*token|enable.*privilege",
            re.IGNORECASE,
        ),
        "Privilege escalation",
        10,
    ),
    # Encryption / obfuscation / packing
    (
        re.compile(
            r"encrypt|decrypt|obfuscat|base64|bcrypt|dpapi|xor|rc4|aes"
            r"|pack.*execut|compress|deobfuscat|decode.*data|encode.*data",
            re.IGNORECASE,
        ),
        "Encryption / obfuscation",
        5,
    ),
]

# Maximum capa score contribution (prevents capa from dominating all other modules).
# Eight categories at their listed weights sum to 95, which alone would push
# any capa-heavy sample into CRITICAL before pe_analysis, YARA or VirusTotal
# have said anything. 60 keeps a full sweep of capabilities inside HIGH.
_MAX_SCORE = 60

# Maximum number of ATT&CK mappings to store in the report.
# A cap rather than a full list because capa can map several hundred rules on
# a large binary, and the JSON report is meant to stay readable. The count of
# capabilities is reported separately, so nothing about scale is hidden.
_MAX_ATTACK_MAPPINGS = 50


def run(file_path: Path, config: dict) -> dict:
    """Run capa capability detection on a file.

    Invokes the capa binary with --json, parses detected capabilities and
    ATT&CK mappings, and scores based on capability categories found.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict. Read for ``capa_binary``,
                   ``capa_timeout_seconds`` and ``module_timeout_seconds``.

    Returns:
        Standard module result dict. ``status`` is "skipped" for every
        capa failure — an absent binary, a timeout, or unparseable output —
        because none of them say anything about the sample.
    """
    # ------------------------------------------------------------------
    # Phase 1: Resolve the binary and the time budget.
    #
    # capa gets its own timeout key because it is an order of magnitude
    # slower than any in-process module: -p deep raises it to 180s while
    # module_timeout_seconds stays at 60. The chained get() means a config
    # that omits the capa-specific key still inherits a sane bound rather
    # than running unbounded.
    # ------------------------------------------------------------------
    capa_path = Path(config.get("capa_binary", "./bin/capa"))
    timeout = config.get("capa_timeout_seconds",
                         config.get("module_timeout_seconds", 60))

    # A missing binary is the normal case on a fresh clone (install.sh
    # downloads it), so it logs at info rather than warning.
    if not capa_path.is_file():
        logger.info(
            "capa binary not found at %s — skipping capability detection", capa_path
        )
        return {
            "module": "capa_analysis",
            "status": "skipped",
            "data": {},
            "score_delta": 0,
            "reason": "capa binary not found",
        }

    # ------------------------------------------------------------------
    # Phase 2: Run capa. Distinguish a timeout from every other failure
    # only in the reason string — the caller's handling is identical, but
    # "capa timed out" tells the analyst to retry with -p deep, whereas
    # "capa analysis failed" tells them to check the install.
    # ------------------------------------------------------------------
    capa_json, timed_out = _run_capa(file_path, capa_path, timeout)
    if capa_json is None:
        reason = "capa timed out" if timed_out else "capa analysis failed"
        return {
            "module": "capa_analysis",
            "status": "skipped",
            "data": {},
            "score_delta": 0,
            "reason": reason,
        }

    # ------------------------------------------------------------------
    # Phase 3: Parse, score, and assemble the report payload.
    #
    # total_capabilities is recorded before the ATT&CK truncation so the
    # report can still state how many capabilities capa found even when
    # only the first _MAX_ATTACK_MAPPINGS mappings are carried.
    # ------------------------------------------------------------------
    capabilities, attack_mappings = _parse_capa_output(capa_json)
    score_delta, reasons, scored_categories = _score_capabilities(capabilities)

    data = {
        "total_capabilities": len(capabilities),
        "capabilities": capabilities,
        "attack_mappings": attack_mappings[:_MAX_ATTACK_MAPPINGS],
        "scored_categories": scored_categories,
    }

    # An empty `reasons` list means capa ran fine and scored nothing. That
    # is a real result, not a skip, so the reason distinguishes "capa found
    # capabilities, none risky" from "capa found nothing at all" — the
    # second usually means an unsupported format rather than a clean file.
    if not reasons:
        reason_text = (
            f"No high-risk capabilities detected "
            f"({len(capabilities)} low-risk capabilities found)"
            if capabilities
            else "No capabilities detected"
        )
    else:
        reason_text = "; ".join(reasons)

    return {
        "module": "capa_analysis",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason_text,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_capa(
    file_path: Path, capa_path: Path, timeout: int
) -> tuple[dict | None, bool]:
    """Invoke capa with --json and return the parsed JSON output.

    capa exits with code 0 when rules match, 1 when no rules match (but
    analysis succeeded).  Both are valid; any other exit code is an error.

    Args:
        file_path: Path to the file under analysis, passed to capa as-is.
        capa_path: Path to the capa binary, already checked to exist.
        timeout:   Hard wall-clock bound in seconds. capa on a large packed
                   binary can run for minutes, and design rule 5 forbids a
                   module that can hang the pipeline.

    Returns:
        (parsed_json_dict_or_None, timed_out) — timed_out is True only when
        subprocess.TimeoutExpired was raised; False for all other failures.
        The caller needs the two apart only to phrase its reason string.
    """
    # stdout carries the JSON document and stderr the progress bar, so both
    # are captured: letting stderr through would corrupt `-f json | jq`
    # (design rule 7). check=False because a non-zero exit is expected and
    # handled below, not exceptional.
    cmd = [str(capa_path), "--json", str(file_path)]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "capa timed out after %ds on %s — skipping (complex binary or unsupported format)",
            timeout,
            file_path.name,
        )
        return None, True
    except OSError as exc:
        logger.warning("capa invocation failed: %s — skipping", exc)
        return None, False

    # capa exit codes:
    #   0  — success, rules matched
    #   1  — no rules matched (analysis succeeded, some versions)
    #  14  — file limitation warning (AutoIt, .NET etc.) but may still produce JSON
    # Other non-zero codes indicate real errors; still attempt JSON parse from stdout.
    #
    # The parse is attempted regardless because exit code and output are
    # independent in capa: code 14 in particular is a *warning* about the
    # sample's format, and discarding its JSON would blind the tool to the
    # AutoIt and .NET droppers that trigger it. So this branch only logs.
    if proc.returncode not in (0, 1, 14) and proc.returncode is not None:
        # Slice the bytes before decoding: a capa crash can put megabytes of
        # traceback on stderr, and errors="replace" guarantees the decode
        # itself cannot raise on partial UTF-8 left at the cut.
        stderr_snippet = (
            proc.stderr[:400].decode("utf-8", errors="replace") if proc.stderr else ""
        )
        logger.info(
            "capa exited with code %d — will still attempt JSON parse. stderr: %s",
            proc.returncode,
            stderr_snippet[:200],
        )

    # Empty stdout is common for formats capa refuses outright (documents,
    # archives, ELF without the right backend). It is not an error worth a
    # warning — the module simply has nothing to say about the file.
    if not proc.stdout:
        logger.info("capa produced no output — no capabilities detected")
        return None, False

    # json.loads accepts bytes directly, so stdout is never decoded here:
    # capa emits UTF-8 and letting json handle it avoids a second copy of
    # what can be a multi-megabyte result document.
    try:
        return json.loads(proc.stdout), False
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Failed to parse capa JSON output: %s", exc)
        return None, False


def _parse_capa_output(capa_json: dict) -> tuple[list[str], list[dict]]:
    """Extract capability names and ATT&CK mappings from capa JSON output.

    Compatible with capa v6 and v7+ JSON structures.  The ``rules`` dict
    keys are the capability names; ATT&CK data lives in each rule's ``meta``
    section.

    Args:
        capa_json: The parsed capa result document. Only ``rules`` is read;
                   the ``meta`` block describing capa's own version and the
                   per-rule match addresses are deliberately ignored.

    Returns:
        (list_of_capability_names, list_of_attack_mapping_dicts)
    """
    capabilities: list[str] = []
    attack_mappings: list[dict] = []
    seen_attacks: set[tuple[str, str]] = set()

    # Every isinstance() guard below exists because this walks a document
    # produced by an external binary whose schema has already changed once
    # (v6 → v7). A shape surprise must degrade to fewer capabilities, never
    # to an exception — the module's whole result would be lost otherwise.
    rules = capa_json.get("rules", {})
    if not isinstance(rules, dict):
        logger.warning("capa JSON 'rules' field is not a dict — cannot parse")
        return capabilities, attack_mappings

    for rule_name, rule_data in rules.items():
        if not isinstance(rule_data, dict):
            continue

        meta = rule_data.get("meta", {})

        # Skip internal library / subscope rules — they're implementation
        # details, not user-facing capabilities.
        #
        # Library rules are the shared building blocks other rules match on
        # ("contains PE file", "parse PE header"); subscope rules are the
        # anonymous inner matches capa synthesises for function- or
        # basic-block-scoped clauses. Both would inflate total_capabilities
        # and, worse, feed the scoring regexes with names that describe
        # capa's own plumbing rather than the sample's behaviour.
        if meta.get("lib", False) or meta.get("is_subscope_rule", False):
            continue

        capabilities.append(rule_name)

        # Extract ATT&CK mappings for this rule. A rule may carry several
        # (or none) — the ATT&CK block is optional metadata in the ruleset.
        for entry in meta.get("attack", []):
            if not isinstance(entry, dict):
                continue

            technique_id = entry.get("id", "").strip()
            technique_name = entry.get("technique", "").strip()
            tactic = entry.get("tactic", "").strip()
            subtechnique_name = (entry.get("subtechnique") or "").strip()

            # capa puts the full ID (e.g. "T1055.012") in the 'id' field.
            # The 'subtechnique' field is the name string, not a numeric suffix.
            # Concatenating the two — the obvious reading of the schema —
            # produces "T1055.012.Process Hollowing" and breaks every
            # downstream ATT&CK link, so the id is used verbatim.
            full_id = technique_id

            # Dedup on (technique, rule) rather than technique alone: two
            # different capabilities mapping to T1055 are two findings worth
            # showing, but one capability listing T1055 twice is noise capa
            # occasionally emits when a rule inherits its parent's metadata.
            dedup_key = (full_id, rule_name)
            if dedup_key in seen_attacks:
                continue
            seen_attacks.add(dedup_key)

            # Build a combined technique name including subtechnique if present.
            display_technique = (
                f"{technique_name}: {subtechnique_name}"
                if subtechnique_name
                else technique_name
            )

            mapping: dict = {
                "capability": rule_name,
                "tactic": tactic,
                "technique_id": full_id,
                "technique_name": display_technique,
            }
            attack_mappings.append(mapping)

    return capabilities, attack_mappings


def _score_capabilities(capabilities: list[str]) -> tuple[int, list[str], list[dict]]:
    """Score a list of capability names against known risk categories.

    Each matching category is counted once at its maximum score.  The total
    is capped at ``_MAX_SCORE`` to prevent capa from overwhelming other modules.

    Args:
        capabilities: Capability names as capa spells them, library and
                      subscope rules already filtered out by the caller.

    Returns:
        (total_score_delta, list_of_reason_strings, list_of_category_dicts)
        The category dicts are what the terminal and HTML reporters render;
        the reason strings are joined into the module's one-line summary.
    """
    # category → maximum score seen across all capabilities that matched it.
    hit_categories: dict[str, int] = {}

    for cap in capabilities:
        for pattern, category, score in _CAPABILITY_RULES:
            if pattern.search(cap):
                current = hit_categories.get(category, 0)
                if score > current:
                    hit_categories[category] = score
                # Do NOT break — one capability may contribute to multiple
                # categories (e.g. a rule named "anti-debug via inject" matches
                # both Anti-analysis and Process injection).

    # The cap applies to the sum, not to any single category, so a sample
    # that trips six categories still lands at _MAX_SCORE rather than
    # accumulating past everything else the pipeline measured.
    score_delta = min(sum(hit_categories.values()), _MAX_SCORE)

    # Build reason strings and sorted category list (highest score first).
    # Highest-first because the report truncates the tail: the categories a
    # reader loses to truncation must be the ones that mattered least.
    # Note the printed "+N" values are pre-cap, so they can sum past
    # score_delta when the cap bites — intentional, since they explain
    # what was found rather than restating the clamped total.
    reasons: list[str] = []
    scored_categories: list[dict] = []
    for category, score in sorted(hit_categories.items(), key=lambda x: -x[1]):
        reasons.append(f"capa: {category} (+{score})")
        scored_categories.append({"category": category, "score": score})

    return score_delta, reasons, scored_categories
