"""Capability detection module using Mandiant capa.

Invokes capa via subprocess, parses the JSON output to extract detected
capabilities, and maps them to MITRE ATT&CK tactics, technique IDs, and
technique names. Returns score_delta for high-risk capabilities.
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
_MAX_SCORE = 60

# Maximum number of ATT&CK mappings to store in the report.
_MAX_ATTACK_MAPPINGS = 50


def run(file_path: Path, config: dict) -> dict:
    """Run capa capability detection on a file.

    Invokes the capa binary with --json, parses detected capabilities and
    ATT&CK mappings, and scores based on capability categories found.

    Args:
        file_path: Path to the file under analysis.
        config:    Pipeline configuration dict.

    Returns:
        Standard module result dict.
    """
    capa_path = Path(config.get("capa_binary", "./bin/capa"))
    timeout = config.get("capa_timeout_seconds",
                         config.get("module_timeout_seconds", 60))

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

    capabilities, attack_mappings = _parse_capa_output(capa_json)
    score_delta, reasons, scored_categories = _score_capabilities(capabilities)

    data = {
        "total_capabilities": len(capabilities),
        "capabilities": capabilities,
        "attack_mappings": attack_mappings[:_MAX_ATTACK_MAPPINGS],
        "scored_categories": scored_categories,
    }

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

    Returns:
        (parsed_json_dict_or_None, timed_out) — timed_out is True only when
        subprocess.TimeoutExpired was raised; False for all other failures.
    """
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
    if proc.returncode not in (0, 1, 14) and proc.returncode is not None:
        stderr_snippet = (
            proc.stderr[:400].decode("utf-8", errors="replace") if proc.stderr else ""
        )
        logger.info(
            "capa exited with code %d — will still attempt JSON parse. stderr: %s",
            proc.returncode,
            stderr_snippet[:200],
        )

    if not proc.stdout:
        logger.info("capa produced no output — no capabilities detected")
        return None, False

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

    Returns:
        (list_of_capability_names, list_of_attack_mapping_dicts)
    """
    capabilities: list[str] = []
    attack_mappings: list[dict] = []
    seen_attacks: set[tuple[str, str]] = set()

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
        if meta.get("lib", False) or meta.get("is_subscope_rule", False):
            continue

        capabilities.append(rule_name)

        # Extract ATT&CK mappings for this rule.
        for entry in meta.get("attack", []):
            if not isinstance(entry, dict):
                continue

            technique_id = entry.get("id", "").strip()
            technique_name = entry.get("technique", "").strip()
            tactic = entry.get("tactic", "").strip()
            subtechnique_name = (entry.get("subtechnique") or "").strip()

            # capa puts the full ID (e.g. "T1055.012") in the 'id' field.
            # The 'subtechnique' field is the name string, not a numeric suffix.
            full_id = technique_id

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

    Returns:
        (total_score_delta, list_of_reason_strings, list_of_category_dicts)
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

    score_delta = min(sum(hit_categories.values()), _MAX_SCORE)

    # Build reason strings and sorted category list (highest score first).
    reasons: list[str] = []
    scored_categories: list[dict] = []
    for category, score in sorted(hit_categories.items(), key=lambda x: -x[1]):
        reasons.append(f"capa: {category} (+{score})")
        scored_categories.append({"category": category, "score": score})

    return score_delta, reasons, scored_categories
