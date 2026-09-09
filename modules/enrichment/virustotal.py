"""VirusTotal hash lookup module.

Queries the VirusTotal v3 API using the file's SHA256 hash (never the file
itself). Parses detection ratio, threat labels, and first-seen date.
Gracefully skips if no API key is configured.

Free-tier API limits (as of 2026):
  - 4 requests per minute
  - 500 requests per day
  - 15,500 requests per month

The module handles HTTP 429 (rate limit) with automatic retry (up to 2
attempts) using the Retry-After header when present. If retries are
exhausted, returns a user-friendly error with wait-time guidance.

Design notes
------------
**The file is never uploaded.** Only its SHA256 leaves the machine (design
rule 3). A sample routinely contains the victim's own data, and uploading it
would both leak that and tip off an operator watching VirusTotal for their
payload to appear. The hash is recomputed here rather than read from the
file_intake result, so this module cannot be made to send something other
than the file it was pointed at.

**A miss is not an acquittal.** HTTP 404 means the hash has never been
submitted, which is the *expected* state for a targeted or freshly-built
sample — precisely the dangerous case. It scores -5 as mild reassurance and
says so in the reason string, rather than reading as clean.

**Scoring is asymmetric.** Detections add up to +25; a clean-but-seen result
subtracts only 5. An engine consensus is strong evidence of malice, while its
absence is weak evidence of safety: AV signatures lag new builds by days.

**The API key never reaches the report.** `_parse_response` builds its data
dict field by field from the response rather than copying the request
context, and `reporting/shared.py` strips credentials recursively as a second
line of defence.
"""

import hashlib
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Optional dependency. Without it the module skips rather than failing:
# an offline analysis box should still get all twelve other modules
# (design rule 2).
try:
    import requests

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    logger.warning("requests library not available — VirusTotal lookups disabled")

_VT_API_URL = "https://www.virustotal.com/api/v3/files"


def run(file_path: Path, config: dict) -> dict:
    """Look up the file's SHA256 hash on VirusTotal.

    The file is NEVER uploaded — only the hash is sent.

    Args:
        file_path: Path to the file under analysis (used only to
                   extract the SHA256 from file_intake results via
                   pipeline ordering — but we re-hash here for safety).
        config:    Validated configuration dict.  Must contain
                   ``virustotal_api_key`` (non-empty string) for the
                   lookup to proceed.

    Returns:
        Standard module result dict.
    """
    # ------------------------------------------------------------------
    # Step 1: Both preconditions are SKIPS, not errors.
    #
    # No key and no requests library are ordinary states for a scan run
    # offline or without an account, and neither says anything about the
    # file. Reporting them as errors would make a normal offline run look
    # like a failed one.
    # ------------------------------------------------------------------
    # `or ""` rather than a .get default: config_loader guarantees the
    # key is always PRESENT, so the default never fires. A bare
    # `virustotal_api_key:` in YAML parses to None, and .strip() on that
    # raised AttributeError and killed the whole pipeline.
    api_key = (config.get("virustotal_api_key") or "").strip()

    if not api_key:
        return _skipped("No VirusTotal API key configured")

    if not _HAS_REQUESTS:
        return _skipped("requests library not installed")

    # ------------------------------------------------------------------
    # Step 2: Hash locally. This is the only thing that will be sent.
    # ------------------------------------------------------------------
    # Compute SHA256 locally (never send the file).
    sha256 = _sha256(file_path)
    if sha256 is None:
        return _error("Could not compute SHA256 hash")

    timeout = config.get("module_timeout_seconds", 60)
    max_retries = 2  # Retry up to 2 times on rate limit

    # ------------------------------------------------------------------
    # Step 3: Query, then branch on the status code.
    #
    # _request_with_retry returns EITHER a Response or a finished result
    # dict, so the isinstance check is the sentinel for "the network
    # failed and the error result is already built".
    # ------------------------------------------------------------------
    resp = _request_with_retry(sha256, api_key, timeout, max_retries)
    if isinstance(resp, dict):
        # _request_with_retry returned an error/skip result dict directly
        return resp

    # ── Handle response status codes ──
    if resp.status_code == 404:
        # An unknown hash is the expected state for a targeted or newly
        # built sample, so this is the LEAST reassuring "clean" result
        # the module can produce. It scores -5 and says so, rather than
        # being reported as a pass.
        # Hash not in VT database — not necessarily clean.
        primary_404 = {
            "module": "virustotal",
            "status": "success",
            "data": {
                "sha256": sha256,
                "found": False,
                "detection_ratio": "0/0",
                "malicious": 0,
                "undetected": 0,
                "total_engines": 0,
                "threat_label": None,
                "first_seen": None,
                "community_score": None,
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            },
            "score_delta": -5,
            "reason": "Hash not seen on VirusTotal — not necessarily clean",
        }
        inner_lookups, inner_delta, inner_reason = _lookup_embedded_hashes(
            config, api_key, timeout, max_retries,
        )
        if inner_lookups:
            primary_404["data"]["embedded_hash_lookups"] = inner_lookups
            primary_404["score_delta"] += inner_delta
            if inner_reason:
                primary_404["reason"] = f"{primary_404['reason']}; {inner_reason}"
        return primary_404

    if resp.status_code == 401:
        return _error("VirusTotal API key is invalid (HTTP 401)")

    if resp.status_code == 429:
        # Retries exhausted — give the user actionable guidance
        retry_after = resp.headers.get("Retry-After")
        wait_msg = f" (retry after {retry_after}s)" if retry_after else ""
        return _error(
            f"VirusTotal API rate limit exceeded{wait_msg} — "
            f"free tier allows 4 requests/minute and 500/day. "
            f"Use --skip virustotal to continue without VT, or wait and retry"
        )

    if resp.status_code != 200:
        return _error(f"VirusTotal API returned HTTP {resp.status_code}")

    # ── Parse successful response ──
    try:
        body = resp.json()
    except ValueError:
        return _error("VirusTotal returned invalid JSON")

    primary = _parse_response(body, sha256)

    # ── Embedded-hash forward-lookup (from archive_analysis) ──
    inner_lookups, inner_delta, inner_reason = _lookup_embedded_hashes(
        config, api_key, timeout, max_retries,
    )
    if inner_lookups:
        primary.setdefault("data", {})["embedded_hash_lookups"] = inner_lookups
        primary["score_delta"] = primary.get("score_delta", 0) + inner_delta
        if inner_reason:
            sep = "; " if primary.get("reason") else ""
            primary["reason"] = f"{primary.get('reason', '')}{sep}{inner_reason}"

    return primary


def _collect_prior_hashes(config: dict) -> list[dict]:
    """Walk prior module results for embedded PE/ELF hashes to VT-forward.

    Args:
        config: The pipeline config, read for ``_module_results_so_far``.
                This is why virustotal must run last in enabled_modules —
                archive_analysis and onenote_analysis publish the hashes
                it forwards, and it can only see modules that already ran.

    Returns:
        One entry per unique embedded SHA256. Deduplicated because the
        same payload commonly appears more than once in an archive, and
        each lookup costs a request against a 4-per-minute quota.
    """
    prior = config.get("_module_results_so_far") or []
    seen: set[str] = set()
    out: list[dict] = []
    for result in prior:
        data = result.get("data") or {}
        for entry in data.get("embedded_executables", []) or []:
            sha = (entry.get("sha256") or "").lower()
            if not sha or sha in seen:
                continue
            seen.add(sha)
            out.append({
                "name": entry.get("name"),
                "sha256": sha,
                "size": entry.get("size"),
                "type": entry.get("type"),
            })
    return out


def _lookup_embedded_hashes(
    config: dict,
    api_key: str,
    timeout: int,
    max_retries: int,
) -> tuple[list[dict], int, str]:
    """Look up each unique embedded SHA256 on VT. Cap score contribution.

    Args:
        config:      Pipeline config, for the prior-results handoff.
        api_key:     VirusTotal API key.
        timeout:     Per-request timeout in seconds.
        max_retries: Retries per request on HTTP 429.

    Returns:
        ``(per_hash_results, score_delta, reason)``. The delta is capped
        at +10 so a zip of twenty flagged files cannot alone saturate the
        score — the archive's own module already scored the container.

    NOTE: this issues one request PER embedded hash with no shared rate
    budget, and each can sleep up to 120s on a 429. Against the free
    tier's 4 requests/minute, an archive with a dozen payloads will
    either stall for minutes or exhaust its retries. A shared token
    bucket across the whole scan is the fix; not attempted here.
    """
    hashes = _collect_prior_hashes(config)
    if not hashes:
        return [], 0, ""

    results: list[dict] = []
    hits = 0
    for h in hashes:
        sha = h["sha256"]
        resp = _request_with_retry(sha, api_key, timeout, max_retries)
        if isinstance(resp, dict):  # error result dict
            results.append({
                "name": h["name"], "sha256": sha,
                "detection_ratio": None, "threat_label": None,
                "error": resp.get("reason"),
            })
            continue
        if resp.status_code == 404:
            results.append({
                "name": h["name"], "sha256": sha,
                "found": False, "detection_ratio": "0/0", "threat_label": None,
            })
            continue
        if resp.status_code != 200:
            results.append({
                "name": h["name"], "sha256": sha,
                "detection_ratio": None, "threat_label": None,
                "error": f"HTTP {resp.status_code}",
            })
            continue
        try:
            body = resp.json()
        except ValueError:
            continue
        # `or {}` at each step, not a .get default — see _parse_response.
        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.get(k, 0) for k in
                    ("malicious", "suspicious", "undetected",
                     "harmless", "type-unsupported", "failure"))
        label = (attrs.get("popular_threat_classification", {})
                      .get("suggested_threat_label"))
        results.append({
            "name": h["name"],
            "sha256": sha,
            "found": True,
            "detection_ratio": f"{detections}/{total}",
            "threat_label": label,
        })
        if detections > 0:
            hits += 1

    # +2 per flagged payload, capped at +10. Deliberately modest: the
    # container's own module has already scored the fact that it carries
    # executables, so this only adds the external corroboration.
    delta = min(hits * 2, 10)
    reason = ""
    if hits:
        reason = f"VirusTotal: {hits} embedded executable hash(es) flagged"
    return results, delta, reason


def _request_with_retry(
    sha256: str, api_key: str, timeout: int, max_retries: int
) -> "requests.Response | dict":
    """Make the VT API request with automatic retry on HTTP 429.

    Args:
        sha256:      The hash to look up — the only thing sent.
        api_key:     Sent in the ``x-apikey`` header, never in the URL,
                     so it cannot land in a proxy or server access log.
        timeout:     Per-request timeout in seconds.
        max_retries: Extra attempts after a 429.

    Returns:
        The Response object on success, or a module error dict if all
        attempts fail due to network/timeout errors. Two return types on
        purpose: the caller distinguishes them with isinstance, which
        keeps the error text next to the failure that produced it.

    A non-429 response is returned immediately whatever its status — 404
    and 401 are meaningful answers, and the caller interprets them.
    """
    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(
                f"{_VT_API_URL}/{sha256}",
                headers={"x-apikey": api_key},
                timeout=timeout,
            )
        except requests.exceptions.Timeout:
            return _error(f"VirusTotal API request timed out after {timeout}s")
        except requests.exceptions.ConnectionError:
            return _error("Could not connect to VirusTotal API — check network")
        except requests.exceptions.RequestException as exc:
            return _error(f"VirusTotal API request failed: {exc}")

        if resp.status_code != 429:
            return resp

        # Honour Retry-After when the server sends it; 60s otherwise,
        # matching the free tier's 4-per-minute window. The header is
        # attacker-influenced only in the sense that it comes from the
        # network, hence the cap below.
        # Rate limited — check Retry-After header, default to 60s
        retry_after = resp.headers.get("Retry-After")
        try:
            wait_seconds = int(retry_after) if retry_after else 60
        except (ValueError, TypeError):
            wait_seconds = 60

        # Cap the wait so a hostile or misconfigured Retry-After cannot
        # park the scan for hours.
        # Bounded on BOTH sides. A negative Retry-After parses happily as
        # an int and survives the upper cap, and time.sleep() raises
        # ValueError on a negative argument.
        # Cap wait to something reasonable (max 120s)
        wait_seconds = max(0, min(wait_seconds, 120))

        if attempt < max_retries:
            logger.warning(
                "VirusTotal rate limit hit (attempt %d/%d) — waiting %ds before retry",
                attempt + 1, max_retries + 1, wait_seconds,
            )
            time.sleep(wait_seconds)
        else:
            # Return the 429 response for the caller to handle
            return resp

    # Should not reach here, but just in case
    return _error("VirusTotal API request failed after retries")


def _parse_response(body: dict, sha256: str) -> dict:
    """Extract detection stats, threat label, and metadata from VT response.

    Args:
        body:   Decoded JSON from a 200 response.
        sha256: The hash queried, echoed into the result and permalink.

    Returns:
        A standard module result dict.

    Every field is read with ``.get`` and a default. The response is
    third-party JSON whose shape can change without notice, and a missing
    key must degrade one field rather than fail the lookup.
    """
    # `or {}` at each step, not a .get default: a default only applies to
    # an ABSENT key, and `{"data": null}` is valid JSON that puts None
    # there. Chaining .get onto that raised AttributeError and failed the
    # lookup fatally instead of degrading it.
    attrs = (body.get("data") or {}).get("attributes") or {}

    # Detection statistics
    stats = attrs.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    type_unsupported = stats.get("type-unsupported", 0)
    failure = stats.get("failure", 0)
    total_engines = malicious + suspicious + undetected + harmless + type_unsupported + failure

    # "suspicious" is counted alongside "malicious": an engine reporting
    # a heuristic hit is still an engine objecting to the file.
    # Combined detection count (malicious + suspicious)
    detections = malicious + suspicious

    # Threat classification
    classification = attrs.get("popular_threat_classification", {})
    threat_label = classification.get("suggested_threat_label")

    # First seen date
    first_seen = attrs.get("first_submission_date")

    # Community votes
    community = attrs.get("total_votes", {})
    community_score = community.get("malicious", 0) - community.get("harmless", 0)

    # Built field by field rather than by copying anything from the
    # request, so the key has no path into the report. reporting/shared.py
    # strips credentials recursively as a second line of defence.
    # Build data dict — NEVER include the API key
    data = {
        "sha256": sha256,
        "found": True,
        "detection_ratio": f"{detections}/{total_engines}",
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "total_engines": total_engines,
        "threat_label": threat_label,
        "first_seen": first_seen,
        "community_score": community_score,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }

    # ── Scoring ──
    score_delta, reason = _compute_score(detections, total_engines, threat_label)

    return {
        "module": "virustotal",
        "status": "success",
        "data": data,
        "score_delta": score_delta,
        "reason": reason,
    }


def _compute_score(detections: int, total_engines: int, threat_label: str | None) -> tuple[int, str]:
    """Determine score_delta and reason from VT detections.

    Args:
        detections:    malicious + suspicious engine count.
        total_engines: Engines that returned any verdict.
        threat_label:  VT's suggested family label, if it has one.

    Returns:
        ``(score_delta, reason)``.

    Scoring rules (see docs/scoring.md):
      >10 engines detect  → +25
      1–10 engines detect → +10
      0 detections (found) →  -5  (seen but no detections = mild reassurance)

    The asymmetry is intentional. Consensus among many engines is strong
    evidence of malice; the absence of detections is weak evidence of
    safety, because signatures lag new builds by days. The 10-engine
    threshold separates a genuine consensus from the one or two engines
    that flag half of all packed software.
    """
    if detections > 10:
        label_part = f" ({threat_label})" if threat_label else ""
        return 25, f"VirusTotal: {detections}/{total_engines} engines flagged malicious{label_part}"

    if detections >= 1:
        label_part = f" ({threat_label})" if threat_label else ""
        return 10, f"VirusTotal: {detections}/{total_engines} engines flagged malicious{label_part}"

    return -5, f"VirusTotal: 0/{total_engines} detections — hash seen but no engines flagged it"


def _sha256(file_path: Path) -> str | None:
    """Compute SHA256 of a file.  Returns None on read error.

    Args:
        file_path: File to hash.

    Returns:
        Lowercase hex digest, or None if the file could not be read.

    Streamed in 64 KiB chunks so a multi-gigabyte sample never lands in
    memory. Recomputed here rather than reused from file_intake so this
    module always hashes the file it was actually given.
    """
    try:
        h = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.error("Could not read file for SHA256: %s", exc)
        return None


def _skipped(reason: str) -> dict:
    """Build a skipped result — no key, no library, nothing was asked."""
    return {
        "module": "virustotal",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    """Build an error result — the lookup was attempted and failed.

    Distinct from a skip so the report can say "VirusTotal was not
    consulted" rather than "VirusTotal found nothing". Both score 0: a
    lookup that did not happen must not move the verdict either way.
    """
    return {
        "module": "virustotal",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
