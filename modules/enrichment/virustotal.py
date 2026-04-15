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
"""

import hashlib
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

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
    api_key = config.get("virustotal_api_key", "").strip()

    if not api_key:
        return _skipped("No VirusTotal API key configured")

    if not _HAS_REQUESTS:
        return _skipped("requests library not installed")

    # Compute SHA256 locally (never send the file).
    sha256 = _sha256(file_path)
    if sha256 is None:
        return _error("Could not compute SHA256 hash")

    timeout = config.get("module_timeout_seconds", 60)
    max_retries = 2  # Retry up to 2 times on rate limit

    resp = _request_with_retry(sha256, api_key, timeout, max_retries)
    if isinstance(resp, dict):
        # _request_with_retry returned an error/skip result dict directly
        return resp

    # ── Handle response status codes ──
    if resp.status_code == 404:
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
    """Walk prior module results for embedded PE/ELF hashes to VT-forward."""
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
    """Look up each unique embedded SHA256 on VT. Cap score contribution."""
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
        attrs = body.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
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

    delta = min(hits * 2, 10)
    reason = ""
    if hits:
        reason = f"VirusTotal: {hits} embedded executable hash(es) flagged"
    return results, delta, reason


def _request_with_retry(
    sha256: str, api_key: str, timeout: int, max_retries: int
) -> "requests.Response | dict":
    """Make the VT API request with automatic retry on HTTP 429.

    Returns the Response object on success, or a module error dict if
    all attempts fail due to network/timeout errors.
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

        # Rate limited — check Retry-After header, default to 60s
        retry_after = resp.headers.get("Retry-After")
        try:
            wait_seconds = int(retry_after) if retry_after else 60
        except (ValueError, TypeError):
            wait_seconds = 60

        # Cap wait to something reasonable (max 120s)
        wait_seconds = min(wait_seconds, 120)

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
    """Extract detection stats, threat label, and metadata from VT response."""
    attrs = body.get("data", {}).get("attributes", {})

    # Detection statistics
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    type_unsupported = stats.get("type-unsupported", 0)
    failure = stats.get("failure", 0)
    total_engines = malicious + suspicious + undetected + harmless + type_unsupported + failure

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

    Scoring rules (from CLAUDE.md):
      >10 engines detect  → +25
      1–10 engines detect → +10
      0 detections (found) →  -5  (seen but no detections = mild reassurance)
    """
    if detections > 10:
        label_part = f" ({threat_label})" if threat_label else ""
        return 25, f"VirusTotal: {detections}/{total_engines} engines flagged malicious{label_part}"

    if detections >= 1:
        label_part = f" ({threat_label})" if threat_label else ""
        return 10, f"VirusTotal: {detections}/{total_engines} engines flagged malicious{label_part}"

    return -5, f"VirusTotal: 0/{total_engines} detections — hash seen but no engines flagged it"


def _sha256(file_path: Path) -> str | None:
    """Compute SHA256 of a file.  Returns None on read error."""
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
    return {
        "module": "virustotal",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }


def _error(reason: str) -> dict:
    return {
        "module": "virustotal",
        "status": "error",
        "data": {},
        "score_delta": 0,
        "reason": reason,
    }
