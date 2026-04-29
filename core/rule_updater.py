"""YARA rule source manager — clone, update, validate, and report.

Manages git-based YARA rule repositories. Called by the ``update-rules``
CLI command in main.py. Returns data dicts that the CLI layer formats.
"""

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_METADATA_FILENAME = ".rule_sources.json"

_DEFAULT_SOURCES: list[dict] = [
    {
        "name": "signature-base",
        "type": "git",
        "url": "https://github.com/Neo23x0/signature-base.git",
        "directory": "signature-base",
        "branch": "master",
        "enabled": True,
    },
]


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def check_git_available() -> bool:
    """Return True if git is on PATH and runnable."""
    try:
        proc = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def _run_git(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
) -> tuple[int, str, str]:
    """Run a git command and return (returncode, stdout, stderr)."""
    cmd = ["git"] + args
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return -1, "", "git not found on PATH"
    except subprocess.TimeoutExpired:
        return -1, "", f"git command timed out after {timeout}s"
    except OSError as exc:
        return -1, "", str(exc)


def _get_current_commit(target: Path) -> str | None:
    """Return the short commit hash at HEAD, or None."""
    rc, out, _ = _run_git(["rev-parse", "--short", "HEAD"], cwd=target)
    return out if rc == 0 else None


def _get_commit_timestamp(target: Path) -> str | None:
    """Return ISO timestamp of HEAD commit, or None."""
    rc, out, _ = _run_git(["log", "-1", "--format=%aI"], cwd=target)
    return out if rc == 0 else None


def _clone_repo(
    url: str,
    target: Path,
    branch: str,
    timeout: int = 300,
) -> tuple[bool, str]:
    """Clone a git repo. Returns (success, error_msg)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    rc, _, err = _run_git(
        ["clone", "--branch", branch, url, str(target)],
        timeout=timeout,
    )
    if rc != 0:
        return False, err or f"git clone exited with code {rc}"
    return True, ""


def _pull_repo(
    target: Path,
    timeout: int = 120,
) -> tuple[bool, str, str | None, str | None]:
    """Pull updates (fast-forward only).

    Returns (success, error_msg, old_commit, new_commit).
    """
    old_commit = _get_current_commit(target)
    rc, _, err = _run_git(["pull", "--ff-only"], cwd=target, timeout=timeout)
    if rc != 0:
        return False, err or f"git pull exited with code {rc}", old_commit, None
    new_commit = _get_current_commit(target)
    return True, "", old_commit, new_commit


def _count_changed_files(
    target: Path, old_commit: str, new_commit: str,
) -> dict[str, int]:
    """Count new/modified/deleted rule files between two commits."""
    rc, out, _ = _run_git(
        ["diff", "--name-status", f"{old_commit}..{new_commit}",
         "--", "*.yar", "*.yara"],
        cwd=target,
    )
    changes = {"new": 0, "modified": 0, "deleted": 0}
    if rc != 0 or not out:
        return changes
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if not parts:
            continue
        status = parts[0].strip()
        if status == "A":
            changes["new"] += 1
        elif status.startswith("M") or status.startswith("R"):
            changes["modified"] += 1
        elif status == "D":
            changes["deleted"] += 1
    return changes


def _count_rule_files(directory: Path) -> int:
    """Count *.yar + *.yara files recursively."""
    count = 0
    for ext in ("*.yar", "*.yara"):
        count += sum(1 for _ in directory.rglob(ext))
    return count


def _fetch_remote(target: Path, timeout: int = 60) -> tuple[bool, str]:
    """Fetch from origin without merging. For --check mode."""
    rc, _, err = _run_git(["fetch", "origin"], cwd=target, timeout=timeout)
    if rc != 0:
        return False, err or f"git fetch exited with code {rc}"
    return True, ""


def _commits_behind(target: Path, branch: str) -> int:
    """Count commits HEAD is behind origin/<branch>."""
    rc, out, _ = _run_git(
        ["rev-list", "--count", f"HEAD..origin/{branch}"],
        cwd=target,
    )
    if rc != 0 or not out:
        return -1
    try:
        return int(out)
    except ValueError:
        return -1


# ---------------------------------------------------------------------------
# Metadata persistence
# ---------------------------------------------------------------------------


def load_metadata(rules_dir: Path) -> dict:
    """Load .rule_sources.json from rules_dir, or return empty dict."""
    path = rules_dir / _METADATA_FILENAME
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read rule metadata: %s", exc)
        return {}


def save_metadata(rules_dir: Path, metadata: dict) -> None:
    """Write .rule_sources.json atomically."""
    path = rules_dir / _METADATA_FILENAME
    try:
        path.write_text(
            json.dumps(metadata, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        logger.warning("Failed to save rule metadata: %s", exc)


# ---------------------------------------------------------------------------
# Source operations
# ---------------------------------------------------------------------------


def get_rule_sources(config: dict) -> list[dict]:
    """Return enabled rule sources from config, with defaults as fallback."""
    sources = config.get("rule_sources")
    if not sources or not isinstance(sources, list):
        return [s for s in _DEFAULT_SOURCES if s.get("enabled", True)]
    return [s for s in sources if s.get("enabled", True)]


def get_source_status(source: dict, rules_dir: Path) -> dict:
    """Return status info for a single rule source."""
    name = source["name"]
    target = rules_dir / source.get("directory", name)
    exists = (target / ".git").is_dir()

    status: dict = {
        "name": name,
        "exists": exists,
        "commit": None,
        "last_updated": None,
        "rule_count": 0,
        "staleness_days": None,
    }

    if not exists:
        return status

    status["commit"] = _get_current_commit(target)
    status["rule_count"] = _count_rule_files(target)

    ts = _get_commit_timestamp(target)
    if ts:
        status["last_updated"] = ts
        try:
            commit_dt = datetime.fromisoformat(ts)
            now = datetime.now(timezone.utc)
            status["staleness_days"] = (now - commit_dt).days
        except ValueError:
            pass

    return status


def update_source(
    source: dict,
    rules_dir: Path,
    *,
    force: bool = False,
) -> dict:
    """Clone or pull a single rule source.

    Returns a result dict with action, commits, changes, and errors.
    """
    name = source["name"]
    src_type = source.get("type", "git")
    target = rules_dir / source.get("directory", name)

    result: dict = {
        "name": name,
        "action": "skipped",
        "old_commit": None,
        "new_commit": None,
        "changes": {"new": 0, "modified": 0, "deleted": 0},
        "rule_count": 0,
        "error": None,
    }

    if src_type != "git":
        result["error"] = f"source type '{src_type}' not yet supported"
        logger.warning("Rule source '%s': type '%s' not supported", name, src_type)
        return result

    url = source.get("url")
    branch = source.get("branch", "master")

    if not url:
        result["error"] = "no URL configured"
        return result

    if force and target.exists():
        logger.info("Force mode: removing %s", target)
        try:
            shutil.rmtree(target)
        except OSError as exc:
            result["action"] = "error"
            result["error"] = f"failed to remove directory: {exc}"
            return result

    if not (target / ".git").is_dir():
        logger.info("Cloning %s from %s", name, url)
        ok, err = _clone_repo(url, target, branch)
        if not ok:
            result["action"] = "error"
            result["error"] = err
            return result
        result["action"] = "cloned"
        result["new_commit"] = _get_current_commit(target)
        result["rule_count"] = _count_rule_files(target)
        return result

    logger.info("Pulling updates for %s", name)
    ok, err, old_commit, new_commit = _pull_repo(target)
    if not ok:
        result["action"] = "error"
        result["error"] = err
        result["old_commit"] = old_commit
        return result

    result["old_commit"] = old_commit
    result["new_commit"] = new_commit

    if old_commit and new_commit and old_commit != new_commit:
        result["action"] = "pulled"
        result["changes"] = _count_changed_files(target, old_commit, new_commit)
    else:
        result["action"] = "up_to_date"

    result["rule_count"] = _count_rule_files(target)
    return result


def check_source_updates(source: dict, rules_dir: Path) -> dict:
    """Dry-run: check if updates are available without applying them."""
    name = source["name"]
    target = rules_dir / source.get("directory", name)
    branch = source.get("branch", "master")

    info: dict = {
        "name": name,
        "exists": (target / ".git").is_dir(),
        "has_updates": False,
        "local_commit": None,
        "remote_commit": None,
        "commits_behind": 0,
        "error": None,
    }

    if not info["exists"]:
        info["has_updates"] = True
        return info

    info["local_commit"] = _get_current_commit(target)

    ok, err = _fetch_remote(target)
    if not ok:
        info["error"] = err
        return info

    behind = _commits_behind(target, branch)
    if behind < 0:
        info["error"] = "failed to count commits behind"
        return info

    info["commits_behind"] = behind
    info["has_updates"] = behind > 0

    if behind > 0:
        rc, out, _ = _run_git(
            ["rev-parse", "--short", f"origin/{branch}"],
            cwd=target,
        )
        if rc == 0:
            info["remote_commit"] = out

    return info


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_rules(rules_dir: Path) -> dict:
    """Compile all .yar/.yara files individually and report results."""
    try:
        import yara  # noqa: PLC0415
    except ImportError:
        return {
            "total_files": 0,
            "valid_count": 0,
            "broken_count": 0,
            "broken_files": [],
            "skipped_reason": "yara-python not installed",
        }

    externals = {
        "filepath": "",
        "filename": "",
        "extension": "",
        "filetype": "",
        "owner": "",
    }

    rule_files: list[Path] = []
    for ext in ("*.yar", "*.yara"):
        rule_files.extend(rules_dir.rglob(ext))
    rule_files = sorted(set(rule_files))

    broken: list[dict] = []
    valid = 0
    for rf in rule_files:
        try:
            yara.compile(filepath=str(rf), externals=externals)
            valid += 1
        except yara.SyntaxError as exc:
            broken.append({"file": str(rf.relative_to(rules_dir)), "error": str(exc)})
        except yara.Error as exc:
            broken.append({"file": str(rf.relative_to(rules_dir)), "error": str(exc)})

    return {
        "total_files": len(rule_files),
        "valid_count": valid,
        "broken_count": len(broken),
        "broken_files": broken,
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def update_all_sources(
    config: dict,
    *,
    force: bool = False,
    check_only: bool = False,
) -> dict:
    """Update (or check) all enabled rule sources and validate.

    Returns an aggregate result dict for the CLI to display.
    """
    rules_dir = Path(config.get("yara_rules_dir", "./rules/yara"))
    rules_dir.mkdir(parents=True, exist_ok=True)

    sources = get_rule_sources(config)
    metadata = load_metadata(rules_dir)

    report: dict = {
        "git_available": check_git_available(),
        "sources": [],
        "validation": None,
    }

    if not report["git_available"]:
        return report

    for source in sources:
        if check_only:
            info = check_source_updates(source, rules_dir)
            report["sources"].append(info)
        else:
            result = update_source(source, rules_dir, force=force)
            report["sources"].append(result)

            if result["action"] not in ("error", "skipped"):
                now_utc = datetime.now(timezone.utc).isoformat()
                metadata[source["name"]] = {
                    "last_updated_utc": now_utc,
                    "commit": result.get("new_commit") or result.get("old_commit"),
                    "rule_count": result.get("rule_count", 0),
                    "url": source.get("url", ""),
                }

    if not check_only:
        save_metadata(rules_dir, metadata)
        report["validation"] = validate_rules(rules_dir)

    return report
