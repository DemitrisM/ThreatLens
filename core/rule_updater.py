"""YARA rule source manager — clone, update, validate, and report.

Manages git-based YARA rule repositories. Called by the ``rules update`` CLI
command in ``cli/rules.py``. Returns data dicts that the CLI layer formats;
nothing here prints.

Design notes
------------
Every function returns data, never output. That split is what lets
``rules update``, ``--check`` and ``--validate-only`` share one code path and
differ only in which dicts the CLI renders.

Git is driven through the ``git`` binary rather than a library, because the
rule sources are ordinary public repositories and shelling out avoids adding
GitPython to the dependency list for four commands' worth of work. Every git
call is timeout-bounded — a hung clone against an unreachable remote must not
wedge the CLI.

Failures are reported, not raised. Updating rules is a maintenance action a
user may run offline or behind a proxy; the command should say what could not
be done and exit cleanly.
"""

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Written into the rules directory to record what was fetched and when.
# Leading dot keeps it out of the *.yar globs used to count rule files.
_METADATA_FILENAME = ".rule_sources.json"

# Fallback used only when config supplies no usable rule_sources list.
# NOTE: duplicates config_loader.DEFAULTS["rule_sources"]; the two can drift.
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
    """Return True if git is on PATH and runnable.

    Returns:
        True when ``git --version`` exits 0. Checked once up front by
        ``update_all_sources`` so the command can report a single clear
        cause instead of failing per source.
    """
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
    """Run a git command and return (returncode, stdout, stderr).

    The single choke point for every git invocation in this module, so the
    timeout and the never-raise guarantee are enforced in one place.

    Args:
        args:    Arguments after ``git``, already split.
        cwd:     Repository to run in, or None for a cwd-independent command.
        timeout: Seconds before the subprocess is killed.

    Returns:
        ``(returncode, stdout, stderr)`` with both streams stripped. A
        returncode of -1 means git never ran or was killed, with the cause
        in stderr. Never raises.
    """
    # No shell=True: the URLs and branch names come from a config file, and
    # passing them through a shell would make that file an injection vector.
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
    """Return the short commit hash at HEAD, or None.

    Args:
        target: Path to a cloned rule repository.

    Returns:
        Short hash, or None if *target* is not a readable git repository.
    """
    rc, out, _ = _run_git(["rev-parse", "--short", "HEAD"], cwd=target)
    return out if rc == 0 else None


def _get_commit_timestamp(target: Path) -> str | None:
    """Return ISO timestamp of HEAD commit, or None.

    Args:
        target: Path to a cloned rule repository.

    Returns:
        The author date in ISO 8601 with offset (``%aI``), which
        ``datetime.fromisoformat`` parses directly for the staleness
        calculation. None if the repository is unreadable.
    """
    rc, out, _ = _run_git(["log", "-1", "--format=%aI"], cwd=target)
    return out if rc == 0 else None


def _clone_repo(
    url: str,
    target: Path,
    branch: str,
    timeout: int = 300,
) -> tuple[bool, str]:
    """Clone a git repo. Returns (success, error_msg).

    Args:
        url:     Repository URL from the source config.
        target:  Destination directory; its parent is created if needed.
        branch:  Branch to check out.
        timeout: Seconds allowed — five minutes, well above the default
                 120s, because signature-base is a large first clone.

    Returns:
        ``(True, "")`` on success, or ``(False, message)``.
    """
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

    Args:
        target:  Path to a cloned rule repository.
        timeout: Seconds allowed for the pull.

    Returns:
        ``(success, error_msg, old_commit, new_commit)``. The two commits
        bracket the update so the caller can diff them for a change count;
        *new_commit* is None on failure.
    """
    # --ff-only on purpose: a rules directory is a mirror, not a working
    # copy. If local history diverged, fail loudly rather than produce a
    # merge commit in someone's rule set.
    old_commit = _get_current_commit(target)
    rc, _, err = _run_git(["pull", "--ff-only"], cwd=target, timeout=timeout)
    if rc != 0:
        return False, err or f"git pull exited with code {rc}", old_commit, None
    new_commit = _get_current_commit(target)
    return True, "", old_commit, new_commit


def _count_changed_files(
    target: Path, old_commit: str, new_commit: str,
) -> dict[str, int]:
    """Count new/modified/deleted rule files between two commits.

    Args:
        target:     Path to the repository.
        old_commit: Commit before the pull.
        new_commit: Commit after the pull.

    Returns:
        ``{"new": int, "modified": int, "deleted": int}``, all zero if the
        diff could not be produced — this is a cosmetic summary, so a
        failure here must not turn a successful update into an error.
    """
    # Pathspec restricts the diff to rule files: signature-base carries
    # READMEs and tooling whose churn is not interesting here.
    rc, out, _ = _run_git(
        ["diff", "--name-status", f"{old_commit}..{new_commit}",
         "--", "*.yar", "*.yara"],
        cwd=target,
    )
    changes = {"new": 0, "modified": 0, "deleted": 0}
    if rc != 0 or not out:
        return changes
    # --name-status lines are "<status>\t<path>". Rename statuses carry a
    # similarity score (R100), hence startswith rather than equality.
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
    """Count *.yar + *.yara files recursively.

    Args:
        directory: Directory to walk.

    Returns:
        Total rule-file count. Both extensions are in use across the
        upstream repositories, so both are counted.
    """
    count = 0
    for ext in ("*.yar", "*.yara"):
        count += sum(1 for _ in directory.rglob(ext))
    return count


def _fetch_remote(target: Path, timeout: int = 60) -> tuple[bool, str]:
    """Fetch from origin without merging. For --check mode.

    Args:
        target:  Path to the repository.
        timeout: Seconds allowed.

    Returns:
        ``(True, "")`` or ``(False, message)``. Fetching without merging is
        what makes ``--check`` a true dry run: it updates the remote
        tracking refs so the caller can count how far behind HEAD is,
        while leaving the working tree untouched.
    """
    rc, _, err = _run_git(["fetch", "origin"], cwd=target, timeout=timeout)
    if rc != 0:
        return False, err or f"git fetch exited with code {rc}"
    return True, ""


def _commits_behind(target: Path, branch: str) -> int:
    """Count commits HEAD is behind origin/<branch>.

    Args:
        target: Path to the repository.
        branch: Branch name to compare against.

    Returns:
        The count, or -1 if it could not be determined. -1 rather than 0
        so the caller can distinguish "up to date" from "unknown" and
        report the latter as an error.
    """
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
    """Load .rule_sources.json from rules_dir, or return empty dict.

    Args:
        rules_dir: Directory holding the rule repositories.

    Returns:
        The stored metadata, or ``{}`` when absent or unreadable. A
        corrupt metadata file degrades to "no history recorded" and is
        rewritten on the next successful update — it is a convenience
        record, never a source of truth.
    """
    path = rules_dir / _METADATA_FILENAME
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read rule metadata: %s", exc)
        return {}


def save_metadata(rules_dir: Path, metadata: dict) -> None:
    """Write .rule_sources.json atomically.

    Args:
        rules_dir: Directory holding the rule repositories.
        metadata:  Mapping of source name to its update record.

    A write failure is warned about, not raised: the rules themselves have
    already been updated successfully by this point, and losing the
    bookkeeping file must not turn that into a reported failure.
    """
    path = rules_dir / _METADATA_FILENAME
    try:
        # default=str so a stray datetime in the record serialises rather
        # than aborting the write.
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
    """Return enabled rule sources from config, with defaults as fallback.

    Args:
        config: Loaded configuration dict.

    Returns:
        Only sources with ``enabled`` true. A missing or malformed
        ``rule_sources`` falls back to ``_DEFAULT_SOURCES`` so the command
        still works against a hand-trimmed config file.
    """
    sources = config.get("rule_sources")
    if not sources or not isinstance(sources, list):
        return [s for s in _DEFAULT_SOURCES if s.get("enabled", True)]
    return [s for s in sources if s.get("enabled", True)]


def get_source_status(source: dict, rules_dir: Path) -> dict:
    """Return status info for a single rule source.

    Args:
        source:    One source entry from the config.
        rules_dir: Directory holding the rule repositories.

    Returns:
        A status dict with ``name``, ``exists``, ``commit``,
        ``last_updated``, ``rule_count`` and ``staleness_days``. Every key
        is always present so the CLI can render a uniform table; the
        fields are None or 0 when the source has not been cloned.
    """
    name = source["name"]
    target = rules_dir / source.get("directory", name)
    # The .git directory, not the directory itself: an empty or partially
    # deleted folder must not read as a working clone.
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

    # Staleness is the headline number: YARA rules age badly, and how long
    # ago upstream last committed is what tells an analyst whether a clean
    # scan means anything.
    ts = _get_commit_timestamp(target)
    if ts:
        status["last_updated"] = ts
        try:
            commit_dt = datetime.fromisoformat(ts)
            now = datetime.now(timezone.utc)
            status["staleness_days"] = (now - commit_dt).days
        except ValueError:
            # Unparseable timestamp — leave staleness None rather than
            # invent a number.
            pass

    return status


def update_source(
    source: dict,
    rules_dir: Path,
    *,
    force: bool = False,
) -> dict:
    """Clone or pull a single rule source.

    Args:
        source:    One source entry from the config.
        rules_dir: Directory holding the rule repositories.
        force:     Delete an existing clone and start again. The escape
                   hatch for a repository whose history diverged, since
                   ``_pull_repo`` refuses anything but a fast-forward.

    Returns:
        A result dict with ``action`` (one of ``skipped``, ``cloned``,
        ``pulled``, ``up_to_date``, ``error``), the bracketing commits,
        a change count, the rule count, and ``error``. Never raises.
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

    # ------------------------------------------------------------------
    # Step 1: Reject sources this module cannot handle.
    #
    # The type field exists so a future http/zip source can be added
    # without changing the config schema; today only git is implemented.
    # ------------------------------------------------------------------
    if src_type != "git":
        result["error"] = f"source type '{src_type}' not yet supported"
        logger.warning("Rule source '%s': type '%s' not supported", name, src_type)
        return result

    url = source.get("url")
    branch = source.get("branch", "master")

    if not url:
        result["error"] = "no URL configured"
        return result

    # ------------------------------------------------------------------
    # Step 2: Honour --force by removing the existing clone first.
    #
    # Scoped to the configured directory under rules_dir, and only reached
    # when the caller explicitly asked for it.
    # ------------------------------------------------------------------
    if force and target.exists():
        logger.info("Force mode: removing %s", target)
        try:
            shutil.rmtree(target)
        except OSError as exc:
            result["action"] = "error"
            result["error"] = f"failed to remove directory: {exc}"
            return result

    # ------------------------------------------------------------------
    # Step 3: Clone if absent. A first clone has no previous commit to
    # diff against, so it reports counts but no change breakdown.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 4: Otherwise pull, and distinguish a real update from a no-op
    # by comparing the bracketing commits. Only a genuine change is worth
    # the extra git call to count the diff.
    # ------------------------------------------------------------------
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
    """Dry-run: check if updates are available without applying them.

    Args:
        source:    One source entry from the config.
        rules_dir: Directory holding the rule repositories.

    Returns:
        An info dict with ``exists``, ``has_updates``, ``local_commit``,
        ``remote_commit``, ``commits_behind`` and ``error``. Backs
        ``rules update --check``; nothing on disk is modified except the
        remote tracking refs the fetch updates.
    """
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

    # A source that was never cloned counts as having updates: from the
    # user's point of view, running the update would fetch something.
    if not info["exists"]:
        info["has_updates"] = True
        return info

    info["local_commit"] = _get_current_commit(target)

    # ------------------------------------------------------------------
    # Fetch, then count. The fetch is what makes origin/<branch> current;
    # without it the count would compare against stale tracking refs and
    # report "up to date" for a repository that is months behind.
    # ------------------------------------------------------------------
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

    # Only resolve the remote hash when there is actually something to
    # show — it is one more subprocess, and pointless when up to date.
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
    """Compile all .yar/.yara files individually and report results.

    Args:
        rules_dir: Directory holding the rule repositories.

    Returns:
        ``{"total_files", "valid_count", "broken_count", "broken_files"}``,
        plus ``skipped_reason`` when yara-python is unavailable.
    """
    # ------------------------------------------------------------------
    # Step 1: yara-python is optional, so its absence is a skip with a
    # stated reason rather than an error (design rule 2). Imported here
    # rather than at module scope so `rules update --check` works on a
    # machine without the engine at all.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 2: Supply the external variables the upstream rules reference.
    #
    # signature-base rules test filename/extension/filetype conditions. A
    # rule referencing an undefined external fails to compile at all, so
    # these must be declared here even though validation matches nothing —
    # otherwise every such rule would be reported as broken.
    # ------------------------------------------------------------------
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
    # set() because a file matching both globs would otherwise be counted
    # twice; sorted() to keep the broken-file list stable between runs.
    rule_files = sorted(set(rule_files))

    # ------------------------------------------------------------------
    # Step 3: Compile one file at a time.
    #
    # Deliberately not a bulk compile: bulk compilation aborts on the
    # first bad rule and names only that one, whereas the point of this
    # pass is to identify every broken file so the scanner can exclude
    # them and keep working.
    # ------------------------------------------------------------------
    broken: list[dict] = []
    valid = 0
    for rf in rule_files:
        try:
            yara.compile(filepath=str(rf), externals=externals)
            valid += 1
        except yara.SyntaxError as exc:
            # Paths are stored relative to rules_dir so the report reads
            # the same regardless of where the project is checked out.
            broken.append({"file": str(rf.relative_to(rules_dir)), "error": str(exc)})
        except yara.Error as exc:
            # Non-syntax engine errors — a rule exceeding an internal
            # limit, an unsupported module import.
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

    Args:
        config:     Loaded configuration dict.
        force:      Re-clone every source from scratch.
        check_only: Report what would change without changing it.

    Returns:
        An aggregate dict with ``git_available``, a per-source result
        list, and ``validation`` (None in check mode). The CLI formats it.
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

    # Without git nothing below can work. Return the flag and let the CLI
    # explain it once, rather than emitting the same error per source.
    if not report["git_available"]:
        return report

    # ------------------------------------------------------------------
    # Step 1: Process each source. check_only swaps the whole operation
    # for its read-only counterpart — that branch is the only difference
    # between the two modes.
    # ------------------------------------------------------------------
    for source in sources:
        if check_only:
            info = check_source_updates(source, rules_dir)
            report["sources"].append(info)
        else:
            result = update_source(source, rules_dir, force=force)
            report["sources"].append(result)

            # Record only sources that actually did something. Note the
            # fallback to old_commit: an "up_to_date" source still has a
            # valid current commit worth stamping with today's check.
            if result["action"] not in ("error", "skipped"):
                now_utc = datetime.now(timezone.utc).isoformat()
                metadata[source["name"]] = {
                    "last_updated_utc": now_utc,
                    "commit": result.get("new_commit") or result.get("old_commit"),
                    "rule_count": result.get("rule_count", 0),
                    "url": source.get("url", ""),
                }

    # ------------------------------------------------------------------
    # Step 2: Persist the record and compile-check what was fetched.
    #
    # Both are skipped in check mode, which must leave no trace: nothing
    # was written, so there is nothing to record or validate.
    # ------------------------------------------------------------------
    if not check_only:
        save_metadata(rules_dir, metadata)
        report["validation"] = validate_rules(rules_dir)

    return report
