"""The lockfile's invariants, because a lockfile rots silently.

`requirements.lock` exists because every dependency in `pyproject.toml` is
specified with `>=` and no upper bound, so two installs of the same commit
produced different builds — measured, a hermetic install resolved
`click==8.5.0` on the same day the development venv held `8.3.1`.

Nothing about a stale lockfile looks wrong. The file still parses, the build
still succeeds, and the drift only shows up as behaviour that differs between
two machines months later. So the invariants are checked mechanically.
"""

import re
import tomllib
from pathlib import Path

import pytest

# Anchored to the repository, not to pytest's working directory: these tests
# read project files, and a relative path silently changes meaning depending
# on where pytest was invoked from.
ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "requirements.lock"
PYPROJECT = ROOT / "pyproject.toml"


def _read(path: Path) -> str:
    """Read a project file as UTF-8 explicitly.

    `Path.read_text()` uses the locale encoding, which is cp1252 on a
    default Windows install — and this lockfile's header contains em dashes,
    so an implicit read is a real decode risk rather than a theoretical one.
    Requirements files and TOML are both defined as UTF-8.
    """
    return path.read_text(encoding="utf-8")


def _normalise(name: str) -> str:
    """Canonical distribution name, per PEP 503.

    One function, used by **both** the lockfile side and the pyproject side.
    They were separate for one review round and the pyproject side forgot the
    underscore rule — the same asymmetry that bit the archive path mapper,
    where two copies of "the same file" drifted four times and every drift
    was a hole. PyPI treats `flare_capa` and `flare-capa` as one project, so
    anything comparing names must too.
    """
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _split_spec(spec: str) -> tuple[str, str | None]:
    """Split a requirement into (normalised name, pinned version or None).

    Tolerates the shapes a requirement can legally take beyond `a==1`:
    environment markers (`; python_version < "3.13"`), extras
    (`pkg[extra]==1`) and surrounding whitespace. The `tools` extra is
    exactly pinned and a separate test enforces that, but this parser is
    also pointed at the lockfile, and being strict here would make a
    perfectly valid file look broken.
    """
    spec = spec.split(";", 1)[0].strip()          # drop any marker
    m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*(.+)$", spec)
    if m:
        return _normalise(m.group(1)), m.group(2).strip()
    m = re.match(r"^([A-Za-z0-9._-]+)", spec)
    return (_normalise(m.group(1)) if m else spec), None


def _pins() -> dict[str, str | None]:
    """Return {normalised name: version} for every pin in the lockfile."""
    out = {}
    for line in _read(LOCK).splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        name, version = _split_spec(s)
        out[name] = version
    return out


def test_the_lockfile_exists_and_is_not_empty():
    assert LOCK.is_file(), "requirements.lock is what makes the image reproducible"
    assert len(_pins()) > 50


def test_every_line_is_exactly_pinned():
    """A `>=` in a lockfile defeats the entire point of having one."""
    loose = []
    for line in _read(LOCK).splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "==" not in s:
            loose.append(s)
    assert not loose, f"not exactly pinned: {loose}"


def test_the_project_does_not_pin_itself():
    """`pip freeze` emits `threatlens @ file:///abs/path`.

    That is unbuildable on any other machine and leaks a local absolute
    path into a tracked file. The image copies the source to /app and runs
    it from there; it never installs the project as a package.
    """
    pins = _pins()
    assert not [p for p in pins if p.startswith("threatlens")]


def test_no_local_paths_leak_into_the_lockfile():
    body = "\n".join(
        l for l in _read(LOCK).splitlines()
        if l.strip() and not l.lstrip().startswith("#")
    )
    assert "file://" not in body
    assert "/home/" not in body


@pytest.mark.parametrize("package", ["flare-capa", "flare-floss"])
def test_the_external_tools_agree_with_pyproject(package):
    """The one drift that would be actively harmful.

    capa's rule set and FLIRT signatures are fetched separately and pinned
    to the git tag matching the capa version. If `pyproject.toml` and the
    lockfile disagree about that version, the image installs one capa and
    downloads another capa's rules — and capa does not loudly refuse a
    mismatched rule set, it just matches differently.
    """
    data = tomllib.loads(_read(PYPROJECT))
    tools = data["project"]["optional-dependencies"]["tools"]
    declared = dict(_split_spec(spec) for spec in tools)

    package = _normalise(package)
    assert package in declared, f"{package} missing from the tools extra"
    locked = _pins().get(package)
    assert locked is not None, f"{package} missing from requirements.lock"
    assert locked == declared[package], (
        f"{package}: pyproject pins {declared[package]}, lockfile pins {locked}"
    )


def test_the_optional_c_hasher_is_locked():
    """`ssdeep` is opt-in on the host but always present in the image.

    It needs libfuzzy-dev and `--no-build-isolation`, which the builder
    stage provides. Without it `file_intake` falls back to `ppdeep`, which
    is ~350x slower and skips files over 8 MiB entirely.
    """
    assert "ssdeep" in _pins()
