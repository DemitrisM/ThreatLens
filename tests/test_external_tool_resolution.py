"""How ThreatLens finds and invokes its two external tools.

Two separate concerns, both changed for 0.6.0:

**Resolution.** `capa_binary` and `floss_binary` used to be paths only
(`./bin/capa`). They are now command names resolved on `PATH`, because the
container installs the tools as console scripts. The resolution rule is
security-relevant, not cosmetic — see
``test_a_bare_name_ignores_a_same_named_file_in_the_cwd``.

**capa's rule set.** The PyInstaller bundle embeds capa's rules and FLIRT
signatures; the PyPI package does not and exits 10 without them. So the
rules and signatures directories are configurable and passed as ``-r`` and
``-s``. Both default to ``None`` — meaning "not configured" — so an install
still using the bundled binary is completely unaffected.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest


def _make_executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


# ======================================================================
# Resolution
# ======================================================================
def test_a_bare_name_resolves_through_path():
    """The PATH branch, using a command guaranteed to exist and be runnable.

    Deliberately not a temp-directory fixture. `shutil.which` decides with
    `os.access(path, os.X_OK)`, and Docker mounts `--tmpfs /tmp` as
    `rw,nosuid,nodev,noexec` — so a file created under pytest's `tmp_path`
    inside the container is never executable however its mode bits are set,
    and a test built on one fails on a false premise. That noexec mount is
    worth keeping: extracted malware lands in /tmp. `sh` is on PATH in any
    POSIX environment, host or image, so the branch is tested against a real
    executable and no filesystem is fought.
    """
    from modules.static._bundled_tool import resolve_tool

    resolved = resolve_tool("sh")
    assert resolved is not None
    assert resolved.is_file()
    assert resolved == Path(shutil.which("sh")).resolve()


def test_a_bare_name_ignores_a_same_named_file_in_the_cwd(tmp_path, monkeypatch):
    """The security case, and the reason a bare name must not be a path.

    The container sets its working directory to the folder of samples under
    analysis. If a bare name were tested with `Path(name).exists()`, a sample
    sitting there would satisfy it and ThreatLens would execute the malware
    instead of the tool.

    The decoy is deliberately **not** executable, which makes the test
    stronger rather than weaker: `Path(name).exists()` does not care about
    the execute bit, so a plain file is enough to catch that mistake — and
    it needs nothing from the filesystem, so the test behaves identically on
    the host and inside a noexec container.
    """
    from modules.static._bundled_tool import resolve_tool

    real = Path(shutil.which("sh")).resolve()

    decoy = tmp_path / "sh"
    decoy.write_text("#!/bin/sh\nexit 66\n")
    monkeypatch.chdir(tmp_path)
    assert decoy.exists(), "the decoy must exist, or the test proves nothing"

    resolved = resolve_tool("sh")
    assert resolved == real, "a bare name must never resolve against the CWD"
    assert resolved != decoy.resolve()


def test_a_bare_name_is_resolved_by_which_and_nothing_else(monkeypatch):
    """Pin the mechanism, not just the outcome.

    The decoy test above proves a bare name does not resolve to a CWD file,
    but it cannot catch every way of getting there: a decoy that is not
    executable would also be rejected by `os.access(name, os.X_OK)`, so
    swapping `shutil.which` for a hand-rolled CWD check would still pass it.

    This asserts the branch delegates to `shutil.which` and returns what it
    says — so a reimplementation that consults the filesystem directly fails
    here even if its answer happens to be right on the test machine.
    """
    from modules.static import _bundled_tool

    sentinel = Path("/nowhere/real/capa")
    seen = []

    def _fake_which(name, *a, **kw):
        seen.append(name)
        return str(sentinel)

    monkeypatch.setattr(_bundled_tool.shutil, "which", _fake_which)
    resolved = _bundled_tool.resolve_tool("capa")

    assert seen == ["capa"], "the bare name must be handed to shutil.which verbatim"
    assert resolved == sentinel, "and its answer must be what is returned"


def test_a_value_with_a_separator_is_treated_as_a_path(tmp_path, monkeypatch):
    from modules.static._bundled_tool import resolve_tool

    monkeypatch.chdir(tmp_path)
    (tmp_path / "bin").mkdir()
    explicit = _make_executable(tmp_path / "bin" / "capa")

    assert resolve_tool("./bin/capa") == explicit
    assert resolve_tool(str(explicit)) == explicit


def test_an_unresolvable_name_returns_none(tmp_path, monkeypatch):
    from modules.static._bundled_tool import resolve_tool

    monkeypatch.setenv("PATH", str(tmp_path))
    assert resolve_tool("capa") is None
    assert resolve_tool("./bin/nope") is None


def test_a_directory_is_not_a_tool(tmp_path, monkeypatch):
    from modules.static._bundled_tool import resolve_tool

    monkeypatch.chdir(tmp_path)
    (tmp_path / "capa-dir").mkdir()
    assert resolve_tool("./capa-dir") is None


def test_a_malformed_setting_does_not_raise():
    """Design rule 2: a config typo must not kill the pipeline.

    The value comes from YAML, so YAML picks its type. `capa_binary: true`
    arrives as a bool and `capa_binary: 123` as an int; both reached the
    separator test and raised `TypeError: argument of type 'bool' is not
    iterable`, taking the whole scan with them. Verified against five types
    before the guard was added.
    """
    from modules.static._bundled_tool import resolve_tool

    for bad in (True, 123, 4.5, ["capa"], {"a": 1}, object()):
        assert resolve_tool(bad) is None, f"{bad!r} should resolve to nothing"


def test_a_malformed_setting_degrades_the_module_not_the_scan(tmp_path):
    from modules.static import capa_analysis

    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r = capa_analysis.run(sample, {"capa_binary": True})
    assert r["status"] == "skipped"
    assert r["score_delta"] == 0


# ======================================================================
# capa still skips gracefully when the tool is absent (design rule 2)
# ======================================================================
def test_capa_skips_when_the_binary_cannot_be_resolved(tmp_path, monkeypatch):
    from modules.static import capa_analysis

    monkeypatch.setenv("PATH", str(tmp_path))
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")

    r = capa_analysis.run(sample, {"capa_binary": "capa"})
    assert r["status"] == "skipped"
    assert r["score_delta"] == 0
    assert r["module"] == "capa_analysis"


# ======================================================================
# capa rules and signatures
# ======================================================================
def _capture_cmd(recorder):
    def _run(cmd, **kwargs):
        recorder.append(cmd)
        raise subprocess.TimeoutExpired(cmd, 1)
    return _run


def test_no_rules_flags_when_unconfigured(tmp_path, monkeypatch):
    """The compatibility seam: an install using the bundle is untouched."""
    from modules.static import capa_analysis

    seen: list = []
    monkeypatch.setattr(capa_analysis.subprocess, "run", _capture_cmd(seen))
    capa = _make_executable(tmp_path / "capa")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")

    capa_analysis.run(sample, {"capa_binary": str(capa)})
    assert seen, "capa was never invoked"
    assert "-r" not in seen[0]
    assert "-s" not in seen[0]


def test_rules_and_signature_flags_are_passed_when_the_dirs_exist(tmp_path, monkeypatch):
    from modules.static import capa_analysis

    seen: list = []
    monkeypatch.setattr(capa_analysis.subprocess, "run", _capture_cmd(seen))
    capa = _make_executable(tmp_path / "capa")
    rules = tmp_path / "capa-rules"; rules.mkdir()
    sigs = tmp_path / "capa-sigs"; sigs.mkdir()
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")

    capa_analysis.run(sample, {
        "capa_binary": str(capa),
        "capa_rules_dir": str(rules),
        "capa_signatures_dir": str(sigs),
    })
    cmd = seen[0]
    assert "-r" in cmd and cmd[cmd.index("-r") + 1] == str(rules)
    assert "-s" in cmd and cmd[cmd.index("-s") + 1] == str(sigs)


def test_configured_but_missing_rules_dir_skips_loudly(tmp_path, monkeypatch):
    """A silent zero-capability result would read as 'nothing found'.

    Same class as the FLOSS degraded-run defect in 0.5.13: a skip that
    renders as a finding. The reason must name the path.
    """
    from modules.static import capa_analysis

    seen: list = []
    monkeypatch.setattr(capa_analysis.subprocess, "run", _capture_cmd(seen))
    capa = _make_executable(tmp_path / "capa")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    missing = tmp_path / "not-here"

    r = capa_analysis.run(sample, {
        "capa_binary": str(capa),
        "capa_rules_dir": str(missing),
    })
    assert r["status"] == "skipped"
    assert r["score_delta"] == 0
    assert "not-here" in r["reason"]
    assert not seen, "capa must not be invoked with a rules dir that is absent"


def test_defaults_do_not_configure_rule_paths():
    """`None`, not a path — or every existing install breaks.

    The rule above skips when a configured directory is missing. If the
    defaults named any path, every host install using the bundled binary
    would become 'configured but missing' and lose capa entirely.
    """
    from core.config_loader import DEFAULTS

    assert DEFAULTS["capa_rules_dir"] is None
    assert DEFAULTS["capa_signatures_dir"] is None


def test_default_binaries_still_point_at_the_bundled_location(tmp_path, monkeypatch):
    """A default must not change existing behaviour.

    `config.yaml` is gitignored, so a fresh clone runs on DEFAULTS alone.
    Defaulting these to bare names looked tidier and silently broke the
    hand-placed `./bin/capa` workflow: capa reported "binary not found" and
    `string_analysis` fell back to `source="raw"` with both binaries sitting
    right there. The container opts into bare names in its own config
    instead.
    """
    from core.config_loader import DEFAULTS
    from modules.static._bundled_tool import resolve_tool

    assert DEFAULTS["capa_binary"] == "./bin/capa"
    assert DEFAULTS["floss_binary"] == "./bin/floss"

    # And the default must resolve without PATH help, which is the whole point.
    # An ordinary file suffices: the path branch tests is_file(), not the
    # execute bit, so this works on a noexec filesystem too.
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "capa").write_text("#!/bin/sh\nexit 0\n")
    assert resolve_tool(DEFAULTS["capa_binary"]) is not None


def test_a_bare_name_is_still_accepted_for_the_container():
    """The image configures bare names, so resolution must support both."""
    from modules.static._bundled_tool import resolve_tool

    assert resolve_tool("sh") is not None, "a real PATH command must resolve"


# ======================================================================
# The tools are pinned exactly, because the rules pin to the same tag
# ======================================================================
def test_tools_extra_is_exactly_pinned():
    import tomllib

    data = tomllib.loads(Path("pyproject.toml").read_text())
    tools = data["project"]["optional-dependencies"]["tools"]
    joined = " ".join(tools)
    assert "flare-capa==9.4.0" in joined
    assert "flare-floss==3.1.1" in joined
    for spec in tools:
        assert ">=" not in spec, f"{spec} must be pinned exactly: capa's rules and signatures are pinned to the matching tag"
