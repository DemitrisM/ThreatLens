"""The Compose image tag and `cli.__version__` must agree.

`docker-compose.yml` names the image it builds — `threatlens:0.5.15` — and
nothing derives that from the package. It was written by hand at 0.5.14 and
was still saying 0.5.14 when the package had moved to 0.5.15, which is a
silent kind of wrong: Compose happily builds and tags an image whose name
claims a version the code inside it is not.

Nothing about the drift looks like a failure. `docker compose build`
succeeds, the scan runs, and the only symptom is a user reporting a bug
against a version number that was never what they were running. So the
invariant is checked mechanically, the same way `test_requirements_lock.py`
pins the capa version across the three files that repeat it.

The README is checked too. It documents a raw `docker run` for the offline
scan, and that command names the tag explicitly — so the tag lives in three
places and any two of them can disagree.
"""

import re
from pathlib import Path

# Anchored to the repository rather than to pytest's working directory: these
# tests read project files, and a relative path would change meaning with the
# directory pytest was invoked from.
ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "docker-compose.yml"
README = ROOT / "README.md"


def _version() -> str:
    """The package version, read from source rather than imported.

    Importing `cli` pulls in click and the whole command surface for one
    string, and this test is about what the files say.
    """
    text = (ROOT / "cli" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "cli/__init__.py has no __version__ assignment"
    return match.group(1)


def test_compose_image_tag_matches_package_version():
    """`docker-compose.yml` tags the image with the current version."""
    text = COMPOSE.read_text(encoding="utf-8")
    tags = re.findall(r"^\s*image:\s*threatlens:(\S+)\s*$", text, re.MULTILINE)

    assert tags, "docker-compose.yml declares no threatlens image tag"
    for tag in tags:
        assert tag == _version(), (
            f"docker-compose.yml builds threatlens:{tag} while the package is "
            f"{_version()}. Bump the tag, or the image name lies about what is "
            f"inside it."
        )


def test_readme_documents_the_same_tag():
    """The README's raw `docker run` names the tag Compose actually builds.

    A stale tag here is worse than a stale one in Compose: the command is
    copy-pasted, and `docker run threatlens:<old>` either runs an image the
    user built weeks ago or fails outright with "Unable to find image".
    """
    tags = set(re.findall(r"threatlens:(\d+\.\d+\.\d+)", README.read_text(encoding="utf-8")))

    # No tag in the README is fine — it only names one because the offline
    # scan cannot go through Compose. What is not fine is naming a wrong one.
    for tag in tags:
        assert tag == _version(), (
            f"README.md names threatlens:{tag}, the package is {_version()}"
        )
