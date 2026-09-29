"""One place that decides where the malware corpus lives.

Six test files needed the corpus and five of them hardcoded an absolute path
under one developer's home directory, while only `test_live_corpus.py`
honoured the `THREATLENS_CORPUS` override. The consequence was invisible
rather than loud: on any other machine — and inside the container, where the
corpus is bind-mounted somewhere else entirely — those five **silently
skipped**. Running the suite in the image reported "1107 passed, 16 skipped"
against the host's 1123, and a skipped test looks exactly like a passing one
in a tally.

That matters here more than it usually would, because the containerisation
plan's acceptance check is "the suite passes inside the image". A check that
passes while sixteen real-sample tests quietly opt out proves nothing about
real samples, which is the one thing it was there to prove.

So the path is resolved in exactly one function. Setting `THREATLENS_CORPUS`
moves every test at once.
"""

import os
from pathlib import Path

#: Where the corpus lives on the original development machine. Only ever a
#: fallback — `THREATLENS_CORPUS` takes precedence, and an empty value for it
#: is treated as unset rather than as an empty path.
_DEFAULT_ROOT = "/home/pmafma/Documents/Malware"


def corpus_root() -> Path:
    """The corpus directory, honouring ``$THREATLENS_CORPUS``."""
    return Path(os.environ.get("THREATLENS_CORPUS") or _DEFAULT_ROOT)


def corpus_path(*parts: str) -> Path:
    """A path inside the corpus, e.g. ``corpus_path("lnk test malware", "x.lnk")``."""
    return corpus_root().joinpath(*parts)


def have_corpus() -> bool:
    """True when the corpus directory is present and readable."""
    return corpus_root().is_dir()
