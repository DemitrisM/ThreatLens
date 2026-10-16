"""Abstract base class for dynamic analysis providers.

Defines the two-function surface every dynamic backend exposes, and the
reason the split between them is shaped the way it is.

Design notes
------------
**Why ``is_available`` cannot decide applicability.** ``core/pipeline.py``'s
``_run_dynamic_provider`` calls ``is_available(config)`` *before* ``run()``,
hands it **only the config — never the sample path** — and on a False return
gives up with a bare ``None`` that carries no reason. So a provider that
declined there would be unable to say *why*, and unable to look at the file
it is declining. ``is_available`` therefore answers only "is this backend
configured at all", and **every per-sample decision lives in ``run()``**,
which returns a proper result dict with a reason attached.

**Why the module-level functions rather than the class.** The pipeline
imports a module and looks up ``run`` and ``is_available`` on it with
``getattr``; it never instantiates anything. The ABC here is for providers
that want the shape documented and their own structure checked — the module
still has to export the two functions, which is what the registry contract
actually requires.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class DynamicProvider(ABC):
    """The interface a dynamic analysis backend implements.

    Implementations are expected to honour design rule 2: never raise into
    the pipeline. Every failure path returns a result dict instead.
    """

    #: Registry key this provider is selected by in ``dynamic_provider``.
    name: str = ""

    @abstractmethod
    def is_available(self, config: dict) -> bool:
        """Whether this backend is configured well enough to be worth calling.

        This cannot see the sample, so it must not try to answer whether a
        particular file is analysable — see the module docstring.

        Args:
            config: The validated configuration dict.

        Returns:
            True if ``run`` should be called at all.
        """

    @abstractmethod
    def run(self, file_path: Path, config: dict) -> dict:
        """Analyse *file_path*, returning the standard module result dict.

        Must not raise. Applicability, unavailability and failure are all
        reported as result dicts carrying a reason.

        Args:
            file_path: The sample under analysis.
            config:    The validated configuration dict.

        Returns:
            A dict matching the module contract in design rule 1, with a
            ``data["detonation"]`` block as required by D-2.
        """
