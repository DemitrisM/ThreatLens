"""ThreatLens — CLI entry point.

Thin shim so ``python main.py`` continues to work.
The actual CLI definition lives in the ``cli`` package.
"""

from cli import cli

if __name__ == "__main__":
    cli()
