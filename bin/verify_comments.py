#!/usr/bin/env python3
"""Prove that a commenting pass changed no executable code.

The project's commenting standard adds docstrings and block comments across a
package at a time. Those diffs are large — several hundred lines per package —
which makes it easy for a real code change to hide inside one, and impossible
to be sure by reading.

This settles it mechanically. For each file it parses the version at git HEAD
and the version in the working tree, strips every docstring from both, and
compares the resulting ASTs. Comments never reach the AST at all, and stripped
docstrings are the only other thing a comment pass may touch, so identical
trees mean the executable code is byte-for-byte equivalent.

Usage:

    bin/verify_comments.py core/*.py
    bin/verify_comments.py modules/static/pe_analysis/*.py

    # against a different baseline
    bin/verify_comments.py --base origin/main reporting/**/*.py

Exit codes:
    0  every file's AST is unchanged
    1  at least one file differs — a real code change is in the diff
    2  usage error

A DIFF result is not automatically wrong. When a comment pass turns up a
genuine defect, the fix belongs in its own commit with its own tests, and this
tool is how you notice that the two got mixed together.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys


def strip_docstrings(tree: ast.AST) -> str:
    """Return a dump of *tree* with every docstring removed.

    Args:
        tree: A parsed module.

    Returns:
        ``ast.dump`` output. A body emptied by the strip is refilled with
        ``pass`` so the node still parses as valid structure rather than
        collapsing and producing a spurious difference.
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef,
                             ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:] or [ast.Pass()]
    return ast.dump(ast.fix_missing_locations(tree))


def baseline_source(path: str, base: str) -> str | None:
    """Fetch *path* as it exists at the *base* git revision.

    Returns:
        The file's contents, or None when it does not exist at that
        revision — a newly added file, which has nothing to compare to.
    """
    proc = subprocess.run(["git", "show", f"{base}:{path}"],
                          capture_output=True, text=True)
    return proc.stdout if proc.returncode == 0 else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a commenting pass changed no executable code.")
    parser.add_argument("paths", nargs="+", help="Python files to check")
    parser.add_argument("--base", default="HEAD",
                        help="git revision to compare against (default: HEAD)")
    args = parser.parse_args(argv)

    differing = 0
    for path in args.paths:
        if not path.endswith(".py"):
            continue

        old_source = baseline_source(path, args.base)
        if old_source is None:
            print(f"NEW   {path}  (not in {args.base} — nothing to compare)")
            continue

        try:
            with open(path, encoding="utf-8") as handle:
                new_source = handle.read()
            old_dump = strip_docstrings(ast.parse(old_source))
            new_dump = strip_docstrings(ast.parse(new_source))
        except SyntaxError as exc:
            print(f"ERROR {path}  ({exc})")
            differing += 1
            continue
        except OSError as exc:
            print(f"ERROR {path}  ({exc})")
            differing += 1
            continue

        if old_dump == new_dump:
            print(f"SAME  {path}")
        else:
            print(f"DIFF  {path}  <- executable code changed")
            differing += 1

    if differing:
        print(f"\n{differing} file(s) changed executable code. If that is "
              f"deliberate, it belongs in its own commit with tests.")
    return 1 if differing else 0


if __name__ == "__main__":
    sys.exit(main())
