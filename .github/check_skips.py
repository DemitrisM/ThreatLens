#!/usr/bin/env python3
"""Fail CI when a test stops running for a reason nobody chose.

A skipped test is indistinguishable from a passing one in an exit code, and
this project has already been bitten by that: five test files hardcoded an
absolute corpus path, so sixteen real-sample tests silently excused themselves
inside the container while the tally read **1107 passed, 16 skipped** against
the host's 1123. The acceptance check at the time was "the suite passes inside
the image", and it passed while proving nothing about real samples.

So the exit code is not sufficient evidence. This reads the JUnit XML and
checks *why* each skip happened.

**What this cannot do**, stated here so nobody mistakes a green run for more
than it is: it sees only what the test runner did. When a module degrades
gracefully — FLOSS never executing, capa timing out — the pipeline reports
`status: "skipped"` inside the result and the **test passes**. None of that
reaches this file. That class is caught by running the tool against the real
corpus and reading the output, which is where all three instances were found.

Counts are deliberately not pinned. A runner and a developer machine differ
for legitimate reasons — `unar` present or absent, UTC against a local
timezone with py7zr asserting timezone-correct timestamps — and a pinned
number would go red for a non-defect, which teaches everyone to edit the
number rather than read it.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

#: A skip is expected only when it says a sample or the corpus is absent. CI
#: holds no malware corpus by design, so these are the honest ones. Anything
#: else — an unimportable module, a missing binary, a re-hardcoded path — is
#: the failure this script exists for. Matched case-insensitively against the
#: skip message.
EXPECTED_SKIP_PATTERNS = (
    r"corpus sample unavailable",
    r"corpus unavailable",
    r"malware corpus not present",
    r"no macro-bearing sample available",
)

#: Not a target, a floor. It catches a collection error that silently drops
#: most of the suite, and sits far enough below the real count (1108 without
#: the corpus) that ordinary variation between environments never reaches it.
MINIMUM_PASSED = 1000


def _expected(message: str) -> bool:
    """True when this skip message is one of the known corpus-absence ones."""
    return any(re.search(p, message, re.IGNORECASE) for p in EXPECTED_SKIP_PATTERNS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit_xml", type=Path)
    parser.add_argument(
        "--min-passed",
        type=int,
        default=MINIMUM_PASSED,
        help=f"floor on passing tests (default {MINIMUM_PASSED})",
    )
    args = parser.parse_args()

    if not args.junit_xml.is_file():
        print(f"FAIL: no JUnit XML at {args.junit_xml}", file=sys.stderr)
        print("      pytest needs --junitxml=<path>; no -q setting writes it.",
              file=sys.stderr)
        return 1

    root = ET.parse(args.junit_xml).getroot()
    # pytest emits <testsuites><testsuite>; older tooling emits a bare
    # <testsuite>. Accept both rather than depending on which one pytest felt
    # like writing.
    suites = root.findall("testsuite") or ([root] if root.tag == "testsuite" else [])
    if not suites:
        print(f"FAIL: {args.junit_xml} contains no <testsuite>", file=sys.stderr)
        return 1

    total = errors = failures = skipped = 0
    unexpected: list[tuple[str, str]] = []

    for suite in suites:
        total += int(suite.get("tests", 0))
        errors += int(suite.get("errors", 0))
        failures += int(suite.get("failures", 0))
        skipped += int(suite.get("skipped", 0))

        for case in suite.iter("testcase"):
            for skip in case.findall("skipped"):
                # The reason lives in @message; the element text carries the
                # file and line. Prefer the message, fall back to the text,
                # because a skip with neither should be treated as unknown
                # rather than quietly allowed.
                message = skip.get("message") or (skip.text or "")
                if not _expected(message):
                    name = f"{case.get('classname', '')}::{case.get('name', '')}"
                    unexpected.append((name, message.strip()[:160]))

    passed = total - errors - failures - skipped

    print(f"tests={total} passed={passed} failed={failures} "
          f"errors={errors} skipped={skipped}")

    ok = True

    if unexpected:
        ok = False
        print(f"\nFAIL: {len(unexpected)} test(s) skipped for an unrecognised "
              f"reason.\nA skip reads like a pass in the exit code, so each of "
              f"these is coverage that\nquietly disappeared:\n", file=sys.stderr)
        for name, message in unexpected:
            print(f"  - {name}\n      {message!r}", file=sys.stderr)
        print("\nIf the reason is legitimate, add it to EXPECTED_SKIP_PATTERNS "
              "in this file\nwith a comment saying why.", file=sys.stderr)

    if passed < args.min_passed:
        ok = False
        print(f"\nFAIL: {passed} passing tests, floor is {args.min_passed}. "
              f"The suite lost coverage\nwholesale — check for a collection "
              f"error.", file=sys.stderr)

    if ok:
        print(f"OK: {skipped} skip(s), all corpus-absence; "
              f"{passed} passed (floor {args.min_passed}).")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
