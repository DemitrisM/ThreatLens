"""Run peepdf in a process of its own and hand back what it found, as JSON.

Why this is a separate process at all
-------------------------------------
peepdf writes scratch files into the **current working directory** while
parsing, and when it cannot it abandons the object it was reading rather than
reporting a failure. The module used to solve that by ``os.chdir``-ing into a
directory it owned — correct, but ``os.chdir`` is **process-global, not
per-thread**, so a module that moves it moves it for everything else in the
process.

A child process cannot do that to its parent. The parent launches this worker
with ``cwd=`` already set to a scratch directory it owns, so nothing calls
``os.chdir`` anywhere — the child is simply *born* standing in the right place.

This began as the prerequisite for parallel module execution, which was then
measured and rejected (see CLAUDE.md). It stands on its own regardless — the
reasons below are why it was worth doing, and none of them depend on
concurrency:

* peepdf gets a **timeout**, which it has never had.
* A crash in an unmaintained parser becomes an exit code instead of taking the
  whole scan down with it — design rule 2 by construction.
* Hostile input is parsed with a smaller blast radius.

This module imports **only the standard library and peepdf**. No project
imports, so there is no ``PYTHONPATH`` or package-context to arrange, and it
behaves identically on a host and inside the image.

Extraction only, no scoring
---------------------------
This returns raw facts. Every weight, pattern table and threshold stays in
``pdf_analysis`` where its tests already are, so moving the parse across a
process boundary changes where peepdf runs and nothing about what a PDF
scores.

Protocol
--------
``argv[1]`` the PDF, absolute. ``argv[2]`` where to write the JSON.

Results go to that **file, not stdout**: peepdf prints, and a
JSON-on-stdout protocol would be corrupted by any library chatter — the same
trap design rule 7 exists for. Exit 0 means the file was written and is
readable; any other exit means the parent should treat the parse as failed.
"""

import json
import sys

try:
    import resource
except ImportError:      # pragma: no cover — Unix-only, and this is a Linux tool
    # The project targets Linux and ships as a Debian image, so this should
    # never fire. It is handled anyway because the alternative is the worker
    # dying at import, which the parent would report as a generic crash and
    # which would disable structural PDF analysis entirely while looking like
    # a parser failure. Losing the memory bound is worth admitting; losing the
    # module without saying so is not.
    resource = None

#: Address-space ceiling for this process, applied **before** peepdf is
#: imported. A wall-clock timeout bounds time and nothing else: a PDF crafted
#: to make the parser allocate can exhaust system memory well inside a 60s
#: budget, and the OOM killer does not read design rule 2.
#:
#: Set here rather than through the parent's ``preexec_fn``, which runs between
#: fork and exec and is documented as unsafe in the presence of threads.
#:
#: **4 GiB, and it cannot sensibly be much tighter.** peepdf-3 5.4.1 pulls in
#: STPyV8, and V8 reserves a large contiguous virtual address range for its
#: heap cage at import. Measured inside the shipped image: at 1 GiB the worker
#: dies on SIGTRAP with "Fatal process out of memory: Failed to reserve
#: virtual memory" before reading a byte of the sample; 1.5 GiB and above
#: import and parse cleanly. 4 GiB is chosen for headroom across peepdf and
#: V8 versions rather than as a tight bound.
#:
#: The host misses this entirely — peepdf 5.3.0 there never initialises V8 —
#: so this value must be changed against the image, not against a developer
#: machine.
#:
#: Note what this does and does not buy. RLIMIT_AS bounds *address space*, not
#: resident memory, and V8 reserves far more than it commits. So this catches
#: gross runaway allocation and nothing subtler; a real memory bound for the
#: container is the container's own, not this.
MEMORY_LIMIT_BYTES = 4 * 1024 * 1024 * 1024

#: Ceiling on the JavaScript handed back to the parent. The parent needs every
#: block to build its match haystack, so these are not truncated individually
#: the way the stored copies are — but "all of it" from a hostile file is an
#: unbounded read, so the aggregate stops here and says that it did.
MAX_JS_PAYLOAD_BYTES = 5 * 1024 * 1024


def _limit_memory() -> None:
    """Bound this process's address space, tolerating a system that refuses.

    A hard limit lower than the request cannot be raised by an unprivileged
    process, so the soft limit is clamped to whatever hard limit exists rather
    than failing outright — an unbounded parse still beats no parse, and the
    wall-clock timeout in the parent remains.
    """
    if resource is None:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        target = MEMORY_LIMIT_BYTES
        if hard != resource.RLIM_INFINITY:
            target = min(target, hard)
        resource.setrlimit(resource.RLIMIT_AS, (target, hard))
    except (ValueError, OSError):
        pass


def _flatten(versions) -> list[str]:
    """Flatten one of peepdf's per-version lists into plain strings.

    peepdf returns a list *per PDF version*, whose entries may be
    ``(name, code)`` tuples or bare strings depending on where the item was
    found. Both shapes appear in the corpus, so both are handled rather than
    trusting the documented type.
    """
    out: list[str] = []
    for per_version in versions or []:
        if isinstance(per_version, (list, tuple)):
            for entry in per_version:
                if isinstance(entry, tuple) and len(entry) >= 2:
                    out.append(str(entry[1]))
                else:
                    out.append(str(entry))
        elif isinstance(per_version, str):
            out.append(per_version)
    return out


def _extract(target: str) -> dict:
    """Parse `target` and harvest whatever peepdf manages to expose.

    Every accessor is wrapped on its own: peepdf's shapes vary by PDF version
    and a failure in one says nothing about the next, so a partial harvest is
    still worth returning.
    """
    from peepdf.PDFCore import PDFParser

    result: dict = {"parsed": False, "failure": None}

    # forceMode and looseMode tell peepdf to keep going through structural
    # violations instead of aborting. Malware PDFs are malformed far more often
    # than not, frequently on purpose, so strict parsing would refuse exactly
    # the files worth reading.
    ret, pdf_file = PDFParser().parse(target, forceMode=True, looseMode=True)

    # Both halves matter: peepdf signals failure through the status code on
    # some paths and through a None document on others.
    if ret != 0 or pdf_file is None:
        result["failure"] = "peepdf could not parse PDF structure"
        return result

    result["parsed"] = True

    try:
        result["version"] = str(pdf_file.getVersion())
        result["encrypted"] = bool(pdf_file.isEncrypted())
    except Exception:  # noqa: BLE001
        pass

    try:
        stats = pdf_file.getStats()
        if isinstance(stats, dict):
            result["stats"] = {
                "Objects": stats.get("Objects", 0),
                "Streams": stats.get("Streams", 0),
                "URIs": stats.get("URIs", 0),
            }
    except Exception:  # noqa: BLE001
        pass

    try:
        result["errors"] = [str(e) for e in (pdf_file.getErrors() or [])]
    except Exception:  # noqa: BLE001
        pass

    try:
        js_items = [j for j in _flatten(pdf_file.getJavascriptCode()) if j and j != "[]"]
        kept, budget = [], MAX_JS_PAYLOAD_BYTES
        for block in js_items:
            if budget <= 0:
                result["js_truncated"] = True
                break
            if len(block) > budget:
                # Truncate the block rather than dropping it. Dropping would
                # hand the parent an EMPTY list for a file whose whole payload
                # is one oversized block, and the parent's pattern matching
                # would then see nothing at all — a detection bypass costing
                # the attacker a single large comment. A prefix still matches.
                kept.append(block[:budget])
                result["js_truncated"] = True
                budget = 0
                break
            kept.append(block)
            budget -= len(block)
        result["javascript"] = kept
        # The full count, even when the payload was cut short: the parent
        # reports how many blocks a file carries, and under-reporting that
        # because of a transport limit would be a finding about the wrong
        # thing.
        result["javascript_total"] = len(js_items)
    except Exception:  # noqa: BLE001
        pass

    try:
        result["uris"] = [u for u in _flatten(pdf_file.getURIs()) if u]
    except Exception:  # noqa: BLE001
        pass

    try:
        result["urls"] = [u for u in _flatten(pdf_file.getURLs()) if u]
    except Exception:  # noqa: BLE001
        pass

    try:
        susp = pdf_file.getSuspiciousComponents()
        flat: list[str] = []
        for per_version in susp if isinstance(susp, list) else [susp]:
            if isinstance(per_version, dict):
                flat.extend(f"{k}: {v}" for k, v in per_version.items())
            elif isinstance(per_version, list):
                flat.extend(str(i) for i in per_version)
            elif isinstance(per_version, str):
                flat.append(per_version)
        result["suspicious"] = flat
    except Exception:  # noqa: BLE001
        pass

    return result


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <pdf> <output.json>", file=sys.stderr)
        return 2

    _limit_memory()

    target, destination = argv[1], argv[2]
    try:
        payload = _extract(target)
    except MemoryError:
        # The address-space ceiling, reported as itself rather than as a
        # generic crash, because "this file tried to exhaust memory" is a fact
        # about the sample worth seeing in a log.
        payload = {"parsed": False, "failure": "peepdf exceeded the memory limit"}
    except BaseException as exc:  # noqa: BLE001
        # BaseException, not Exception: peepdf reaches SystemExit on some
        # malformed input, and a worker that dies silently would look to the
        # parent exactly like a crash it cannot explain.
        payload = {"parsed": False, "failure": f"peepdf parse failure: {exc}"}

    try:
        with open(destination, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
    except OSError as exc:
        print(f"could not write results: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
