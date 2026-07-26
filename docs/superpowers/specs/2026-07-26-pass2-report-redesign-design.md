# Pass 2 — Report Redesign (design)

**Date:** 26th July 2026
**Supersedes:** `docs/cli_redesign_plan.md` §2.2 and §2.4, which targeted a ~40-line
default report. That target is **dropped** — see "Density decision" below.

---

## Goal

One severity colour map instead of five. One indicator renderer instead of four
dialects. `-v` and `-vv` genuinely different. `triage` gets its own shape. Full
detail stays visible by default; only content printed *twice* is removed.

## Density decision (revised from the plan)

The original plan cut the default report to ~40 lines by demoting the per-member
tables behind `-v`. That was rejected after seeing it rendered: an analyst
triaging an archive needs the member list and every SHA256 in front of them, not
one keystroke away.

**New rule: nothing is demoted for being long. Only genuine duplication is cut.**

| Removed | Why |
|---|---|
| `Score Breakdown` table | Restates `Module Results` — same module, same Δ, same reason, back to back, in a different box style. One is truncated at 120 chars, the other is not. |
| Six `Not applicable` rows | Collapse to a single module status strip. |

Everything else stays at detail 0, in full. Measured expectation: **116 → ~75
lines on the RedLine baseline, with no information lost.**

## Hash display decision

Verified by rendering the real `NetSupport + booking + ini.rar` sample at two
widths:

| Layout | 100 cols | 80 cols |
|---|---|---|
| SHA256 as a table column | hash split across 2 lines | split |
| SHA256 on its own row, boxed | intact | split |
| **Flat, no box** | **intact** | **intact** |

A SHA256 is 64 characters. Box borders and cell padding consume 6+ columns, so a
boxed layout at 80 columns has ~59 left and *must* break the hash mid-string.
That breaks double-click copy-paste into VirusTotal, which is the only reason to
print a full hash.

**Hash-bearing tables (archive embedded executables, OneNote blobs) render flat.**
Every other table keeps its box. Flat layout holds down to 66 columns.

---

## Architecture

### New files

| File | Responsibility | Depends on |
|---|---|---|
| `reporting/theme.py` | `TOKENS` — the single severity/band palette, in both rich and CSS form. `rich_style(name)`, `css_root()`. | nothing |
| `reporting/console.py` | `out` (stdout) / `err` (stderr) `Console` singletons. | rich |
| `reporting/terminal_reporter/_render.py` | Rendering primitives: `render_indicators`, `render_hash_list`, `score_bar`, `module_strip`, `more_hint`. | `theme`, `console`, `_common` |
| `reporting/triage_reporter.py` | `derive_flags(module_results) -> set[str]`, triage score table, adaptive legend. | `theme`, `console` |

`cli/_console.py` becomes a re-export of `reporting/console.py`. Reporting is the
lower layer — `cli` already imports it, so it owns the singletons and there is
exactly one stdout `Console` in the tree.

### Types

```python
Severity = Literal["bad", "warn", "info"]

class Row(NamedTuple):
    label: str
    value: str
    severity: Severity = "info"
```

A `NamedTuple` rather than the plan's bare 3-tuple: tuple-compatible, but typed
and self-describing at every call site.

### Changed files

- `_common.py` — keeps the console re-export; gains `LIMITS`, naming the ~12
  magic numbers currently inline at their use sites (attack 10, IOCs-per-type 5,
  strings 10, capabilities 10, blobs 20, members 20, execs 10, HTML members 50,
  reason 120, PDB 90, sha display 16).
- `pe.py`, `doc.py`, `archive.py`, `onenote.py` — each drops `print_*_indicators`
  and exports a pure `*_rows(data, detail_level) -> list[Row]`.
- `shared.py` — gains the recursive credential sanitiser both reporters call.

---

## Stage 2a — unify

No layout redesign. Establishes the primitives.

1. `theme.py` becomes the only palette. Delete `_SEV_STYLES` (×2, byte-identical),
   `_CLASS_COLOURS` (×2, byte-identical), and derive `BAND_COLOURS`,
   `STATUS_COLOURS`, `_IOC_TYPE_STYLES` from `TOKENS`.
2. `report.html.j2` receives a generated `{{ theme_css }}` whose values are
   **byte-identical to today's `:root` block**, so HTML output does not change and
   the change is verifiable by diffing a rendered report.
3. The four dialects converge on `render_indicators()`.

**Expected output change:** `pe`/`doc` unchanged. `archive`/`onenote` change —
their hand-padded `Panel` becomes an indicator table. Their satellite tables
(members, execs, blobs, nested) are **not** collapsed; they stay at detail 0.

Two bugs fixed here, both confirmed in `onenote.py`:
- `_CLASS_COLOURS.get(band.upper())` is fed a `risk_band`
  (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), which can never match a `MALICIOUS` key, so
  it always falls back to white.
- Reads `scoring["final_score"]`; the pipeline emits `total_score`.

**Silent truncation fixed:** `archive._dangerous_members_table` caps at `[:20]`
and `_embedded_execs_table` at `[:10]` with **no "more" hint** — the analyst
cannot tell rows were dropped. New rule: default cap 50 with a mandatory hint;
`-v` uncaps.

## Stage 2b — scan layout

1. `Module Results` + `Score Breakdown` merge into one `FINDINGS` table.
2. Skipped modules collapse to `modules ✓✓✓✓✓ ○○○○○  5 ran, 5 n/a`.
3. Score bar — today 12 and 98 render identically except in hue.
4. Hash-bearing tables adopt the flat layout.
5. `-vv` gains raw per-module JSON via the shared sanitiser. This is what finally
   makes level 2 differ from level 1.
6. Fix `recommendations.py`, which still advertises `--dynamic speakeasy` — a flag
   Pass 1 deleted.

### Detail ladder

| Level | Adds |
|---|---|
| 0 | Everything except the below. All indicator tables, all members, all execs with full SHA256, IOCs, strings, recommendations. |
| 1 (`-v`) | Per-module timing; `info`-severity indicator rows; caps lifted (ATT&CK 10→all, IOCs 5/type→all, strings 10→all, capabilities 10→all, members/execs 50→all). |
| 2 (`-vv`) | Raw per-module JSON; untruncated reasons. |

## Stage 2c — triage

`derive_flags(module_results) -> set[str]` is pure and unit-tested against the
plan's §2.7 letter table (`S`/`I`/`Y`/`M`/`A`/`P`/`V`/`E`). Score table sorted
descending; the legend lists only letters that actually fired in that run.

---

## Testing

Rendered terminal output is only deterministic if timing, timestamps and terminal
width are pinned. So:

1. **Fixtures** — real `-f json` output captured from live samples into
   `tests/fixtures/`, with `elapsed_seconds` and timestamps nulled. Already
   captured: `fx_rar` (NetSupport, MALICIOUS, 15 entries, 9 embedded PE32),
   plus RedLine and a OneNote sample.
2. **Injection** — `print_terminal_report(report, *, detail_level=0, console=None)`
   accepts an injected `Console(width=100, no_color=True)`.
   `print_footer(timing, *, now=None)` takes an injectable clock.
3. `tests/test_report_rows.py` — pure builders against fixture dicts, including
   `render_indicators` dropping `info` rows at detail 0 *while preserving order*
   (today `pe.py` appends its whitelist rows and `doc.py` inserts at index 0; both
   reorder relative to the source list).
4. `tests/test_report_render.py` — golden snapshots at detail 0/1/2, regenerated
   with `THREATLENS_UPDATE_SNAPSHOTS=1`. Carries the assertion that matters:
   `detail1 != detail2`.
5. `tests/test_report_width.py` — renders the hash tables at 80 and 100 columns
   and asserts each SHA256 appears as one unbroken 64-char run. This is the
   regression guard for the decision above.
6. `tests/test_triage_flags.py` — flag derivation.

The 53 Pass 1 tests must stay green after every stage.

---

## Out of scope

- `html_analysis` / `pdf_analysis` renderers and `build_verdict` coverage — Pass 4,
  which depends on `render_indicators()` landing here first.
- Score recalibration; unifying the two band vocabularies (pipeline
  `CRITICAL/HIGH/MEDIUM/LOW` vs per-module `MALICIOUS/SUSPICIOUS/...`). Pass 2
  renders both consistently but does not merge them.
- **`CVE-2025-8088 + UKR,.rar` hangs >110s** with only `file_intake,archive_analysis`
  enabled, while the other five RAR samples finish in 0.3–2s. Found while capturing
  fixtures. Likely a loop in the RAR5 raw-header walker. Separate bug, not Pass 2.
