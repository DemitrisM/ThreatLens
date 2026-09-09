# Changelog

## Unreleased

- Added a block-per-section commenting standard, piloted across the `core/`
  package: docstrings with Args/Returns/Raises on every function, section
  banners on every multi-phase function, and design-notes headers on each
  module. The remaining packages follow in later passes.
- Added this changelog.
- Fixed `_run_module`'s docstring in `core/pipeline.py`, which claimed the
  function enforced the per-module timeout. It never has — timeouts are
  enforced inside the modules that shell out (capa's subprocess, XLM
  deobfuscation's 30s cap), not by the orchestrator.
- Fixed the `core/rule_updater.py` module docstring, which still referred to
  an `update-rules` command in `main.py`. That verb became `rules update` in
  `cli/rules.py`.
- Known issue: `CVE-2025-8088 + UKR,.rar` hangs for over 110 seconds with
  only `file_intake,archive_analysis` enabled, while five other RAR samples
  finish in 0.3–2s. Suspected loop in the RAR5 raw-header walker.
- Known issue: two band vocabularies render side by side. The pipeline scores
  0–100 into LOW/MEDIUM/HIGH/CRITICAL while `archive`, `doc`, `onenote` and
  `lnk` emit MALICIOUS/SUSPICIOUS/INFORMATIONAL/CLEAN on their own
  thresholds, so a green `LOW` banner can sit above a red `MALICIOUS` one.
- Known issue: `core/config_loader.py` assigns `DEFAULTS["rule_sources"]` by
  reference in its validation fallback, defeating the `copy.deepcopy` the
  same function performs to protect the module-level constant.
- Known issue: all 18 validated `.lnk` samples pin at exactly +60, so
  `SCORE_CAP` is doing the work and the corpus cannot rank within MALICIOUS.
  Detection is unaffected; triage ordering is not yet meaningful.
- Known issue: no benign `.lnk` corpus exists, so `lnk_analysis` has no
  false-positive validation.

## 0.4.0

- Reduced the command surface to four verbs — `scan`, `triage`, `compare`
  and `rules` — with at most nine applicable flags each, on two axes: `-p`
  decides what runs, `-v`/`-vv` decides what prints.
- Added `lnk_analysis`, a first-party [MS-SHLLINK] parser with no third-party
  dependency: bounds-checked walker, shell-item decoding with NTFS MFT entry
  and sequence numbers, PropertyStore decoding into named properties,
  four-source target resolution with disagreement detection, 31 compiled
  command patterns, ZDI-CAN-25373 / CVE-2025-9491 position-aware padding
  detection, icon masquerade (T1027.012), overlay carve with SHA256 and
  VirusTotal forward-lookup, TrackerDataBlock attribution, and 36 frozenset
  combo rules. Validated against 18 real MalwareBazaar samples.
- Added `deobfuscate.py`, recovering C2 from obfuscated command lines through
  layered reverse, base64, character de-doubling and `.Replace()` chains.
  Grandoreiro needs all four chained.
- Added 437 tests covering the CLI contract, module selection, config
  loading, report rendering, triage flags, credential handling, and
  `lnk_analysis` in full.
- Added `--fail-on` and risk-based exit codes: 0 clean, 1 threshold reached,
  2 usage error, 3 runtime error.
- Added module aliases (`pe`, `capa`, `vt`, and others) resolved through one
  table shared by the CLI and config validation. Unknown names now exit 2.
- Added the `THREATLENS_VT_KEY` environment variable, and a warning when a
  config file holding an API key is group- or world-readable.
- Replaced five separate colour maps with one palette in
  `reporting/theme.py`, in both rich and CSS form.
- Replaced four rendering dialects with a single `render_indicators()`.
- Added a score bar, a merged FINDINGS table, and a triage score table with
  derived flags.
- Extended `build_verdict()` to cover every scoring module; it previously
  covered five of twelve.
- Weighted indicators so weak signals no longer lead the report.
- `html_analysis` and `pdf_analysis` results now render.
- Split the output streams: stdout carries results only, progress and
  warnings go to stderr, so `threatlens scan … -f json | jq` works.
- Made `-vv` genuinely distinct from `-v`.
- Removed `--vt-key`-style flags by design. Anything on the command line is
  readable by every user via `ps` and `/proc/PID/cmdline`, and lands in shell
  history.
- Removed the `analyse` verb, which survives only as a hidden signpost that
  exits 2.
- A scan that ran no analysis modules can no longer report a clean verdict.
  Unknown module names, an empty `--modules`, and skipping every analysis
  module are all usage errors.
- Credentials are now stripped recursively from all report output.

## 0.3.0

- Added `virustotal` enrichment: hash-only lookup with detection ratio,
  threat labels and rate-limit retry. Files are never uploaded.
- Added `doc_analysis` with magic-byte routing across OLE, OpenXML and RTF —
  olevba and MacroRaptor, VBA stomping detection, XLM Excel-4.0
  deobfuscation, OOXML template injection, and Equation Editor CLSID matching
  for CVE-2017-11882 and CVE-2018-0802.
- Added `pdf_analysis`: peepdf-backed JavaScript extraction, URI detection,
  encryption checks and a raw keyword sweep.
- Added `html_analysis` covering HTML smuggling, nested base64 decode,
  ClickFix clipboard poisoning, JS obfuscation and external C2 detection.
- Added `onenote_analysis`: an MS-ONESTORE FileDataStoreObject walker, typed
  blob classification, encrypted-section detection, and `.onepkg` delegation
  to `archive_analysis`.
- Added `archive_analysis` for ZIP, RAR, 7z, TAR, GZ, BZ2, XZ, CAB, ISO and
  ACE, plus SFX-PE overlays, with a bomb guard that runs before extraction.
- Added CVE-2025-8088 recovery. `rarfile.infolist()` strips NTFS Alternate
  Data Stream suffixes and hides the malicious drop path;
  `rar_raw_headers.parse_rar_filenames()` recovers it from the RAR5 SERVICE
  record.
- Added the `rules update` command with `--check`, `--force` and
  `--validate-only`.
- Added a self-contained HTML reporter mirroring the terminal sections.
- Added scan profiles, module selection, a progress spinner, verbosity
  levels, a MITRE ATT&CK table, IOC and string tables, per-module timing, a
  generated verdict sentence, a recommendations panel, `--hash-only`, batch
  analysis and compare mode.

## 0.2.0

- Added `pe_analysis` with 40+ indicators across 10 submodules: entropy and
  RWX anomalies, 63 tiered suspicious APIs, hollowing API co-occurrence,
  Authenticode and checksum tampering, Go/Rust/Nim language fingerprinting,
  Rich header XOR corruption, 14 packer signatures, TLS callbacks and
  embedded MZ scanning.
- Added `string_analysis`: FLOSS integration with a raw-string fallback, and
  40+ regex matchers across four severity tiers with per-tier caps.
- Added `ioc_extractor` with six IOC types and heavy false-positive
  filtering — a 210-entry TLD whitelist, Go stdlib pseudo-TLD pairs, vowel
  and CamelCase domain rejection, and private/reserved IP filtering.
- Added `capa_analysis`: capa invocation with timeout, v6 and v7+ JSON
  parsing, eight capability categories, and ATT&CK mapping including
  subtechniques.
- Added `yara_scanner` with two-stage compilation that falls back to per-file
  compilation to isolate broken rules.

## 0.1.0

- Added `core/pipeline.py`: module registry, lazy dotted-path imports,
  per-module timing, progress callbacks, and graceful skips for unknown or
  unimportable modules.
- Added `core/file_intake.py`: content-based type detection via python-magic
  with an extension fallback map, plus MD5, SHA256, TLSH and ssdeep hashing.
- Added `core/scoring.py`: sums module deltas, clamps 0–100 once after the
  sum, and assigns risk bands (76+ CRITICAL, 56–75 HIGH, 31–55 MEDIUM,
  0–30 LOW).
- Added `core/config_loader.py`: YAML overlaid on defaults covering every
  key, with non-fatal validation.
- Added the `cli/` package built on click, with `main.py` as a thin
  entry-point shim.
- Added a JSON reporter with timestamped filenames and credential
  sanitisation, and a rich-based terminal reporter with three detail levels.
- Established graceful degradation throughout: a missing dependency logs a
  warning, sets status `skipped`, and returns a zero-score result rather than
  raising.
