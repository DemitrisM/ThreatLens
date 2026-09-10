# Changelog

Versions step in small increments. **1.0.0 is reserved for a tool that does
both static and dynamic analysis end to end** — that means Phase 5's
detonation providers working, Phase 4's packaging and CI done, and a README.
Everything before it is a step toward that.

| Version | What it takes |
|---|---|
| 0.5.0 | *(current)* Defect sweep, full test coverage, commenting standard |
| 0.6.0 | Packaging — `install.sh`, Dockerfile, GitHub Actions CI, README |
| 0.7.0 | The orchestrator timeout, parallel module execution, `msi_analysis` |
| 0.8.0 | First dynamic provider (`speakeasy`), score calibration sweep |
| 0.9.0 | Remaining dynamic providers, benign-corpus false-positive validation |
| 1.0.0 | Static + dynamic, packaged, documented, calibrated |

## Unreleased

- Applied the commenting standard to the five loose static modules —
  `capa_analysis`, `ioc_extractor`, `pdf_analysis`, `string_analysis` and
  `yara_scanner`. Fourth package of the pass; `bin/verify_comments.py` reports
  SAME for all five, proving no executable code rode inside the diff.
- Fixed `.ml` and `.py` domains being unreportable by `ioc_extractor`. Both
  labels sat in `_SOURCE_PSEUDO_TLDS` *and* `_REAL_TLDS`, and the pseudo-TLD
  check runs first, so their real-TLD entries were dead code — no domain on
  either could ever be reported, silently. `.ml` now resolves as Mali (one of
  the five free Freenom ccTLDs, and abused accordingly), `.py` as Python
  (a PyInstaller sample carries hundreds of module filenames). A test asserts
  the two sets stay disjoint, which turns this class of defect into a failure
  rather than a silent loss.
- Fixed `ioc_extractor`'s URL false-positive list matching against the whole
  URL rather than its host. Appending `?ref=www.w3.org` to a C2 URL removed it
  from the report entirely — a false-positive filter that doubled as an evasion
  primitive. Entries are now hosts, matched exactly or as a parent, with
  userinfo and port stripped first so `http://www.w3.org@evil.tld/` cannot
  claim the allow-list.
- Fixed `ioc_extractor` discarding every domain containing an uppercase
  character. The rule exists to reject .NET and Go identifiers like `System.IO`
  that the TLD allow-list cannot catch, but malware configuration data is
  routinely stored shouted, so `EVIL-C2-PANEL.TOP` was dropped too. The test is
  now for *mixed* case; an all-caps candidate is not an identifier.
- Fixed `pdf_analysis` scoring `/EmbeddedFile` inside `/EmbeddedFiles`. Keyword
  matching is raw byte containment, so a document carrying only the name tree
  scored 15 + 5 for one construct and the report listed an attachment that did
  not exist. Counts are now corrected for prefix containment, longest-first
  over corrected counts so a chain of three cannot double-subtract.
- Fixed `pdf_analysis` reporting `encrypted: false` beside its own
  "PDF is encrypted" reason. The flag was written only by the peepdf pass,
  which does not run when peepdf is absent or the header is not `%PDF` —
  exactly the files where it matters. The raw sweep now sets it, and peepdf
  can no longer downgrade it.
- Fixed a JSON `null` in capa's ATT&CK metadata raising `AttributeError`.
  A `get()` default only fires for a missing key, and capa emits null for a
  field it has no value for, so one unmapped rule cost the module every
  capability it had found.
- Added `tests/test_pdf_analysis.py` (12 tests) and
  `tests/test_capa_analysis.py` (14 tests), neither of which existed.
- Applied the commenting standard to `doc_analysis` — fifth package. Records
  why routing answers "should this run" generously and "which passes run"
  strictly, why the passes talk to scoring through one flat flag set, why
  `_quiet.py` has to wrap the import rather than the call, and that the
  module's MALICIOUS/SUSPICIOUS bands are computed on the uncapped total and
  are not the pipeline's risk bands.
- Fixed `doc_analysis` reading only double-quoted `.rels` attributes. XML
  permits either style and Word accepts both, so a single-quoted relationship
  part parsed as no relationships at all — no target, no external check, no
  flags — while Word still fetched the remote template.
- Fixed five `doc_analysis` indicator flags that were emitted and never scored:
  `packager_shell`, `shell_explorer`, `htmlfile`, `ole_package` and
  `altchunk_absolute_path`. A Packager Shell Object embedded in a document
  contributed nothing. A test now reads every flag off the package's AST and
  asserts the rule set covers it. Twelve of the 31 doc samples score higher and
  CVE-2023-36884.docx is now MALICIOUS within `doc_analysis`.
- Fixed `oleid_indicators` testing its macro indicator against `"true"`/`"1"`
  when oleid answers in prose (`'Yes, suspicious'`), so the `encryption_only`
  evasion flag fired for encrypted documents that did have macros.
- Fixed a padded or misdeclared `.rels` part evading relationship inspection.
  Parts over the parse cap were skipped silently, and the declared uncompressed
  size — central-directory metadata zipfile trusts — could understate a part so
  ThreatLens read a fragment while a tolerant consumer read the whole
  relationship. Parts are now read twice and compared, opened by ZipInfo rather
  than by name so duplicate paths cannot shadow each other, and padding past
  the cap convicts the file.
- Rewrote the `doc_analysis` section of `docs/scoring.md`, which still described
  the additive engine the weighted combo engine replaced — it listed weights
  (altChunk +30, VBA present +10) that no longer existed anywhere in the code.
- Added `tests/test_doc_analysis.py` (54 tests). **The suite is now 698 tests,
  up from 605.**

## 0.5.0

- Added a block-per-section commenting standard, applied to `core/`,
  `modules/static/pe_analysis/` and `modules/enrichment/`: docstrings with
  Args/Returns/Raises on every function, section banners on every multi-phase
  function, and design-notes headers on each module. Every package documented
  so far has surfaced real defects, listed below. The remaining packages
  follow in later passes.
- Added this changelog.
- Fixed a blank `virustotal_api_key:` in `config.yaml` crashing the pipeline.
  A YAML key written with no value parses to `None` rather than `""`, and the
  default in `dict.get` only applies to an absent key, so `.strip()` raised
  `AttributeError` and took down the whole scan over one missing pair of
  quotes.
- Fixed a negative `Retry-After` header from VirusTotal reaching
  `time.sleep()`, which raises `ValueError`. The wait is now bounded at both
  ends rather than only capped.
- Fixed `{"data": null}` in a VirusTotal response raising `AttributeError`
  instead of degrading — valid JSON for an empty state, and the chained
  `.get()` could not survive it.
- Added `tests/test_virustotal.py` (23 tests). No test performs a real
  network request. **The suite is now 605 tests, up from 437 at the start
  of this work, with no empty stubs remaining.**
- Known issue: `virustotal` has no shared rate budget. Embedded-hash lookups
  issue one request each and can sleep up to 120s apiece on a rate limit, so
  an archive with many payloads will stall against the free tier's 4
  requests/minute.
- Fixed `config_loader` handing out `DEFAULTS["rule_sources"]` by reference
  when a config file's `rule_sources` was malformed. The returned list *was*
  the module constant, so anything mutating it rewrote the YARA rule source
  URL for the rest of the process.
- Fixed `ioc_extractor` reporting the whole of 172.16.0.0/12 as external
  indicators. The private-range filter used string prefixes that omitted that
  block entirely, so every internal address from 172.16.x to 172.31.x — and
  the default Docker bridge range — was extracted as an IOC. Now uses the
  stdlib `ipaddress` module.
- Fixed packer detection ignoring its own signature tables. `.yP` (Y0da),
  `.packed` and PECompact were listed and never matched; detection now runs
  off the tables, with prefix matching so `UPX0`/`UPX1`/`UPX2` still resolve.
- Fixed a single RWX `.rdata` section raising three separate findings.
- Fixed a native PE with exactly zero imports scoring nothing — the
  small-import-table check started above zero and the branch meant to catch
  the empty case did nothing. An empty table now scores +10.
- Removed three dead branches and one dead constant table.
- Filled the last three empty test stubs. `test_scoring.py` (30),
  `test_pipeline.py` (48) and `test_ioc_extractor.py` (32) join
  `test_pe_analysis.py` (34), plus `test_virustotal.py` (23). No stubs left.
- Known issue: the pipeline enforces no per-module timeout.
  `module_timeout_seconds` is validated and never read, so a slow pure-Python
  module runs to completion regardless. Timeouts exist only inside the modules
  that shell out. `tests/test_pipeline.py` pins this as a documented gap.
- Bumped the version to 0.4.0. `cli/__init__.py` still declared 0.2.0 while
  this changelog recorded 0.3.0 and 0.4.0 as shipped, so `--version`,
  `pyproject.toml` and every report's `meta.version` all understated what the
  tool actually was. The fixtures under `tests/fixtures/` keep their captured
  `"version": "0.2.0"` — they are historical records and no test reads it.
- Fixed `_has_tls_callbacks` reading a fixed 8 bytes from the TLS callback
  array. The array is NULL-terminated by one pointer, which is 4 bytes on a
  32-bit image, so on PE32 the read ran past the terminator and reported a
  callback whenever the trailing bytes were non-zero. The width now follows
  `OptionalHeader.Magic`.
- Added `tests/test_pe_analysis.py`, previously an empty stub — eight tests
  covering the TLS callback check across both pointer widths.
- Fixed four statements in the `pe_analysis` module docstring that
  contradicted the code: the section size-mismatch thresholds, a
  `no_isolation` flag that is not returned, `.itext` as a benign entry-point
  section, and two API category buckets that do not exist.
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
