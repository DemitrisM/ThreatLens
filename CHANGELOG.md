# Changelog

Versions step in small increments. **1.0.0 is reserved for a tool that does
both static and dynamic analysis end to end** — that means Phase 5's
detonation providers working, Phase 4's packaging and CI done, and a README.
Everything before it is a step toward that.

| Version | What it takes |
|---|---|
| 0.5.0 | Defect sweep, full test coverage, commenting standard |
| 0.5.1 | Comment passes 4 and 5, eleven defects fixed, three document evasion paths closed |
| 0.5.2 | The archive_analysis defect sweep — twelve fixes, four archive evasion paths closed, the 227s intake stall |
| 0.5.3 | The archive_analysis comment pass, batches 1–2 — four fixes, five ZIP header-differential evasions closed |
| 0.5.4 | Batches 3–4 — the RAR and 7z/CAB/ISO handlers, three more 7z fixes including a bomb-guard bypass |
| 0.5.5 | Batch 5 — archive_analysis complete; the OOXML costume bypass and the ADS extension blind spot closed |
| 0.5.6 | lnk_analysis complete — four fixes including a size-cap bypass that deleted the module from a scan |
| 0.5.7 | *(current)* html_analysis complete — a Windows-1252 page decoded to mojibake and reported clean |
| 0.6.0 | Packaging — `install.sh`, Dockerfile, GitHub Actions CI, README |
| 0.7.0 | The orchestrator timeout, parallel module execution, `msi_analysis` |
| 0.8.0 | First dynamic provider (`speakeasy`), score calibration sweep |
| 0.9.0 | Remaining dynamic providers, benign-corpus false-positive validation |
| 1.0.0 | Static + dynamic, packaged, documented, calibrated |

## 0.5.7 — 2026-09-24

The `html_analysis` comment pass, both batches. Two defect clusters, and the
first is the most consequential single bug found in the project: a page that
analysed cleanly because the text had been destroyed before any indicator saw
it.

### Fixed — a Windows-1252 page decoded to mojibake and reported clean

`_read_html` tried utf-8, then utf-16, then latin-1, each strict. The middle
step is the problem: `bytes.decode("utf-16")` without a BOM assumes
little-endian and pairs the bytes up, which succeeds for essentially **any**
even-length input. A Windows-1252 page — anything with an accented character,
which fails strict utf-8 — was therefore claimed by utf-16 whenever its length
happened to be even.

Nothing raised. The document became mojibake and every indicator silently
found nothing. Measured: a 50-byte latin-1 page decoded to `格浴㹬猼牣灩㹴…`
and the `eval(atob(` call it carried vanished. Roughly half of all non-UTF-8
pages, by byte-length parity.

UTF-16 is now used only when a BOM says so, matching the browser — HTML5
sniffing does not select it otherwise, and the spec overrides a
`<meta charset="utf-16">` declaration to UTF-8 precisely to stop that being an
attack surface.

UTF-32 is deliberately absent from the BOM table, and briefly was not. Its
little-endian mark is the UTF-16-LE mark followed by two NULs, so listing it
made a UTF-16 document whose first character is U+0000 decode as UTF-32 — one
character of payload to blind the module. Caught in review before it reached a
commit, and pinned by a test.

The magic sniff had the same class of bug: it compared raw bytes, so a BOM sat
in front of `<html` and a UTF-16 page spelled it `<\x00h\x00`. Both are
ordinary ways to save an HTML file that a browser opens as HTML whatever the
extension claims — and a decoy extension is exactly what that fallback is for.

### Fixed — the reported external domain was not the domain

`_extract_domain` normalised hostnames with `netloc.lstrip("www.")`.
`str.lstrip` takes a *set of characters*, so it ate every leading `w` and `.`:
`wordpress.com` became `ordpress.com`, `wp.com` became `p.com`, `web.site`
became `eb.site`. That name went into the report as the suspicious external
domain — an IOC an analyst blocks, for a host that does not exist. It also made
two allowlist entries permanently unreachable.

Three more in the same comparison. Schemes are case-insensitive per RFC 3986,
so `HTTP://evil.test/c2.js` did not match the lowercase literals and read as a
*relative* path — skipped entirely. The relative test was a blocklist of four
prefixes rather than a scheme test, so `ws://`, `file://` and `mailto:` were
skipped too. And browsers fold backslashes, so `src="\\evil.test/c2.js"`
fetches from evil.test while `startswith("//")` missed every backslash
spelling.

Separately, the allowlist matched exactly, so legitimate CDN subdomains were
flagged — the corpus serves from `c0.wp.com` and `stats.wp.com`, plainly why
`wp.com` is listed. Matching is on whole labels now, not `endswith`, which is
itself a bypass: `notwp.com` ends with `wp.com` as raw text.

### Rejected after testing

Entity-encoded schemes were proposed as a fourth gap and are not one.
`convert_charrefs=False` affects text nodes only, so `src="h&#116;tp://…"`
arrives from `html.parser` already decoded. A test pins it, because unescaping
attributes looks harmless and would invite the same for `handle_data` — which
would deobfuscate the script text the obfuscation pass exists to measure.

### Documented

All six files. The notes worth keeping: why ClickFix inverts the usual delivery
problem and therefore needs two independent halves of evidence, why the
obfuscation pass keeps two views of the same script text, and why HTML
smuggling is statically decidable at all.

### Tests

**882 → 940.** Corpus unchanged: the two WordPress false positives are gone and
every genuine C2 domain is still reported, now under its real name.

## 0.5.6 — 2026-09-24

The `lnk_analysis` comment pass, all four batches. The package arrived better
documented than any before it, so the pass mostly filled contracts — and then
turned up four defects anyway, one of them the cheapest evasion found in the
project so far.

### Fixed — the size cap deleted the module from a scan

`run()` returned `status="skipped"` and score 0 for any shortcut over
`max_lnk_size_mb`. Appending eleven megabytes of nulls therefore removed
`lnk_analysis` from the analysis entirely, requiring no understanding of the
format. Measured on `Grandoreiro.lnk`: **MALICIOUS at 60 untouched, skipped
and worth 0 with padding appended.**

The shell-link structure sits at the front of the file, so a bounded prefix
always contains it. The cap now bounds how much is *read*, never whether the
file is looked at. Three consequences had to follow: the real file size is
restored onto the parse result (it drives `large_file` and is printed), the
overlay bounds are recomputed from that size — a structure padded to end
exactly at the cap otherwise leaves the prefix with no trailing bytes and the
overlay looks absent, a quieter version of the same bypass — and a truncated
overlay carries no digests and is not forwarded to VirusTotal, since a hash of
the part that happened to be read is a miss dressed up as an answer.

`test_size_cap_skips_without_reading` was inverted rather than deleted: it
asserted the behaviour that was the bug, and despite its name never checked
that the read was bounded.

### Fixed — a padded basename hid the LOLBin

`_basename` stripped trailing separators and spaces but not leading ones, so
`C:\Windows\System32\   cmd.exe` resolved to `'   cmd.exe'`, which matches no
LOLBin. Windows ignores leading whitespace when it executes, so the shortcut
runs `cmd.exe` while the module reports no LOLBin target — and `lolbin_target`
is a component of the two heaviest rules in the engine, including the
ZDI-CAN-25373 padding combination. Whitespace padding is the central technique
this module exists to detect, which made the basename the last place it should
have been able to hide.

### Fixed — `full_path` dropped the host from every network target

`LinkInfoData.full_path` concatenated `LocalBasePath` and `CommonPathSuffix`
unconditionally. A network-targeted shortcut has no `LocalBasePath` at all, so
for a UNC or WebDAV target it returned the bare suffix — `\payload.exe`
instead of `\\attacker.com@SSL\DavWWWRoot\payload.exe`. `command.py` feeds
that into its four-source target resolution, so the reported target for exactly
the shape the module flags as `webdav_remote_exec` had the attacker's host
removed. Latent in the current corpus, where all 30 samples carry a local
`LinkInfo`.

### Fixed — a false forgery premise

`_timestamps_fabricated` treated a write time earlier than the creation time as
impossible. Windows produces that ordering every time a file is copied.
`APT28.lnk` shows it — creation and access at 2009-07-13, the Windows 7 RTM
date, with a write time a month earlier — and was flagged as fabricated on that
basis alone. The condition is gone; the two that remain describe states a
filesystem does not produce.

### Documented

Comment passes over all eight files. The notes worth keeping: why the
deobfuscation search is breadth-first rather than depth-first, why the
bounds-checked accessors guard against a plausible zero rather than an
exception, why shell-item dispatch reads the class type's high nibble, and why
`resolve_target` reports disagreement on basenames rather than full paths.

One inaccuracy in the new notes was corrected rather than left standing: the
timestamp-source comparison's false positive is not an edge case around
midnight. DOS timestamps are local and FILETIMEs are UTC, so they disagree for
a window each day equal to the host's UTC offset. Its real rate is unmeasured,
because measuring it needs benign shortcuts and the corpus has none — it fires
zero times on the 30 malicious samples, and that zero must not be read as
accuracy.

### Tests

**868 → 882.** Corpus unchanged at 29 of 30 MALICIOUS; `APT28.lnk` drops from
23 to 15, the difference being the false forgery flag.

## 0.5.5 — 2026-09-24

Batch 5 completes the `archive_analysis` comment pass: the indicator set and
the orchestrator. Documenting them turned up the two most serious defects of
the whole pass.

### Fixed — `routing`

- **A ZIP in an OOXML costume was analysed by nothing at all.** The module
  defers a ZIP to `doc_analysis` when it looks like an Office package, and the
  test was two forgeable name checks. Add `[Content_Types].xml` and a `word/`
  entry to any ZIP and `archive_analysis` skipped it as a document while
  `doc_analysis` declined it as not an Office document. Verified end to end:
  both returned `skipped` and a PE sitting beside the two dummy parts was
  examined by nothing. Three strings bought a clean report.

  The fix rests on an asymmetry that had never been written down. This
  predicate decides only whether `archive_analysis` *adds* its analysis; it
  routes nothing away from `doc_analysis`, which is a separate pipeline entry
  applying its own test. A false negative therefore costs a document a
  redundant second analysis, while a false positive costs a payload all
  analysis — so every condition now fails towards "analyse it", and a test
  pins that against a real macro-bearing sample.

  Three conditions were added, each measured against the 57 real OOXML
  packages in the corpus. Every top-level component must be a package
  component. Every part's extension must be on an allow-list of markup,
  metadata and image types — a blocklist was tried first and could not be
  completed, since naming the payload `word/payload` with no extension walked
  straight through, and nothing macro-capable is listed because an
  unreferenced `word/payload.xls` would defer, be ignored as unreferenced, and
  still run when a user unpacked the ZIP. And `[Content_Types].xml` must open
  as XML, read as a stream rather than with `zf.read()` — routing runs before
  the bomb guard, so a whole-member read there would let a content-types part
  that inflates to gigabytes exhaust memory before the tool had even decided
  which module owned the file.

  Corpus effect: 43 of 57 packages still defer, 14 now get archive analysis as
  well — 13 of those carry an embedded `.rtf`, `.xls` or `.xlsx` and every one
  is a malware sample using the embedded-object delivery shape. `doc_analysis`
  still succeeds on **57 of 57**, so no macro analysis is lost.

### Fixed — `indicators`

- **The extension indicators never read the recovered raw name.** The path
  indicators have always inspected both the sanitised member name and the
  `raw_name` recovered from the NTFS ADS suffix; the extension and character
  indicators did not, and that gap was the whole of CVE-2025-8088. In the
  corpus sample `rarfile` reports a `.pdf` while the archive really drops a
  `.lnk` two directories up, so `detect_dangerous_members` returned nothing
  and an archive whose entire purpose is dropping a shortcut never raised
  `dangerous_member` — costing the report its row and the scoring engine a
  flag that `persistence_path` and `embedded_pe` both combine with. That
  sample scored 9 on `path_traversal` alone; it now scores **18**.
  `Crafted8088.rar` goes 9 → 15.

  The entropy check needed one thing the others did not. `.suffix` and the
  double-extension regex anchor to the end of the string, so a Windows-style
  ADS path gives them the right answer on POSIX unaided. Entropy is an average
  over the whole stem and `pathlib` does not split on backslashes here, so the
  unnormalised stem of a traversal path is the entire string — measured at
  4.728 against a 4.5 threshold, firing on the path rather than the payload,
  whose real stem scores 3.322. Separators are normalised first.

### Documented

Comment passes over `indicators.py` and `__init__.py`, completing the package.
The orchestrator's notes record why the phase order is the security property,
why `extracted` cannot simply mean "did extraction run", and two gaps in
archive-only recursion that are recorded rather than fixed: a nested OOXML
container's macros go unread in that mode, and a nested PE is not carved as an
SFX dropper.

### Tests

**837 → 868.** The OOXML fixtures are built byte by byte, including one that
patches a central-directory compression method to prove the unsupported-method
path really did escape before the fix.

## 0.5.4 — 2026-09-24

Batches 3 and 4 of the `archive_analysis` comment pass: the RAR handlers,
then 7z, CAB, ISO and ACE. Documenting the 7z handler turned up three
defects, one of them a decompression-bomb guard that could be bypassed
outright. All three were measured against py7zr 1.1.0 rather than reasoned
about.

### Fixed — `sevenzip_handler`

- **The decompression-bomb budget could be bypassed entirely.** py7zr offers
  no per-member read, so the budget is enforced as a single pre-flight sum
  before `extractall`. That sum excluded encrypted members, on the
  assumption `extractall` would not produce them — but py7zr describes
  encryption only for the archive as a whole, so *every* member of a
  password-protected archive reads as encrypted and the sum collapsed to 0,
  which passes any budget. `extractall` then ran unbounded, decompressing
  whatever was not actually encrypted before failing on whatever was.
  Demonstrated on a password-protected archive holding 1002 bytes: the
  guard compared 0 against the limit. Every member counts now; refusing a
  fully-encrypted archive on its declared size costs nothing, since
  extracting it without the password fails anyway.

- **Every 7z member's timestamp was wrong by the host's UTC offset.** py7zr
  returns an aware UTC `datetime`; `timetuple()` discards the tzinfo and
  `time.mktime` then reads the naive result as local time. Measured at
  exactly 32400s under `TZ=Asia/Tokyo`. A report's timestamps are evidence,
  and being uniformly wrong is worse than being absent because nothing in
  the output says so.

- **The encryption test read an attribute that does not exist.** `FileInfo`
  spells it `crc32`; the code asked for `crc`, so the "missing CRC" half of
  the condition always held and the flag was archive-level by accident.
  Reading the real field would have inverted the test rather than fixed it:
  an encrypted member carries the *same* crc32 as the same bytes stored
  unencrypted, and the only entries reporting `None` are directories. The
  flag is archive-level deliberately now, and `ArchiveEntry.crc` is
  populated rather than always `None`.

### Documented

- `rar_handler` / `rar_raw_headers` — why every member name is read twice,
  by `rarfile` and again by the raw walker: the library strips the NTFS ADS
  suffix that CVE-2025-8088 hides its whole drop path inside, so the
  sanitised view is what you extract with and the raw view is what you
  judge. Records that the STM stream name lives in the service record's
  *header body*, not its data area — established from the samples rather
  than the specification, and the one fact the module exists to encode.
  Also records the 64 MiB read cap as a real gap rather than a memory
  bound: past it the walker reports fewer members than `rarfile`, so ADS
  recovery is refused wholesale.

- `sevenzip_handler` / `other_handlers` — py7zr's all-or-nothing extraction
  is what shapes the 7z path, including why duplicate members are genuinely
  unrecoverable for that format. Not extracting ACE is recorded as a
  security decision rather than a missing feature.

### Tests

**832 → 837.** The 7z tests build real archives with py7zr and assert
against what the library actually returns, since all three defects were
assumptions about it that reading could not settle.

## 0.5.3 — 2026-09-24

The `archive_analysis` commenting pass. Writing down why each check is shaped
the way it is turned up four more defects, three of them evasion paths, in
code the 0.5.2 sweep had already read. Each was fixed test-first in its own
commit and cleared the review gate before any comment describing it was
committed.

### Fixed — `sfx_detect`

- **A failed SFX payload dump left the carved bytes in `/tmp`.**
  `_dump_payload` opens with `delete=False` because the payload has to outlive
  the call for the orchestrator to re-enter the pipeline on it, so the file
  exists from the moment it is created and nothing else removes it. Four paths
  leaked it: a refused write returned `None` from an `except OSError` that did
  not unlink; a flush failing at `close` did the same; and `MemoryError` and
  `KeyboardInterrupt` bypassed the handler entirely — an overlay can be
  hundreds of megabytes, and a triage run is where someone presses Ctrl-C.

  Fixed structurally rather than by stacking guards. Ownership transfers at
  exactly one point, and the outer `finally` holds the unlink and nothing
  else, so no statement can precede it and be interrupted before it runs.
  `close()` stays inside the `try`, because a write that never reaches disk
  must fail the dump — handing the orchestrator a truncated payload to recurse
  into and score is a wrong answer, which is worse than the missing one.

### Fixed — `zip_handler`

- **The header-mismatch detector missed the sizes that matter.** A ZIP carries
  every member's size twice and nothing makes the two agree; Explorer and
  7-Zip extract from the local header while `zipfile` — and therefore the
  decompression-bomb guard — reads the central directory. Detecting that
  divergence is the only reason the raw parser exists. It had five blind
  spots:

  `uncompressed_size` was parsed from both headers and never compared, so the
  one field every bomb threshold is measured against was the one field not
  checked. The comparison required *both* headers to declare a non-zero
  compressed size, so a central directory of 0 made a member vanish from every
  size check here while the local header still declared the real size —
  verified against a hand-built archive where `zipfile` reported `file_size 0`
  and the detector reported nothing. Excusing a zero field by field granted
  the streaming exemption per field rather than per member. Taking the
  streaming flag from the local header alone allowed the same bypass more
  cleanly. And any field holding the Zip64 sentinel was skipped outright.

  The exemption is now an entry-level decision read from general-purpose bit 3
  in *both* headers, and the headers disagreeing about that bit is itself
  reported. A genuinely streamed member sets it in both — confirmed by writing
  one through a non-seekable stream. Zip64 sentinels are resolved through the
  extended-information field rather than skipped, respecting that a local
  header writes both sizes while a central directory writes only the
  sentinelled ones; a sentinel with no backing field is now a finding in its
  own right. `compression_method` comparison was dropped while the block
  around it was rewritten and had no test to notice — restored, with one.

- **A duplicate member name hid a header mismatch.** Records were
  deduplicated by filename, so only the first record under a name was ever
  compared against its own local header. Repeated names are distinct records
  pointing at distinct local headers, which made a benign record placed first
  a way to hide whatever the second declared — in the one shape this package
  already treats as payload-hiding. Every record is compared now; identical
  findings are collapsed afterwards.

### Fixed — `embedded_exec`

- **A modern Linux executable was not recognised as one.** The MIME table
  mapped `application/x-executable` but not `application/x-pie-executable`,
  and distributions have built executables position-independent by default for
  years — `/usr/bin/ls` and `/bin/bash` on the development machine both report
  the PIE type. An ELF payload inside an archive was typed as "not an
  executable" and never hashed or forwarded to VirusTotal. ELF is a deliberate
  *analysis* exclusion; hashing is not, since a hash lookup needs no platform
  support and a Linux payload in a Windows-delivered archive is worth
  reporting.

### Measured

False positives were measured rather than assumed: the reworked ZIP header
comparison produces **zero findings across 91 real ZIP-shaped files** — the
whole sample corpus plus packaged wheels. The Zip64 path is exercised by a
real sample: `APT36.docm` carries sentinels with a proper `0x0001` field for
three of its sixteen members, which is what first showed that skipping them
was wrong.

### Documented

Comment passes over the `archive_analysis` foundation (`entries`, `scoring`,
`bomb_guard`, `routing`, `sfx_detect`) and its ZIP/TAR handlers
(`zip_handler`, `tarball_handler`, `embedded_exec`). Both verified with
`bin/verify_comments.py` — identical ASTs, so no executable code rode along.

### Tests

**811 → 832.** The new ones build ZIPs byte by byte, because an archive that
lies cannot be produced by a library that writes correct ones.

## 0.5.2 — 2026-09-20

Reading `archive_analysis` for the commenting pass surfaced twelve defects
before a line of documentation was written. Several were exploitable. Each was
fixed test-first in its own commit and cleared the Gemini review gate.

### Fixed — `file_intake`

- **A 30 MB archive spent 227.4s in `file_intake`** while every analysis module
  in the same scan finished in 0.3s. Profiling put 226.8s of that (99.7%) in
  `ppdeep._spamsum` across 345M `next()` calls. The pure-Python ssdeep fallback
  — the one that lets ThreatLens install without a compiler — had no size guard
  at all. Measured across the 27-sample RAR corpus it costs a flat 0.78 s/MB,
  rising to 4.4 s/MB on input that makes ssdeep halve its blocksize and rescan,
  so cost was unbounded in file size.

  Now capped at 8 MiB (`max_ppdeep_size_mb`) for the pure-Python backend only;
  the C extension is roughly two orders of magnitude faster and stays uncapped.
  Past the ceiling the fuzzy hash is `null` and a warning names the file, its
  size and the remedy — MD5, SHA256 and TLSH are untouched. **227.4s → 0.53s.**

  This corrects the known issue recorded as a suspected loop in the RAR5
  raw-header walker. That walker is sound: it does the same sample in 0.296s
  and is bounded by an iteration guard. The stall reproduced on any
  sufficiently large file regardless of format, so `Gh0stRAT.rar` and
  `LummaStealer.rar` at ~20 MB were paying it too.

- An explicit `max_ppdeep_size_mb: null` crashed on `float(None)` and took the
  pipeline with it. Unusable values now fall back with a warning.
- The uncapped C path still read whole files via `read_bytes()`. Nothing bounds
  its input and an OOM `SIGKILL` cannot be caught, so it prefers
  `hash_from_file` where the backend provides it.

### Fixed — `archive_analysis` detection

- **Seven of seventeen persistence-path markers could never match.** Every
  Windows form was written as a raw string ending in `\\` — two literal
  backslash characters — while `detect_persistence_paths` collapsed doubled
  separators to single, so a real member path never contained one. The
  indicator was blind to `appdata\roaming`, `appdata\local`, `startup`,
  `start menu\programs\startup`, `system32`, `syswow64` and `temp` — the
  normal shape for a Windows-authored archive, and the exact shape of the
  CVE-2025-8088 Startup drop, whose entire payload is
  `..\..\AppData\Roaming\...\Startup\Updater.exe` hidden in an NTFS ADS
  suffix. That sample now reports its Startup path for the first time.

  The matcher canonicalises separator runs rather than replacing them, which
  closed a second hole: `appdata//roaming/x.exe` survived a sequential replace
  and failed the substring match, while Windows canonicalises the redundant
  separator away and drops the file exactly where the marker says. Padding a
  separator was a one-character evasion primitive.

- **Archive comments bypassed every false-positive filter.**
  `scan_comments_for_iocs` ran `ioc_extractor`'s regexes without
  `_filter_fps`, so the 210-entry TLD allow-list and the non-routable-address
  filter never applied. A benign comment reading "see readme.txt and setup.exe"
  produced two "domains", set `comment_ioc` and scored +3; private, loopback
  and RFC 5737 documentation addresses were reported as external IOCs.

- **Duplicate member names hid payloads from extraction.** A member's name is
  attacker-controlled and is not unique, and every archive library resolves a
  name to exactly one record — so extracting by name read that record once per
  duplicate and never opened its siblings. A ZIP with two `payload.bin` records
  yielded the same bytes twice; so did a tar. Members are now addressed by
  `ArchiveEntry.member_index` in ZIP, RAR and TAR.

  7z, CAB and ISO cannot work that way: the first two are unpacked wholesale
  by an external tool that writes one duplicate over the other before
  ThreatLens sees the disk, and ISO's `pycdlib` exposes no index-based read,
  so a repeated path resolves to one record and its sibling is unreachable.
  The ISO extractor instead claims each source path once, leaving the
  shadowed member unmapped rather than extracting the same record twice. Those bytes are
  genuinely unrecoverable, so they are now reported —
  `duplicate_member_name` (+3) and `shadowed_member_unrecoverable` (+5) — and
  the mapper refuses to let two entries claim one file, so an overwritten
  member is never counted as analysed.

  Collisions are counted over every spelling a member could be written under,
  not the raw string: `a.exe`, `./a.exe`, `C:\a.exe` and `nested/../a.exe` are
  one destination. A shared *basename* across two directories is deliberately
  not a collision — measured, `py7zr.extractall` preserves the directory tree,
  so `dir1/style.css` and `dir2/style.css` both survive and counting that would
  score +8 MALICIOUS across a large benign population.

### Fixed — `archive_analysis` safety

- **Every `.gz`/`.bz2`/`.xz` scan leaked its decompressed payload.**
  `_dispatch_enumerate` created its own `mkdtemp` and returned only the
  entries, so the path was unreachable and nothing ever removed it — live
  malware accumulating in `/tmp` across a triage run. The orchestrator now owns
  the scratch directory outright and cleans it in a `finally`.

- **A `tar.gz` bomb was inflated in full before the guard saw it.** The
  documented guarantee "the bomb guard runs before extraction" holds only for
  formats with a central directory. TAR has no index, so `getmembers()`
  discovers members by walking the stream — for a compressed tarball, by
  decompressing all of it. A 597 KiB file expanding to 600 MiB took 2.65s to
  enumerate, all of it spent on a payload nothing had approved.
  `enumerate_tar` now iterates, so a member declaring more than the whole-tree
  budget is rejected on its declared size and its payload is never inflated.
  **2.65s → 0.00s.**

- Refusing a traversing member name outright orphaned the payload the extractor
  had safely written — prefixing `../` was a way to skip 7z and CAB analysis
  entirely.
- The path mapper attributed surviving bytes to the record they overwrote, and
  a fallback spelling could outrank another member's primary one. Claiming now
  runs in two passes, reverse order within each.
- Drive letters defeated collision detection: `C:\malware.exe` and
  `malware.exe` land on one file but never matched. The mapper and the
  indicator now share one canonicalisation, `entries.member_destinations` —
  they were separate implementations and drifted four times during review, and
  every drift was a hole.
- `extract_tar_members_to_temp` walked the stream to the end, re-inflating the
  bomb the enumeration guard had just refused; and `list(tf)` discarded every
  member recovered before a truncation.
- `rarfile` handle leaked whenever `infolist()` failed before the `with` block.
- `RuntimeError` from `Path.resolve()` on a planted symlink loop went uncaught.
- Extraction errors never reached the report: `data["errors"]` snapshotted
  `meta.handler_errors` before extraction ran, and `list()` copies.

### Changed

- Five `len(list(tmp_dir.iterdir()))` counters replaced with a monotonic index.
  The temp directory was relisted once per member, making naming O(n²).
- New config key `max_ppdeep_size_mb` (default 8), documented in
  `docs/usage.md`.
- New scoring rules `duplicate_member_name` and
  `shadowed_member_unrecoverable`, documented in `docs/scoring.md`.

### Known

- Nested damping is documented in CLAUDE.md and prepared for in
  `core/scoring.py` — `_clamp` accepts a float precisely for it — but nothing
  produces a damped value. `_analyse_archive` merges a nested child's flags and
  discards its `score_delta`. Deferred to the end-of-project calibration sweep,
  since wiring it moves every nested archive's score.

### Tests

698 → 811. Four new archive files plus `test_file_intake.py`.

## 0.5.1 — 2026-09-10

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
