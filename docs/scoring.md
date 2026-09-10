# ThreatLens — Confidence Scoring System

This file is the **single source of truth** for ThreatLens score weights.
When tuning during calibration, edit this file and the corresponding
constants in `core/scoring.py` and the per-module files.

> **Calibration status:** the weights below were tuned ad-hoc as
> indicators were added. A full end-to-end calibration pass against the
> known-malicious + known-benign corpus is still pending and will be
> done at the end of the project — don't treat any single number as
> final.

---

## Score bands

Module `score_delta` values are summed and then clamped to 0–100. Individual modules
can push the raw total above 100 — clamping happens once at the end in `core/scoring.py`.

| Score   | Band       |
|---------|------------|
| 0–30    | LOW RISK   |
| 31–55   | MEDIUM RISK|
| 56–75   | HIGH RISK  |
| 76–100  | CRITICAL   |

### A second band vocabulary exists

Four modules — `archive_analysis`, `doc_analysis`, `onenote_analysis` and
`lnk_analysis`, through the combo engines they share — additionally emit
`MALICIOUS` / `SUSPICIOUS` / `INFORMATIONAL` / `CLEAN` in
`data["classification"]`, on **their own thresholds**, which are not the
0–100 bands above and are not consistent with each other:

| Module | MALICIOUS | SUSPICIOUS | INFORMATIONAL | CLEAN | Cap |
|---|---|---|---|---|---|
| `archive_analysis` | ≥ 7 | 4–6 | 1–3 | 0 | 60 |
| `doc_analysis` | ≥ 7 | 4–6 | 1–3 | 0 | 60 |
| `onenote_analysis` | ≥ 25 | 10–24 | 1–9 | 0 | 60 |
| `lnk_analysis` | ≥ 25 | 10–24 | 1–9 | 0 | 60 |

Both vocabularies render in the same report, so a green `LOW` score banner can
sit directly above a red `MALICIOUS` classification — the archive scored 8/100
overall while its own engine called it malicious. That reads as the tool
contradicting itself and is a **known open issue**. Unifying them is a scoring
change and belongs in the end-of-project calibration sweep, not the reporting
layer.

---

## Verdict weights are NOT score weights

Everything else in this file describes `score_delta` — how much a finding moves
the 0–100 score. There is a **separate, unrelated** weight table in
`reporting/shared.py` (`W_VT`, `W_YARA`, `W_STEALER`, … `W_WEAK`) that decides
only the *order* indicators appear in the one-line verdict sentence.

It exists because the verdict lists at most four indicators, so which four win
those slots matters. `"unsigned binary"` fires for essentially every unsigned
PE, so it carries `W_WEAK = 10` and can no longer lead ahead of, say, stealer
strings — before Pass 4 it took the first slot on the RedLine sample.

Changing a verdict weight changes **sentence wording only**. It never changes a
score, a band, or an exit code. Keep the two tables mentally separate when
calibrating.

---

## Score contributions (provisional, pending final calibration)

### Generic PE indicators

| Indicator | Score |
|---|---|
| High entropy section (entropy 7.0–7.5) | +15 |
| High entropy section (entropy ≥7.5) | +20 |
| No digital signature | +10 |
| Valid digital signature (presence) | 0  *(was −10; commodity stealers ship signed, so presence is no longer treated as a positive)* |
| Packer detected (UPX etc.) | +15 |
| Forged compile timestamp | +5 |

### Suspicious imports — tiered

| Count of suspicious APIs | Score |
|---|---|
| 1–4   | +5 |
| 5–9   | +10 |
| 10–19 | +15 |
| 20+   | +20 |

| Indicator | Score |
|---|---|
| Tiny native import table (<5 funcs, non-.NET) — dynamic resolution / packed | +5 |
| Process-injection / hollowing API combo (≥2 of `NtUnmapViewOfSection`, `SetThreadContext`, `WriteProcessMemory`, `VirtualAllocEx`, `ResumeThread`, …) | +10 |

### API category diversity

| Categories spanned | Score |
|---|---|
| 3   | +5 |
| 4   | +10 |
| 5+  | +15 |

### YARA

Rules are scored **additively** (each match adds its weight independently) before the cap.
Two-stage compilation: bulk first, then per-file fallback so one bad rule doesn't invalidate the set.

| Indicator | Score |
|---|---|
| YARA critical rule | +30 |
| YARA high rule | +25 |
| YARA medium rule | +15 |
| YARA low rule | +5 |
| YARA rule (no severity metadata) | +20 |
| YARA total cap | **60 max** |

### capa (capability detection)

Scoring model: each detected capability is tested against **all** category regex patterns
simultaneously — one capability can fire multiple categories. Per-category score = **max
value seen** across all capabilities matching that category (not sum). Final total =
sum of per-category maxima, capped at 60.

| Capability category | Score |
|---|---|
| Process injection | +20 |
| Anti-analysis / anti-debug | +15 |
| Credential access | +15 |
| Network communication | +10 |
| Persistence mechanism | +10 |
| Data collection / recon | +10 |
| Privilege escalation | +10 |
| Encryption / obfuscation | +5 |
| **capa total cap** | **60 max** |

### IOCs

| Indicator | Score |
|---|---|
| Network IOCs (URLs / IPs) | +10 |
| Suspicious domains | +5 |
| Registry key references | +5 |
| Email addresses | +5 |

---

## pe_analysis structural indicators (PEStudio / DIE / Manalyze-inspired)

| Indicator | Score |
|---|---|
| Single-section PE (shellcode loader) | +10 |
| Section count ≥ 8 (anomaly) | +5 |
| RWX section (read+write+execute) | +15 |
| Section permission anomaly (writable `.text` / exec `.data` / writable `.rdata`) | +10 |
| TLS callbacks (pre-main exec) | +5 |
| High-entropy overlay (≥7.0) | +10 |
| High-entropy `.rsrc` (≥7.0, size ≥ 4 KiB) | +10 |
| Packed .NET (`.text` entropy ≥7.0) | +10 |
| Compiled language fingerprint — Go | +5 |
| Compiled language fingerprint — Rust | +5 |
| Compiled language fingerprint — Nim | +10 |
| Missing ASLR + DEP (no ASLR && no NX) | +10 |
| Missing ASLR alone | +5 |
| Missing DEP alone | +5 |
| Entry point in non-code section | +10 |
| Rich header present but corrupted (linker checksum recompute) | +5 |
| MS-DOS stub modified from default | +5 |
| Suspicious PDB path (`loader` / `stub` / `inject` / …) | +10 |
| Version-info impersonation (Microsoft / Adobe / etc. metadata on an unsigned binary) | +10 |
| Section size mismatch (VirtualSize ≫ RawSize, packed-code marker) | +10 |
| Embedded MZ payload in resources or overlay | +15 |
| Dynamic API resolution (≥5 suspicious APIs as raw strings only — `GetProcAddress` runtime-resolution pattern) | +10 |
| Kernel32-only / loader-only import footprint (`LoadLibrary` + `GetProcAddress` + few else) | +10 |
| PE checksum mismatch on signed binary (post-signing tamper) | +10 |
| AutoIt-compiled binary (`AU3!` marker in `RT_RCDATA`) | +15 |
| Large `RT_RCDATA` blob (≥256 KiB, no AutoIt marker) | +5 |
| Installer wrapper detected (NSIS / InnoSetup / Wise / InstallShield / 7z SFX) | +5 |

---

## string_analysis (severity-weighted, cap 40 + a post-cap bonus)

Score is per unique category fired at each tier, capped at 40 — but the cap is
applied **before** the FLOSS obfuscation bonus, so a FLOSS-sourced result can
return up to **50**. That ordering is deliberate: the tier caps bound what
pattern matching can claim, while the bonus is evidence of a different kind
(the sample built or decoded strings at runtime, which only emulation reveals)
and is not competing for the same budget.

| Tier | Examples | Score per unique category |
|---|---|---|
| Critical | RAT/stealer family name, C2 framework ref (Cobalt Strike/Sliver/Havoc), Telegram/Discord exfil pattern, browser credential path, .NET stealer class/method/field, crypto wallet artefact, process-hollowing API | +10 (cap 30) |
| High | PowerShell evasion flags, LOLBin reference, VM/sandbox check string, anti-debug API name, .NET obfuscator marker, code-injection API string, SMTP exfil host, analysis tool name | +5 (cap 15) |
| Medium | Registry persistence key, schtasks reference, startup path, browser data dir, generic credential keyword, base64 reference, crypto algorithm name | +3 (cap 10) |
| Low | Generic crypto algorithm references | +0 |

---

## VirusTotal (Phase 3)

| Indicator | Score |
|---|---|
| VT detections > 10 engines | +25 |
| VT detections 1–10 engines | +10 |
| VT 0 detections (hash not seen) | −5 |

---

## doc_analysis (capped at 60 total)

Weighted **combo engine**, not an additive checklist — see
`modules/static/doc_analysis/scoring.py`. Each pass emits indicator flags; a
rule fires when its flag set is a subset of what fired. Rules are layered
rather than partitioned, so a flag may appear in several and they all fire:
`ole_package_exec_ext` scores 5 on its own and 9 again with `auto_exec`,
because the base rule prices the artefact and the combination prices the
delivery wrapped around it.

| Flags required | Score | Meaning |
|---|---|---|
| `auto_exec` + `shell_keyword` | +10 | AutoExec + Shell call — macro launches an OS command on open |
| `auto_exec` + `url_downloader_keyword` | +9 | AutoExec + URLDownloadToFile/XMLHTTP — drops remote payload on open |
| `auto_exec` + `ole_package_exec_ext` | +9 | AutoExec + embedded executable in OLE Package |
| `vba_stomping` | +8 | VBA stomping detected (source/p-code divergence) |
| `xlm_exec_call` | +7 | XLM macro uses EXEC/CALL/FORMULA.FILL |
| `template_inject_non_ms` | +7 | Template injection to non-Microsoft URL |
| `rels_oversize` | +7 | Relationship part padded past the parse cap — blinds .rels inspection |
| `template_inject_high` | +6 | External attachedTemplate / oleObject / frame / subDocument |
| `altchunk` | +6 | altChunk relationship (template-injection vector) |
| `heavy_vba_obfuscation` | +6 | Heavy VBA obfuscation (Chr/hex arithmetic) |
| `equation_editor_ole` | +5 | Embedded Equation Editor OLE (CVE-2017-11882 / CVE-2018-0802 candidate) |
| `ole_package_exec_ext` | +5 | OLE Package embeds executable file |
| `packager_shell` | +5 | Packager Shell Object embedded — drops and launches a bundled file |
| `shell_explorer` | +5 | Shell.Explorer / WebBrowser control embedded — loads remote content |
| `htmlfile` | +4 | htmlfile ActiveX object embedded — script execution primitive |
| `rtf_objupdate` | +4 | RTF uses \objupdate — forces object load on open |
| `dangerous_embedded_file` | +4 | Dangerous file extension inside OOXML container |
| `rels_size_mismatch` | +4 | Relationship part declares a smaller size than its stream holds — parser differential |
| `vba_present` | +3 | VBA macros present |
| `xlm_url` | +3 | XLM deobfuscated cells contain HTTP URL |
| `oleid_high_risk` | +3 | oleid reported HIGH-risk indicator |
| `ole_object_in_container` | +2 | Embedded OLE object stream |
| `ole_package` | +2 | OLE Package container embeds a file |
| `altchunk_absolute_path` | +2 | altChunk target is an absolute or UNC path — resolves outside the container |
| `encryption_only` | +2 | Password-protected document with no macros (evasion pattern) |
| `decompression_bomb` | +2 | Decompression-bomb guard tripped on container |
| `malformed_openxml` | +1 | OpenXML container failed clean parse |
| `rtf_parse_failed` | +1 | RTF failed to parse cleanly (possible exploit attempt) |

Classification thresholds are this module's own and are **not** the pipeline's
risk bands: ≥7 MALICIOUS, 4–6 SUSPICIOUS, 1–3 INFORMATIONAL, 0 CLEAN, computed
on the **uncapped** total. A document can read MALICIOUS here while the scan
banner reads LOW, because 60 is a ceiling on a 100-point budget.

Every flag any pass emits must appear in at least one rule above;
`tests/test_doc_analysis.py::test_every_emitted_flag_is_scored` enforces it.

---

## html_analysis (capped at 60 total)

Additive, with one clamp at the end. Weights encode *how far the delivery
chain got*: a decoded payload outscores the mechanism that would have
delivered it, and clipboard poisoning with a LOLBin — ClickFix — is the
single highest-scoring indicator in the module, because the victim is being
told to run the command themselves.

| Indicator | Score |
|---|---|
| Clipboard poisoning containing a LOLBin (ClickFix) | +35 |
| Embedded PE payload in a base64 blob | +30 |
| `eval(atob(…))` — inline base64-encoded JS execution | +30 |
| Embedded ZIP / OLE2 / CAB in a base64 blob | +20 |
| Blob delivery chain (`new Blob` + `URL.createObjectURL`) | +20 |
| Embedded RAR / 7-Zip / gzip in a base64 blob | +15 |
| Clipboard write without a LOLBin | +15 |
| Social-engineering lure text | +15 |
| Suspicious external domain (known-bad TLD / pattern) | +15 |
| Large undecodable blob (≥10 KiB) | +10 |
| Dangerous download extension | +10 |
| `navigator.msSaveOrOpenBlob` — auto-save to disk | +10 |
| Auto-trigger on load (`onload` + download mechanism) | +10 |
| `eval()` alone (not already counted as `eval(atob())`) | +10 |
| `String.fromCharCode()` obfuscation | +10 |
| Junk-comment camouflage | +10 |
| `new Function()` constructor | +10 |
| XHR / Fetch beacon to an external domain | +10 |
| WebSocket connection (live C2 channel) | +10 |
| Other suspicious domains | +10 each, max +20 |
| Double extension in a download filename (`.pdf.exe`) | +5 |
| Obfuscated variable names alongside junk comments | +5 |
| `unescape()` percent-encoding obfuscation | +5 |
| External iframe | +5 |
| Meta-refresh redirect to an external URL | +5 |
| **html_analysis total cap** | **60 max** |

Note the two mutually exclusive pairs: `eval(atob())` suppresses the bare
`eval()` row, and a LOLBin-bearing clipboard write suppresses the plain
clipboard row. Blob-type scoring is a single if/elif ladder, so only the
highest-value payload type found is counted, not one row per type.

---

## onenote_analysis (capped at 60 total)

Weighted combo engine (frozensets of flag strings, same pattern as
doc_analysis and archive_analysis). Flags come from the ONESTORE walker's
typed-blob classification in `embedded.py` and `indicators.py`.

| Flags required | Score | Meaning |
|---|---|---|
| `contains_embedded_lnk` + `contains_embedded_script` | +30 | LNK + script chain — the classic IcedID / Qakbot OneNote TTP |
| `contains_embedded_pe` | +25 | Embedded PE executable |
| `contains_embedded_hta` | +25 | Embedded HTA dropper |
| `contains_embedded_msi` | +22 | Embedded MSI installer |
| `contains_embedded_chm` | +20 | Embedded CHM |
| `contains_embedded_lnk` | +15 | Embedded Windows shortcut |
| `contains_embedded_script` | +15 | Embedded script |
| `multiple_dangerous_blobs` | +10 | Several dangerous payloads stacked in one file |
| `encrypted_section` | +8 | Encrypted section — content hidden from static analysis |
| `large_embedded_payload` | +5 | Embedded payload over 100 KiB |
| `blob_count_anomaly` | +5 | Unusual number of FileDataStoreObjects |
| **onenote_analysis total cap** | **60 max** |

Bands are this module's own, as with doc_analysis and archive_analysis:
≥25 MALICIOUS, 10–24 SUSPICIOUS, 1–9 INFORMATIONAL, 0 CLEAN — and the rules
are layered, so the LNK+script combination fires
alongside both single-flag rules it contains (30 + 15 + 15).

---

## pdf_analysis (capped at 60 total)

| Indicator | Score |
|---|---|
| `/OpenAction` (auto-run on open) | +15 |
| `/Launch` (external app launch) | +15 |
| `/EmbeddedFile` | +15 |
| `/JavaScript` | +10 |
| `/AA` (additional actions) | +10 |
| `/SubmitForm` | +10 |
| `/RichMedia` | +10 |
| `/JS` / `/EmbeddedFiles` / `/XFA` / `/GoToR` / `/GoToE` / `/ImportData` | +5 each |
| `/Encrypt` present | +10 |
| Password hint in filename | +20 (on top of `/Encrypt`) |
| High URI density (≥10 `/URI`) | +5 |
| Very high URI density (≥30 `/URI`) | +10 |
| High action density (≥10 `/Action`) | +5 |
| Very high action density (≥20) | +10 |
| Missing `%PDF` header, HTML body | +40 (HTML smuggling) |
| Missing `%PDF` header, other | +15 |
| peepdf JavaScript extracted | +10 |
| JS exploit pattern (`eval` / `unescape` / `ActiveX` / …) | +15 |
| JS social-engineering alert (e.g. "not compatible", "open in browser") | +10 |
| peepdf suspicious components | +5 |
| peepdf structural anomalies | +5 |

---

## archive_analysis (capped at 60 total)

Weighted combo engine (same pattern as doc_analysis — frozensets of
flag strings, weights, one row per rule). Flag strings are produced by
`indicators.py`, `zip_handler`, `sfx_detect`, `embedded_exec`, and
`rar_raw_headers`. The weights below are initial calibration values;
finalised at end of project.

| Required flags (frozenset) | Weight | Reason |
|---|---|---|
| `zip_header_mismatch` | +10 | LFH/CD disagree — AV evasion trick |
| `sfx_dropper` | +10 | PE with archive payload in overlay |
| `path_traversal` | +9 | ZipSlip / CVE-2025-8088 class |
| `symlink_attack` | +9 | Symlink to /etc/, /root/, C:\Windows, etc. |
| `rtlo_filename` | +8 | Right-to-left override / bidi filename |
| `header_encrypted` | +6 | Full archive listing needs password (RAR5 / 7z) |
| `null_byte_filename` | +6 | Null byte in member name |
| `autorun_inf` | +6 | Root-level autorun.inf |
| `embedded_pe` + `dangerous_member` | +5 | Inner executable + risky extension |
| `persistence_path` + `dangerous_member` | +5 | Startup-folder drop |
| `double_extension` | +5 | `photo.jpg.exe` class |
| `mime_mismatch` | +5 | Declared-type / libmagic-type disagreement |
| `is_encrypted` + `dangerous_member` | +4 | Password-protected with risky name |
| `bomb_guard` | +4 | Ratio / size / count threshold tripped |
| `ace_detected` | +4 | ACE archive (CVE-2018-20250 class) |
| `comment_ioc` | +3 | IP / URL in archive comment |
| `high_entropy_filename` + `dangerous_member` | +3 | High-entropy name + risky ext |
| `dangerous_member` (alone) | +3 | `.exe` / `.lnk` / `.hta` etc. inside archive |
| `is_encrypted` (alone) | +2 | Password-protected archive |
| `timestamp_anomaly` | +1 | All-identical / DOS-zero / out-of-range timestamps |
| `desktop_ini` | +1 | desktop.ini at root |
| `nested_archive` | +1 | Extra layer per recursion depth |

**Classification bands** (same cutoffs as doc_analysis):
- `≥7` → MALICIOUS
- `4–6` → SUSPICIOUS
- `1–3` → INFORMATIONAL
- `0`   → CLEAN

**Nested-archive damping**: child `score_delta` is added with damping
factors `0.5 → 0.25 → 0.125` at depths 1 → 2 → 3 to prevent infinite
compounding. Total is clamped to `SCORE_CAP = 60`.

**VirusTotal embedded-hash contribution** (applied inside
`virustotal.py`, not `archive_analysis`): +2 per embedded SHA256
with `detection_ratio > 0`, capped at +10 total so one infested
archive can't saturate the 100-point scale.

**CVE-2025-8088 note**: the `path_traversal` rule fires on both
classical ZipSlip-style `../` member names and on NTFS Alternate
Data Stream suffixes that WinRAR 7.x uses to hide the real drop
path (e.g., `fiyat teklifi.pdf:..\\..\\AppData\\...\\Startup\\Updater.exe`).
The `rarfile` library strips those suffixes from the entry name, so
`archive_analysis/rar_raw_headers.py` parses the RAR4/RAR5 headers
directly to recover the unsanitised form and expose it to the
indicator as `ArchiveEntry.raw_name`.

---

## lnk_analysis (capped at 60 total)

Frozenset combo rules in `modules/static/lnk_analysis/scoring.py`. A rule
fires when its flag set is a subset of the observed flags; weights sum,
then clamp at `SCORE_CAP = 60`. Bands are computed on the **uncapped**
total and mirror `onenote_analysis` exactly (≥ 25 MALICIOUS, 10–24
SUSPICIOUS, 1–9 INFORMATIONAL, 0 CLEAN) — reusing an existing vocabulary
rather than inventing a fourth.

| Flags | Weight | Rationale |
|---|---|---|
| `lolbin_target` + `args_padding_zdi` | 40 | ZDI-CAN-25373 / CVE-2025-9491 — the real command hidden past the Properties dialog's 260-character visible window |
| `lolbin_target` + `encoded_powershell` | 35 | Base64 `-enc` payload behind a LOLBin |
| `overlay_present` + `overlay_extraction_command` | 35 | Appended payload *and* the findstr/mshta/PowerShell that carves it out |
| `overlay_executable` | 30 | PE/ZIP/script appended past the terminal block |
| `lolbin_target` + `download_cradle` | 30 | Download-and-execute |
| `webdav_remote_exec` | 30 | `\\host@SSL\share` — runs a payload off an attacker share with nothing written to disk, so no download-cradle pattern can fire |
| `lolbin_target` + `remote_url_in_args` | 28 | LOLBin fetching a remote URL |
| `args_smuggled_in_target` | 25 | Arguments hidden in the target field |
| `icon_masquerade` | 25 | Document icon over an executable target (T1027.012) |
| `remote_icon_location` | 25 | Icon fetched remotely — download + NTLM coercion primitive |
| `suspicious_host` | 22 | Known malware-hosting infrastructure |
| `unc_or_webdav_target` | 20 | UNC/WebDAV target |
| `env_path_override_mismatch` | 20 | EnvironmentVariableDataBlock overrides the displayed target |
| `args_padding_heavy` | 20 | Strong whitespace padding short of the full ZDI shape |
| `unc_in_arguments` | 18 | Command line references a UNC network path |
| `lolbin_target` + `hidden_window` | 18 | `-w hidden` |
| `lolbin_target` + `exec_bypass` | 16 | `-nop` / `-ep bypass` |
| `args_over_1024_chars` | 15 | Argument string far past any legitimate length |
| `long_relative_path_traversal` | 15 | More than 4 `..\` levels |
| `double_extension_name` | 15 | `Invoice.pdf.lnk` |
| `no_tracker_block` + `has_arguments` + `lolbin_target` | 15 | Built programmatically, not by Explorer |
| `sanitised_machine_id` | 14 | TrackerDataBlock present but MachineID blanked |
| `obfuscation` | 13 | Caret/backtick splitting, `%VAR:~n,m%`, base64 decode |
| `timestamp_source_mismatch` | 12 | Header FILETIMEs disagree with the shell items' DOS dates |
| `high_entropy` | 12 | ≥ 6.5 — bartblaze's `High_Entropy_LNK` threshold |
| `large_file` | 12 | > 100 KiB — bartblaze's `Large_filesize_LNK` threshold |
| `overlay_present` | 10 | Any data past the terminal block |
| `target_in_user_dir` | 10 | Target under `%TEMP%`/`%APPDATA%`/Public |
| `filesize_zero` | 10 | Header claims a 0-byte target while carrying arguments |
| `vm_oui_mac` | 10 | Build NIC MAC belongs to VMware/VirtualBox/QEMU/Hyper-V |
| `header_anomaly` | 10 | [MS-SHLLINK] MUST-violations |
| `script_payload` | 9 | Script extension in the command line |
| `timestamps_fabricated` | 8 | Zeroed, identical, or write-before-creation |
| `many_arguments` | 6 | More than four tokens (Intezer heuristic) |
| `args_padding_light` | 5 | 8–99 consecutive whitespace characters |
| `lolbin_target` | 5 | **Deliberately low** — see below |

**Why `lolbin_target` alone is only worth 5.** The Windows Start Menu
ships `Windows PowerShell.lnk`, whose target *is* `powershell.exe`. A
module that classes that SUSPICIOUS is useless on a real desktop. The
score has to come from combinations, which is also how the format is
actually abused. `tests/test_lnk_analysis.py::test_stock_start_menu_shortcut_stays_quiet`
pins this.

**Padding thresholds.** The position-aware ZDI check is the high-fidelity
one: the first 260 characters ≥ 95% whitespace *and* non-whitespace
content beyond offset 260. The cruder tiers come from SigmaHQ
`proc_creation_win_susp_lnk_exec_hidden_cmd` (17 consecutive spaces, 6
consecutive newlines). The whitespace *ratio* rule only applies once the
string exceeds 260 characters — below that everything is on screen, so a
space-heavy argument is untidy rather than evasive.

**What is deliberately not scored.** Unit 42's structural prevalence
figures (LinkTargetIDList in 99.53% of malicious samples, RELATIVE_PATH
75.49%, COMMAND_LINE_ARGUMENTS 35.52%) are recorded in `data` as context
but carry no weight — they are too common in benign shortcuts to
discriminate. The widely-repeated 4096-character argument limit is also
not validated: it has no primary Microsoft source and is probably a
shell/dialog limit. The format ceiling is the uint16 `CountCharacters`
field, 65,535.
