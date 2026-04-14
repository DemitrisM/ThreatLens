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

| Score   | Band       |
|---------|------------|
| 0–30    | LOW RISK   |
| 31–55   | MEDIUM RISK|
| 56–75   | HIGH RISK  |
| 76–100  | CRITICAL   |

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

| Indicator | Score |
|---|---|
| YARA rule match | +5 to +30 (by severity metadata) |
| YARA total cap | **60 max** |

### capa (capability detection)

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

## string_analysis (severity-weighted, capped at 40 total)

| Tier | Examples | Score |
|---|---|---|
| Critical | RAT/stealer family name, C2 framework class, .NET stealer rule class, … | +10 |
| High | Process-hollowing API string, browser cred path, Telegram/Discord exfil, … | +5 |
| Medium | LOLBin reference, PowerShell offensive pattern, anti-VM string, … | +3 |

---

## VirusTotal (Phase 3)

| Indicator | Score |
|---|---|
| VT detections > 10 engines | +25 |
| VT detections 1–10 engines | +10 |
| VT 0 detections (hash not seen) | −5 |

---

## doc_analysis (capped at 60 total)

| Indicator | Score |
|---|---|
| VBA macros present | +10 |
| VBA auto-exec trigger | +10 |
| Suspicious VBA keyword set | +10 |
| VBA IOC patterns | +5 |
| MacroRaptor "suspicious" | +15 |
| High-risk oleid indicator | +5 each |
| OpenXML altChunk / aFChunk relation | +30 |
| altChunk Target uses absolute path | +5 (exploit marker bonus) |
| OpenXML external `attachedTemplate` / `subDocument` | +20 |
| OpenXML other external `TargetMode` | +10 |
| Dangerous embedded file ext (.exe / .dll / .rtf / .hta / …) | +10 to +25 |
| OLE object streams inside container | +10 |
| RTF `\objupdate` + `\objdata` combo | +10 |
| RTF embeds Equation Editor class (CVE-2017-11882) | +25 |
| RTF embeds Package / shell class | +15 to +20 |
| Each embedded OLE in RTF | +5 (cap 20) |
| RTF packaged file drop | +15 |

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

## archive_analysis (capped at 60 total) — PENDING IMPLEMENTATION

Weighted combo engine (same pattern as doc_analysis — frozensets of
flag strings, weights, one row per rule). Flag strings are produced by
`indicators.py`, `zip_handler`, `sfx_detect`, `embedded_exec`. The
weights below are initial calibration values; finalised at end of
project.

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
