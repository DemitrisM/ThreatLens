## What this project is
**Tool name: ThreatLens**
GitHub repo: github.com/DemitrisM/ThreatLens

## What this project is
A portable CLI malware analysis tool (final year cybersecurity project).
User inputs a suspicious file → tool performs static analysis → outputs
a structured threat report with transparent confidence scoring.
Target users: SOC analysts, security students, CTF participants.
Built on Ubuntu Linux. Primary language: Python 3.x.

## Full project reference
See docs/project_full.txt for complete feature list, architecture,
build order, and implementation notes. Read it before making any
structural decisions.

---

## Core design rules — NEVER violate these

1. Every analysis module returns exactly this structure:
   {
     "module": "module_name",
     "status": "success" | "skipped" | "error",
     "data": { ... },
     "score_delta": <int>,
     "reason": "<human-readable explanation of score contribution>"
   }

2. Graceful degradation — if a dependency is missing:
   - Log a warning (do not print, use logging module)
   - Set status to "skipped"
   - Return the standard dict with empty data and score_delta 0
   - NEVER raise an unhandled exception that kills the pipeline

3. Never send actual files externally — hash-only lookups to VirusTotal

4. Use pathlib.Path for ALL file paths — never hardcode / or \ separators

5. Use tempfile.mkdtemp() for temp directories — never hardcode /tmp

6. Every module must have a timeout — long-running tools (capa, FLOSS)
   must not hang the pipeline indefinitely

7. Use Python logging module throughout — never use print() for status
   messages. Support --verbose and --debug CLI flags.

---

## Tech stack

### Python libraries
- pefile          — PE file parsing
- python-magic    — File type detection (needs libmagic system lib)
- tlsh            — Fuzzy hashing
- ssdeep          — Fuzzy hashing (supplement)
- yara-python     — YARA rule matching
- oletools        — Office document analysis (olevba, mraptor, oleid)
- peepdf          — PDF analysis
- requests        — VirusTotal API calls
- rich            — Terminal formatting and progress bars
- jinja2          — HTML report templating
- pyyaml          — config.yaml loading
- pytest          — Testing framework
- click or argparse — CLI argument parsing

### External binaries (in ./bin/, downloaded by install.sh)
- FLOSS  — mandiant/flare-floss — string deobfuscation
- capa   — mandiant/capa — capability detection + MITRE ATT&CK mapping

### YARA rules (in ./rules/yara/, downloaded by install.sh)
- Neo23x0 signature-base
- ESET malware indicators

---

## Project directory structure

malware-triage/
├── main.py                        # Entry point, CLI
├── config.yaml                    # User configuration
├── CLAUDE.md                      # This file
├── pyproject.toml                 # Dependencies
├── install.sh                     # Setup script
├── Dockerfile
├── docker-compose.yml
├── README.md
├── docs/
│   └── project_full.txt           # Full project reference document
├── core/
│   ├── pipeline.py                # Orchestrates all modules
│   ├── file_intake.py             # Type detection, hashing
│   ├── scoring.py                 # Confidence score engine
│   └── config_loader.py           # Loads config.yaml
├── modules/
│   ├── static/
│   │   ├── pe_analysis.py         # pefile: headers, sections, entropy
│   │   ├── string_analysis.py     # FLOSS + raw strings
│   │   ├── ioc_extractor.py       # Regex IOC extraction
│   │   ├── capa_analysis.py       # capa + ATT&CK mapping
│   │   ├── yara_scanner.py        # YARA matching
│   │   ├── doc_analysis.py        # oletools: Office docs
│   │   └── pdf_analysis.py        # peepdf: PDFs
│   ├── enrichment/
│   │   └── virustotal.py          # VT hash lookup
│   └── dynamic/
│       ├── provider_base.py       # Abstract base class
│       ├── speakeasy_provider.py
│       ├── vm_worker_provider.py
│       └── cape_provider.py
├── reporting/
│   ├── json_reporter.py
│   ├── terminal_reporter.py       # rich-based
│   ├── html_reporter.py           # Jinja2
│   └── templates/
│       └── report.html.j2
├── rules/
│   └── yara/
├── bin/
│   ├── floss                      # Linux binary
│   └── capa                       # Linux binary
├── tests/
│   ├── samples/                   # Test samples (gitignored)
│   ├── test_pe_analysis.py
│   ├── test_ioc_extractor.py
│   ├── test_scoring.py
│   └── test_pipeline.py
└── .github/
    └── workflows/
        └── test.yml               # CI/CD

---

## config.yaml structure

```yaml
virustotal_api_key: ""
yara_rules_dir: "./rules/yara"
floss_binary: "./bin/floss"
capa_binary: "./bin/capa"
output_dir: "./reports"
log_level: "INFO"
module_timeout_seconds: 60
enabled_modules:
  - file_intake
  - pe_analysis
  - string_analysis
  - ioc_extractor
  - capa_analysis
  - yara_scanner
  - doc_analysis
  - pdf_analysis
  - virustotal
dynamic_provider: "none"   # none | speakeasy | vm_worker | cape
```

---

## Confidence scoring system

Score bands:
  0-30:   LOW RISK
  31-55:  MEDIUM RISK
  56-75:  HIGH RISK
  76-100: CRITICAL

Score contributions (reference weights — adjust based on testing):
  High entropy section (>7.0):          +15 to +20
  YARA rule match:                       +20 to +30 (varies by rule severity)
  capa: process injection capability:    +20
  capa: network communication:           +10
  capa: anti-analysis / anti-debug:      +15
  No digital signature:                  +15
  Packer detected (UPX etc.):            +15
  Suspicious imports (VirtualAlloc etc): +10
  VT detections > 10 engines:            +25
  VT detections 1-10 engines:            +10
  VT 0 detections (hash not seen):       -5
  Valid digital signature:               -10
  Low entropy (normal binary):           -5

---

## MITRE ATT&CK output format (from capa_analysis.py)

```python
{
  "capability": "inject into process",
  "tactic": "Defense Evasion / Privilege Escalation",
  "technique_id": "T1055",
  "technique_name": "Process Injection"
}
```

---

## Current build phase

UPDATE THIS SECTION as you progress through phases.

### Phase 1 — Foundation (current)
Target: Working pipeline that accepts a PE file and outputs JSON with score

Todo:
  [ ] Project structure (empty files with docstrings)
  [ ] pyproject.toml with all dependencies
  [ ] config.yaml
  [ ] config_loader.py
  [ ] main.py with CLI (click preferred)
  [ ] file_intake.py (python-magic, MD5/SHA256/TLSH)
  [ ] pipeline.py skeleton
  [ ] scoring.py
  [ ] json_reporter.py

### Phase 2 — Static PE intelligence
  [ ] pe_analysis.py (pefile, entropy, packer, signatures, imports)
  [ ] string_analysis.py (FLOSS binary invocation, raw strings)
  [ ] ioc_extractor.py (regex patterns for IPs, domains, paths, etc.)
  [ ] capa_analysis.py (binary invocation, ATT&CK mapping)
  [ ] yara_scanner.py

### Phase 3 — Enrichment + document coverage
  [ ] virustotal.py (hash-only lookup)
  [ ] doc_analysis.py (oletools)
  [ ] pdf_analysis.py (peepdf)
  [ ] terminal_reporter.py (rich)
  [ ] html_reporter.py (Jinja2)

### Phase 4 — Portability + quality
  [ ] install.sh
  [ ] Dockerfile + docker-compose.yml
  [ ] Per-module timeouts
  [ ] Parallel module execution (concurrent.futures)
  [ ] pytest test suite
  [ ] GitHub Actions CI/CD
  [ ] Full graceful degradation audit
  [ ] README.md

### Phase 5 — Dynamic backends
  [ ] speakeasy_provider.py
  [ ] vm_worker_provider.py (if time allows)
  [ ] cape_provider.py (document only if no time)

---

## Important implementation notes

### pe_analysis.py — entropy calculation
Shannon entropy formula. Per-section, not whole file.
Flag sections with entropy > 7.0 as suspicious.
Normal .text section entropy is roughly 5.5-6.5.
Entropy close to 8.0 = almost certainly packed or encrypted.

### string_analysis.py — FLOSS invocation
FLOSS is a binary, not a Python library. Invoke via subprocess.
Use --json flag for structured output. Set timeout from config.
Fall back to basic strings extraction if FLOSS binary not found.

### capa_analysis.py — invocation
Same pattern as FLOSS — subprocess with --json flag and timeout.
capa can be slow on large binaries (30-60 seconds is normal).
Parse the ATT&CK mappings from the attack section of capa JSON output.

### ioc_extractor.py — regex patterns to implement
  IPv4:         \b(?:\d{1,3}\.){3}\d{1,3}\b
  URL:          https?://[^\s<>"{}|\\^`\[\]]+ 
  Domain:       \b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b
  Win filepath: [A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*
  Registry:     HKEY_[A-Z_]+(?:\\[^\r\n"]+)+
  Email:        \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
  
Filter out known false positives (version strings, common DLL names).

### virustotal.py — API response parsing
Endpoint: GET https://www.virustotal.com/api/v3/files/{hash}
Header:   x-apikey: <key>
Parse:    data.attributes.last_analysis_stats (malicious, undetected)
          data.attributes.popular_threat_classification.suggested_threat_label
Handle 404 gracefully (hash not seen before = not necessarily clean).

### html_reporter.py — Jinja2 template
Single self-contained HTML file (inline CSS, no external dependencies).
Sections: summary, score breakdown, MITRE ATT&CK table, IOCs,
          YARA matches, raw module data (collapsible).
Use colour coding: red = critical, orange = high, yellow = medium,
                   green = low.

---

## Testing approach

Test samples (never commit actual malware to git — use .gitignore):
  - MalwareBazaar: https://bazaar.abuse.ch — free API, tagged samples
  - theZoo: https://github.com/ytisf/theZoo — defanged research samples

Minimum test assertions:
  - Known-malicious PE file scores >= 56 (HIGH or CRITICAL)
  - Clean PE file (system binary) scores <= 30 (LOW)
  - Missing dependency does not crash pipeline (returns skipped status)
  - All modules return the standard dict structure

---

## Git workflow

Commit after each working module. Suggested commit messages:
  "feat: add file_intake module with python-magic and TLSH hashing"
  "feat: add pe_analysis with entropy and packer detection"
  "feat: add confidence scoring engine"
  "fix: graceful degradation when FLOSS binary not found"
  "test: add pytest suite for ioc_extractor"
  "chore: add Dockerfile and docker-compose"

---

## Useful Claude Code commands

/compact     — summarise context when conversation gets long
/clear       — start fresh for a new module
/cost        — check token usage for current session

## Efficient prompting patterns for this project

Starting a module:
"Implement modules/static/pe_analysis.py following the module interface
in CLAUDE.md. Include graceful degradation, logging, timeout support,
and score_delta with reason strings for all findings."

Debugging:
"This error occurs when running pe_analysis on a packed binary.
Here is the traceback: [paste]. Here is the relevant function: [paste].
Fix it without changing the module interface."

Code review:
"Review ioc_extractor.py for false positives in the domain regex,
edge cases I may have missed, and any violations of the design rules
in CLAUDE.md."

---

## What makes this project academically strong

1. Confidence scoring with per-module reasoning — no existing free tool does this
2. MITRE ATT&CK mapping — industry standard framework, shows professional awareness
3. Pluggable dynamic backend architecture — demonstrates software engineering maturity
4. Multi-file-type coverage — PE + Office + PDF = three most common attack vectors
5. Portability by design — Docker, install script, graceful degradation

## Viva prep — be ready to explain
- Why each library was chosen over alternatives
- How score weights were calibrated (testing on known samples)
- What TLSH fuzzy hashing adds over MD5/SHA256
- Why only hash (never file) is sent to VirusTotal
- What capa does internally (rule-based capability matching)
- The difference between static and dynamic analysis
- Why static-first design was chosen
- What graceful degradation means and why it matters
