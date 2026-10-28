# ThreatLens

Static malware triage for the command line, with transparent confidence
scoring. Every point in a score is attributable: the report says which module
awarded it and why, so a verdict can be argued with rather than just believed.

Version 0.6.1. MIT licensed.

## What it does

Point it at a file. It identifies the format from magic bytes rather than the
extension, runs the modules that apply, and prints a score, a risk band and the
findings behind both.

Thirteen modules ship enabled:

| | |
|---|---|
| `file_intake` | hashes (MD5/SHA256/TLSH/ssdeep), type detection, entropy |
| `pe_analysis` | PE headers, imports, sections, packer indicators |
| `string_analysis` | FLOSS — static, and stack/decoded strings under `-p deep` |
| `ioc_extractor` | URLs, IPs, domains, registry paths, mutexes |
| `capa_analysis` | capa capability matching |
| `yara_scanner` | YARA rules from `rules update` |
| `doc_analysis` | OLE/OOXML macros, VBA, XLM |
| `pdf_analysis` | peepdf — JavaScript, launch actions, embedded files |
| `html_analysis` | smuggling patterns, obfuscated script |
| `archive_analysis` | ZIP/RAR/7z/ISO members, bomb guards, nested recursion |
| `onenote_analysis` | embedded payloads in `.one` files |
| `lnk_analysis` | shell-link targets, arguments, overlays |
| `virustotal` | hash-only lookup, optional, needs a key |

Analysis is static, with two disclosed exceptions. `file_intake` always runs;
everything else is chosen by the profile and the file type. The sample is
never launched, and no payload is run as a program — but a PDF's JavaScript
**is** executed in a V8 engine and Excel 4.0 macro formulas **are**
interpreted, because that is the only way to recover a payload assembled at
runtime. Both are on by default, both are disclosed in the report, and the
first is switchable. See [What runs your sample's code](#what-runs-your-samples-code).

## Requirements

- **x86-64 only.** `peepdf-3` requires STPyV8, which publishes no arm64 wheel.
  This is a property of the dependency, not of the container. Check this first
  — `uname -m` must print `x86_64`. On ARM neither path below works, and that
  is cheaper to learn before a twenty-minute build than after one.
- Either **Docker** with Compose v2, or **Python 3.10+** on Linux.
- **Budget up to 20 minutes and 4 GB free disk** for the first build, and
  expect wide variance between machines. Two cold builds, both from an empty
  cache:

  | | machine A | machine B |
  |---|---|---|
  | `docker compose build` | **5m 0s** | **18m 39s** |
  | Final image | **740 MB** | 1.31 GB |
  | Build cache left behind | 1.25 GB | 1.94 GB |

  Those two rows are not additive — the image and the build cache share
  layers, so the disk actually consumed is less than their sum and is worth
  checking with `docker system df` rather than arithmetic. The 4 GB above is
  headroom for the slower column plus `rules update`, which adds 2–3 minutes
  and 752 rule files. The build compiles `py-tlsh` and `ssdeep` from source,
  runs two `pip wheel` passes over the lockfile and clones the capa rules and
  FLIRT signatures, so several quiet minutes are normal and not a hang.
  `docker builder prune` reclaims the cache afterwards.

### Docker Engine

**Already have Docker?** Check with `docker --version` and skip to
[Compose v2](#compose-v2). Do not run the block below over a working
install — `docker.io` is the distribution's engine package and conflicts
with `docker-ce` from Docker's own apt repository, so on a machine that
already has `docker-ce` it either aborts on a dpkg conflict or silently
replaces your engine with an older one.

If you have no Docker at all, on Debian or Ubuntu — needs root, once:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-buildx
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

`docker-buildx` is not optional: `docker compose build` drives buildx, and
without it the build either fails or falls back to the legacy builder.

**Then log out and back in.** Group membership only applies to new sessions,
and `usermod` prints nothing either way, so the only way to know it worked is
to test it:

```bash
docker run --rm hello-world     # must succeed without sudo
```

If that reports `permission denied while trying to connect to the Docker
daemon socket`, the group has not taken effect yet — log out fully rather
than working around it. `newgrp docker` fixes the current shell only.

**Know what the `docker` group is.** It is not a convenience that saves you
typing `sudo` — the daemon runs as root and carries out whatever is asked of
it over its socket, so membership is equivalent to passwordless, unlogged
root on this host (`docker run -v /:/host ...` is a root shell). That is a
property of Docker, not of ThreatLens, but it is worth deciding deliberately
on a machine you intend to open malware on.

If you would rather not hold it, skip the `usermod` line and prefix every
command below with `sudo`. Two things to know before you do.

**Install the Compose plugin system-wide, not into your home directory.** The
next section installs it under `~/.docker/cli-plugins`, which `sudo` cannot
see — it runs as root with `HOME=/root` — so `sudo docker compose` fails with
`'compose' is not a docker command`. Use these instead of that section's
commands, and note the `mkdir`: neither directory exists by default and
`curl` will not create them.

```bash
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL https://github.com/docker/compose/releases/download/v2.40.3/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
```

**And be clear what `sudo` buys.** It removes the standing, ambient grant and
restores a password prompt and an audit record, but it does **not** reduce
what the container can do — the daemon still runs as root either way, so
escape containment is unchanged.

Do not try to narrow this with a `sudoers` rule. Docker's flags are
expressive enough that any rule permitting `docker run` permits
`-v /:/host --privileged`, and a trailing wildcard absorbs both, so a rule
that reads as a restriction grants full root.

Ignore a `docker-compose` 1.29.x package if your distribution installs one.
That is the end-of-life Python v1 implementation and is not what this project
uses.

### Compose v2

Unlike the engine, the Compose plugin needs **no root** — Docker reads CLI
plugins from your own home directory:

```bash
mkdir -p ~/.docker/cli-plugins
curl -SL https://github.com/docker/compose/releases/download/v2.40.3/docker-compose-linux-x86_64 \
  -o ~/.docker/cli-plugins/docker-compose
chmod +x ~/.docker/cli-plugins/docker-compose
docker compose version          # must be the plugin, not docker-compose 1.x
```

Any `docker compose` plugin at v2 or newer is fine; the version pinned above
is simply the one this was verified against, not a floor to match exactly.
What is being excluded is the end-of-life `docker-compose` v1 Python script.
Nothing in ThreatLens reads a Compose version at runtime, so if
`docker compose version` prints anything at all and `build` works, you are
fine.

Verified on Ubuntu 24.04.5 with `docker.io` 29.1.3, `docker-buildx` 0.30.1 and
the Compose plugin at v2.40.3.

## Run it in Docker

This is the supported path. The image carries capa, FLOSS, YARA, `unar` and
every Python pin, so nothing is installed on your host.

```bash
# 1. Make sure the mount points exist. Both are tracked in the repo, so a
#    fresh clone has them — but if either is missing when you run Compose,
#    Docker creates it root-owned and you need sudo to clean up.
mkdir -p samples reports

# 2. Tell the container who you are, or reports arrive owned by uid 1000.
cp .env.example .env
printf 'TL_UID=%s\nTL_GID=%s\n' "$(id -u)" "$(id -g)" >> .env

# 3. Build.
docker compose build

# 4. Fetch the YARA rules. Do this before the first scan — without them
#    yara_scanner contributes nothing and scores read low.
docker compose run --rm threatlens rules update

# 5. Scan, with no network. Paths are relative to ./samples (read-only).
cp /path/to/suspicious.exe samples/
docker compose run --rm offline scan suspicious.exe
```

Reports land in `./reports`. Rules live in a named volume and survive the
container exiting.

### Two services, and which one to use

| service | network | use it for |
|---|---|---|
| `offline` | **none** | scanning samples — the normal case |
| `threatlens` | egress | `rules update`, and a scan where you want `virustotal` |

**Prefer `offline`.** Analysing a document is not a purely passive act:
`pdf_analysis` **executes** the JavaScript inside a PDF, and the Excel-4.0
pass interprets macro formulas (see "What runs your sample's code" below).
Holding an open route to the internet while doing that is a combination worth
having to ask for by name, which is why it is a separate service rather than
a flag.

Both services drop all Linux capabilities except the three the privilege drop
needs (`SETUID`, `SETGID`, `CHOWN`), set `no-new-privileges`, cap the process
count, and mount `/tmp` as `noexec` tmpfs. Your `samples/` is mounted
read-only, so nothing a sample does can modify your corpus.

`rules update` and the `virustotal` module are the only things that reach the
network. Sample bytes never leave the machine either way — VirusTotal is
queried by hash, not by upload.

Prefer the `offline` service above. If you want the equivalent as a plain
`docker run` — for instance to add your own flags — it is:

```bash
# Compose names the volume after the project, which defaults to this
# directory lowercased. If you have set COMPOSE_PROJECT_NAME, use that
# instead — `docker volume ls | grep threatlens-rules` shows the real name.
RULES="$(echo "${PWD##*/}" | tr '[:upper:]' '[:lower:]')_threatlens-rules"

docker run --rm --network none \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
  --security-opt no-new-privileges:true --pids-limit 512 \
  -v "$PWD/samples:/data:ro" -v "$PWD/reports:/reports" \
  -v "$RULES:/app/rules/yara" \
  --tmpfs /tmp:size=2g,noexec \
  -e TL_UID=$(id -u) -e TL_GID=$(id -g) \
  -w /data threatlens:0.6.1 scan suspicious.exe
```

`noexec` is spelled out even though Docker already applies it by default —
measured on this machine, `--tmpfs /tmp:size=2g` mounts
`rw,nosuid,nodev,noexec` and an attempt to execute from `/tmp` is refused.
Extracted malware lands there, so the guarantee is stated rather than
inherited from a default that a different daemon version could change.

Do not simplify that to `--cap-drop ALL`. The entrypoint starts as root and
drops to `TL_UID` with `gosu`, which needs `SETUID` and `SETGID`; without
them the container fails to start with
`error: failed switching to "1000:1000": operation not permitted`.

## What runs your sample's code

ThreatLens is a static analysis tool, with two deliberate exceptions. Both
are on by default because both recover evidence that reading the file cannot,
and you should know about them:

**PDF JavaScript is executed.** `peepdf` hands every script it finds to a V8
engine and runs it, with `eval` hooked so that each stage generated at
runtime is recovered and re-run. That is how a payload assembled from
fragments at runtime is seen at all. The report tells you what happened, in
`pdf_analysis.data.javascript_engine`:

| field | meaning |
|---|---|
| `available` | a JavaScript engine was importable (`None` if we never found out) |
| `enabled` | execution was armed — i.e. `pdf_javascript_execution` |
| `executed` | it **actually ran** this file's script: armed, importable, and the file carried script. `False` for a PDF with no JavaScript; `None` if the parse died before we could tell |
| `peepdf_version` | which peepdf produced the result |

`enabled` and `executed` are separate on purpose. A clean PDF with no script
reports `enabled: true, executed: false` — the engine was armed and ran
nothing, which is not the same as having executed something.

Script errors appear separately as `js_errors`, so "the script threw on its
first line" is distinguishable from "the file contained no script". They are
not scored — an error means the engine ran, not that the file is malicious.

To turn it off, in `config.yaml`:

```yaml
pdf_javascript_execution: false      # default: true
```

That costs real detection: a PDF whose payload is assembled at runtime will
report only the loader. It is off-by-choice, not a recommendation.

**Write it unquoted.** `false` is a YAML boolean; `"false"` is a string, and
a non-empty string is true in Python — so the quoted form used to arm the
very thing it looks like it disables. Since 0.5.20 a value that is not a
real boolean is refused with a warning naming it, and this setting
specifically falls back to **off** rather than to its default, because a
value we cannot read is not a reason to run a sample's code. The unquoted
spellings YAML already understands — `false`, `no`, `off` — all work.

**Excel 4.0 macros are interpreted.** `doc_analysis` evaluates XLM formula
graphs to resolve obfuscated macros. It calls no Windows APIs — it is a
formula evaluator, so the risk is a hostile workbook hanging the parser
rather than executing anything, which is why that pass carries its own
timeouts.

Neither needs network access, which is the argument for the `offline`
service.

### About `TL_UID`

If you leave the 1000 default and your own id is different, nothing crashes.
The entrypoint starts as root, `chown`s the two mounts to `TL_UID`, then drops
privileges with `gosu` before any sample is opened. But the `chown` **takes
ownership of your `reports/` directory**, and you will then need `sudo` to
delete your own reports. Set the values.

## Run it on the host

The libmagic package was renamed in the 64-bit time_t transition. Ubuntu
24.04+ and Debian trixie+ call it `libmagic1t64`; earlier releases call it
`libmagic1`, and asking for the wrong one fails with `Unable to locate
package`. The block below uses the newer name — substitute `libmagic1` if your
release predates those.

```bash
sudo apt-get install libmagic1t64 git
python3 -m venv .venv
.venv/bin/pip install -e '.[analysis]'
.venv/bin/threatlens rules update
.venv/bin/threatlens scan suspicious.exe
```

`main.py` is a thin shim over the same package, so `python3 main.py scan f.exe`
works without installing anything. `rules update` shells out to `git`, so that
has to be on `PATH`; nothing else does.

### capa and FLOSS

Neither ships in the repository — they are 45 MB and 39 MB, and neither is
tracked. **A fresh clone has neither**, and the two modules that want
them degrade differently:

- `capa_analysis` **skips**, with `capa binary not found` in the report.
- `string_analysis` still **succeeds**, falling back to raw ASCII extraction.
  You keep strings; you lose FLOSS's stack, tight and decoded ones.

Nothing crashes either way. Measured across six real PE samples, having both
tools is worth between **0 and 9 points**, and **the risk band did not move on
any of them** — 100 against 91 on `Amadey.exe`, 100 against 93 on
`RedLineStealer.exe`, and no difference at all on the other four.

> **The scores quoted just above predate the scoring fixes of
> 2026-10-28 and need re-measuring.** Several executable indicators were corrected in that
> round — a digital signature was being counted as an encrypted payload,
> a reproducible build as a forged timestamp, a Rich header as tampered —
> so the absolute scores have moved. The *conclusion* that the two tools
> are worth little on these samples has not been retested either way.
> See `docs/measurement_m2_post_fix.md`.

The reason those four tie is worth knowing, because it is not that capa found
nothing — it is that capa was cut off. Measured across 12 real PEs, capa takes
**11 to 734 seconds**, and the old defaults (120s, or 180s under `-p deep`)
covered only 5 and 6 of them.

The budgets are now **240s by default and 900s under `-p deep`**, set from that
distribution: 240 covers the common case in under four minutes, 900 clears the
slowest sample measured. A `triage` sweep is unaffected either way, because it
defaults to `-p quick`, which does not run capa at all.

**If you already have your own `config.yaml`, it keeps whatever
`capa_timeout_seconds` you set** — it is read ahead of the built-in defaults,
so update it by hand to pick this up.

The Docker image has both tools already; on the host, pick one of these.

**Fetch the binaries** — matches the built-in defaults, so no config edit and
no separate rule set. Their rules are embedded:

```bash
curl -sSL -o /tmp/capa.zip \
  https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux.zip
curl -sSL -o /tmp/floss.zip \
  https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip
unzip -j -d bin /tmp/capa.zip capa && unzip -j -d bin /tmp/floss.zip floss
chmod +x bin/capa bin/floss
```

**Or install the PyPI packages** — the same tools. ("flare-" is Mandiant's team
name, not a fork.) They start faster, because the `./bin` copies are
PyInstaller bundles that unpack themselves on every run: 3.0s against 5.3s end
to end, measured on one small sample during the containerisation work. Do not
read that as a 40% saving on a long analysis — the samples above take capa
between 137 and 723 seconds, and the bundle's unpacking is a fixed cost, not a
proportional one.

The wheels do not carry capa's rules or FLIRT signatures, and capa exits 10
without them, so both must be fetched at the matching tag and pointed at
explicitly:

```bash
.venv/bin/pip install -e '.[tools]'

git clone --depth 1 -b v9.4.0 https://github.com/mandiant/capa-rules.git ~/capa-rules
git clone --depth 1 -b v9.4.0 --filter=blob:none --sparse \
  https://github.com/mandiant/capa.git /tmp/capa-src
git -C /tmp/capa-src sparse-checkout set sigs
mkdir -p ~/capa-sigs && cp /tmp/capa-src/sigs/*.sig ~/capa-sigs/
```

then in `config.yaml` — absolute paths, `~` is not expanded:

```yaml
capa_binary: "capa"          # bare name: resolved on PATH
floss_binary: "floss"
capa_rules_dir: "/home/you/capa-rules"
capa_signatures_dir: "/home/you/capa-sigs"
```

A value containing a `/` is used as a path; a bare name is looked up with
`shutil.which` and never from the working directory.

### Optional extras

Two more, neither installed by default and both for good reasons:

- `.[fast-hashing]` — the C `ssdeep` binding. Up to 350x faster than the
  pure-Python fallback on large files, and lifts the 8 MB fuzzy-hash ceiling.
  Needs `libfuzzy-dev`, a compiler, and `--no-build-isolation`:
  ```bash
  sudo apt-get install libfuzzy-dev
  .venv/bin/pip install --no-build-isolation '.[fast-hashing]'
  ```
- `.[dynamic]` — the Speakeasy emulator. Off by default (`dynamic_provider:
  none`).

If you want the host to agree with the container exactly, build the virtualenv
from `requirements.lock` rather than from `pyproject.toml`. A host venv created
with `--system-site-packages` can borrow an older `peepdf` from `~/.local` and
score four known PDF samples lower than the image does.

## Commands

```
threatlens scan     FILE          Analyse one file
threatlens triage   DIRECTORY     Analyse every file in a directory
threatlens compare  FILE1 FILE2   Two files, scores side by side
threatlens rules    update        Clone, pull and validate the YARA sources
```

`-h` works on every one of them.

Cost and display are separate axes, and they never interfere:

| Axis | Flag | Decides |
|---|---|---|
| Cost | `-p quick\|standard\|deep` | which modules run, with what timeouts |
| Display | `-v`, `-vv` | how much of the result prints |

| Profile | Runs | Typical time |
|---|---|---|
| `quick` | `file_intake` + `pe_analysis` + `lnk_analysis` | <1s |
| `standard` | all enabled modules | 5–120s |
| `deep` | as `standard`, capa timeout **900s**, FLOSS emulation on | 30s–15min |

Output is `text` (default), `json`, `jsonl` or `html`. stdout carries results
only; progress, warnings and log lines go to stderr, so this is reliable:

```bash
threatlens scan f.exe -f json | jq .scoring.total_score
```

Exit codes: `0` clean or no threshold, `1` verdict at or above `--fail-on`,
`2` usage error, `3` runtime error. A runtime error outranks a threat verdict,
because a partial sweep cannot assert a complete answer.

```bash
threatlens scan artefact.exe --fail-on high || echo "blocked: $?"
```

## The VirusTotal key

Optional. Every other module works without it, and an absent lookup scores 0,
so it moves no verdict.

There is deliberately **no `--vt-key` flag** — an argument is readable through
`ps` by every user on the host and lands in your shell history. Use the
environment variable, or a config file outside the repository:

```bash
THREATLENS_VT_KEY=<key> threatlens scan sample.exe

mkdir -p ~/.config/threatlens
printf 'virustotal_api_key: "<key>"\n' > ~/.config/threatlens/config.yaml
chmod 600 ~/.config/threatlens/config.yaml
```

In Docker, put it in `.env`, which is not tracked, and Compose passes it
through. Never
bake a key into the image: layers are permanent and `docker history` exposes
them even after a later layer deletes the file.

## Configuration

First hit wins: `--config PATH`, then `$THREATLENS_CONFIG`, then `./config.yaml`,
then `~/.config/threatlens/config.yaml`, then built-in defaults. Pointing
`--config` at a file that does not exist is a usage error rather than a silent
fallback.

The repository ships no ignore rules, so a `config.yaml` you create in a clone
is visible to `git` and a `git add -A` would stage it. **Prefer
`~/.config/threatlens/config.yaml`**, outside the repository, for anything
holding a key.

`config.yaml` is not tracked — it is where a VirusTotal key would sit — so a
fresh clone has none and runs on `DEFAULTS` in `core/config_loader.py`, which
is the authoritative list of every key. To write your own, copy
`config.docker.yaml`: it is complete and commented. **Its paths are the
container's**, so for host use change them back to the repo-relative ones
(`./rules/yara`, `./bin/capa`, `./bin/floss`, `./reports`).

**Inside the container your host `config.yaml` is not read.** The image sets
`THREATLENS_CONFIG=/app/config.docker.yaml`, and that beats `./config.yaml` in
the search order. To change a setting there, edit a *separate* copy that keeps
the container's absolute paths, and mount it over the baked one:

```bash
cp config.docker.yaml my-container-config.yaml   # edit timeouts, modules, caps
docker compose run --rm \
  -v "$PWD/my-container-config.yaml:/app/config.docker.yaml:ro" \
  threatlens scan suspicious.exe
```

Do not mount a host `config.yaml` here. Its paths are repo-relative, and the
container resolves them against `/data` — your samples mount — so it would find
no rules and no binaries and still print a verdict.

The VirusTotal key needs none of this — it arrives through the environment.

The settings you are most likely to touch:

| Setting | Default | Effect |
|---|---|---|
| `virustotal_api_key` | `""` | Overridden by `THREATLENS_VT_KEY` |
| `yara_rules_dir` | `./rules/yara` | Where `rules update` writes |
| `capa_binary` / `floss_binary` | `./bin/capa`, `./bin/floss` | A `/` makes it a path, a bare name resolves on `PATH` |
| `capa_rules_dir` / `capa_signatures_dir` | unset | Required only for the PyPI capa |
| `output_dir` | `./reports` | Where HTML reports land |
| `log_level` | `WARNING` | `-v`/`-vv` override it |
| `module_timeout_seconds` | `60` | **Not enforced by the orchestrator yet** — see the limitations below |
| `capa_timeout_seconds` | `240` | `-p deep` raises it to **900**. Measured: capa takes 11–734s on real PEs, so 240 covers the common case and 900 covers all of it |
| `floss_timeout_seconds` | `300` | Emulation takes 127–271s on real samples, so the generic 60 would time out every run |
| `floss_emulation` | `false` | `-p deep` turns it on. Costs ~26x |
| `enabled_modules` | all 13 | What `standard` and `deep` run |
| `dynamic_provider` | `none` | Config-only; there is no CLI flag |
| `speakeasy_timeout_seconds` | `60` | Emulation budget. The hard kill is this **+30**, derived and not configurable |
| `speakeasy_max_api_count` | `20000` | Emulated API calls. Both budgets are per entry point |
| `rule_sources` | signature-base | Repos `rules update` clones |

Per-format caps — archive recursion and bomb thresholds, OneNote blob limits,
the `.lnk` size ceiling — are grouped and commented in `config.docker.yaml`.

## Limitations, stated plainly

- **Static by default; no sandbox either way.** With `dynamic_provider:
  none` — the default — nothing from the sample is run as a program. Setting
  it to `speakeasy` adds **emulation**, not a sandbox: the sample's
  instructions are interpreted in software, on Linux, with synthetic Windows
  APIs and no real network. It applies to **native Windows PEs only** —
  .NET assemblies and raw shellcode are stated exclusions.
- **Emulation yields far less than it sounds like it should.** Measured on
  all 21 native PE candidates in the project corpus: **none** executed
  dynamically generated code, so no unpacked payload was recoverable, and
  runs ended after roughly 1.5s against a 20s budget — stopping before the
  unpacking routines completed rather than running out of time. What it does
  recover is runtime-resolved imports, in 13 of 21 samples, which partly
  repairs a known blind spot in static import-table analysis against packed
  binaries. **A packer that only unpacks at runtime still limits what any
  module can see.**
- **An emulation that records nothing is reported as a failure, never as
  clean.** Three states — `observed`, `failed`, `not attempted` — and only
  `observed` can contribute to the score.
- **x86-64 Linux.** See above.
- **YARA coverage is whatever `rules update` fetched.** Only `signature-base`
  is enabled by default.
- **Scores are evidence, not a verdict.** The bands are calibrated against a
  311-sample corpus; they rank suspicion, they do not prove intent.
- **`module_timeout_seconds` is not enforced by the orchestrator.** It is
  validated and then not read — `core/pipeline.py` says so at the call site.
  Timeouts exist only inside the modules that shell out (capa, FLOSS, the 30s
  XLM cap), so a slow pure-Python parser runs to completion whatever the
  setting says. Do not treat it as a hang guard.
- `pdf_analysis` changes the process working directory while it parses. Safe
  while modules run in sequence, which they do today.

## Tests

**1331 tests collected**, and that is the number to check — it is the one the
environment cannot change. How many of them *run* depends on what is present:

| where | passed | skipped |
|---|---|---|
| host, malware corpus present | 1330 | 1 |
| host, no corpus | 1307 | 24 |
| inside the image, no corpus | — | — |

The image row is blank on purpose: the image currently lags the source
tree, so any figure printed here would describe an older build. It is
re-measured at the next image build.

23 of the skips are the tests that scan real samples. The 24th needs
`pcodedmp` on `PATH`, which the image has and a bare host may not — that is
the whole difference between the last two rows. All three exit 0.

`pytest` is not part of `.[analysis]`, so install it first.

```bash
# Host
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest

# Container. Both overrides are needed: -w /app because compose sets
# working_dir to /data, and THREATLENS_CORPUS because the live-malware tests
# default to a host path and would otherwise skip silently.
docker compose run --rm -w /app -e THREATLENS_CORPUS=/data \
  threatlens --exec python -m pytest tests/
```

`--exec` goes *through* the entrypoint, so the tests run as the same
unprivileged user a real scan does. `--entrypoint pytest` would bypass the
`gosu` drop, run them as root, and hide every permission failure a real user
would hit.

Corpus scans that need the network or a long capa run are deselected by
default; `-m corpus_slow` runs those on their own.

**Without the malware corpus the tests that scan real samples skip rather
than fail**, and the exit status is still 0 — so read the collected count and
the skip count, not just the exit status. A skipped test looks exactly like a
passing one in the tally, and a run where the corpus-gated tests silently
vanished is indistinguishable from a healthy one by exit code alone.
To supply the corpus so those 23 tests run instead of skipping, point
`THREATLENS_CORPUS` at the directory — `tests/_corpus.py` resolves the path in
one place and that variable overrides it:

```bash
THREATLENS_CORPUS=/path/to/corpus .venv/bin/pytest
```

`pyproject.toml` already passes `-q`, so adding your own makes it `-qq` and
pytest prints no summary line at all — which is precisely the count you need.

## Where things are

| | |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | version history, and the roadmap to 1.0.0 |
| `config.docker.yaml` | a complete config with every entry commented |
| `core/config_loader.py` | `DEFAULTS` — the values used when no config is found |
| `-h` | on the tool and on each of its four commands |

The user guide, the scoring reference and the build notes are not published
yet. They are working material for a project still in Phase 4, and they go out
with the version they describe.
