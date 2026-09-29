# ThreatLens

Static malware triage for the command line, with transparent confidence
scoring. Every point in a score is attributable: the report says which module
awarded it and why, so a verdict can be argued with rather than just believed.

Version 0.5.15. MIT licensed.

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

Analysis is static. `file_intake` always runs; everything else is chosen by the
profile and the file type. Nothing is executed.

## Requirements

- **x86-64 only.** `peepdf-3` requires STPyV8, which publishes no arm64 wheel.
  This is a property of the dependency, not of the container.
- Either **Docker** with Compose v2, or **Python 3.10+** on Linux.

Compose v2 installs to `~/.docker/cli-plugins/` and needs **no root**:

```bash
mkdir -p ~/.docker/cli-plugins
curl -SL https://github.com/docker/compose/releases/download/v2.40.3/docker-compose-linux-x86_64 \
  -o ~/.docker/cli-plugins/docker-compose
chmod +x ~/.docker/cli-plugins/docker-compose
docker compose version
```

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

# 5. Scan. Paths are relative to ./samples, which is mounted read-only.
cp /path/to/suspicious.exe samples/
docker compose run --rm threatlens scan suspicious.exe
```

Reports land in `./reports`. Rules live in a named volume and survive the
container exiting.

`rules update` and the `virustotal` module are the only things that reach the
network. Sample bytes never leave the machine either way — VirusTotal is
queried by hash, not by upload.

A scan itself needs no network at all, and can be run with none. `docker
compose run` has no `--network` flag, so this one is a plain `docker run`:

```bash
# Compose names the volume after the project, which defaults to this
# directory lowercased. If you have set COMPOSE_PROJECT_NAME, use that
# instead — `docker volume ls | grep threatlens-rules` shows the real name.
RULES="$(echo "${PWD##*/}" | tr '[:upper:]' '[:lower:]')_threatlens-rules"

docker run --rm --network none \
  -v "$PWD/samples:/data:ro" -v "$PWD/reports:/reports" \
  -v "$RULES:/app/rules/yara" \
  --tmpfs /tmp:size=2g \
  -e TL_UID=$(id -u) -e TL_GID=$(id -g) \
  -w /data threatlens:0.5.15 scan suspicious.exe
```

### About `TL_UID`

If you leave the 1000 default and your own id is different, nothing crashes.
The entrypoint starts as root, `chown`s the two mounts to `TL_UID`, then drops
privileges with `gosu` before any sample is opened. But the `chown` **takes
ownership of your `reports/` directory**, and you will then need `sudo` to
delete your own reports. Set the values.

## Run it on the host

```bash
sudo apt-get install libmagic1t64 git    # libmagic1 on releases before trixie
python3 -m venv .venv
.venv/bin/pip install -e '.[analysis]'
.venv/bin/threatlens rules update
.venv/bin/threatlens scan suspicious.exe
```

`main.py` is a thin shim over the same package, so `python3 main.py scan f.exe`
works without installing anything. `rules update` shells out to `git`, so that
has to be on `PATH`; nothing else does.

### capa and FLOSS

Neither ships in the repository — they are 45 MB and 39 MB, and `.gitignore`
excludes them. **A fresh clone has neither**, and the two modules that want
them degrade differently:

- `capa_analysis` **skips**, with `capa binary not found` in the report.
- `string_analysis` still **succeeds**, falling back to raw ASCII extraction.
  You keep strings; you lose FLOSS's stack, tight and decoded ones.

Nothing crashes either way. Measured on one corpus sample, the difference is
100/CRITICAL with both tools against 93/CRITICAL without — the band held, the
evidence behind it did not. The Docker image has both already; on the host,
pick one of these.

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

**Or install the PyPI packages** — the same tools, and capa runs about 40%
faster. But the wheels do not carry capa's rules or FLIRT signatures, and capa
exits 10 without them, so both must be fetched at the matching tag and pointed
at explicitly:

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
| `deep` | as `standard`, capa timeout 180s, FLOSS emulation on | 30s–5min |

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

In Docker, put it in `.env` (gitignored) and Compose passes it through. Never
bake a key into the image: layers are permanent and `docker history` exposes
them even after a later layer deletes the file.

## Configuration

First hit wins: `--config PATH`, then `$THREATLENS_CONFIG`, then `./config.yaml`,
then `~/.config/threatlens/config.yaml`, then built-in defaults. Pointing
`--config` at a file that does not exist is a usage error rather than a silent
fallback.

`config.yaml` is gitignored — it is where a VirusTotal key would sit — so a
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
| `capa_timeout_seconds` | `120` | `-p deep` raises it to 180 |
| `floss_timeout_seconds` | `300` | Emulation takes 127–271s on real samples, so the generic 60 would time out every run |
| `floss_emulation` | `false` | `-p deep` turns it on. Costs ~26x |
| `enabled_modules` | all 13 | What `standard` and `deep` run |
| `dynamic_provider` | `none` | Config-only; there is no CLI flag |
| `rule_sources` | signature-base | Repos `rules update` clones |

Per-format caps — archive recursion and bomb thresholds, OneNote blob limits,
the `.lnk` size ceiling — are grouped and commented in `config.docker.yaml`.

## Limitations, stated plainly

- **Static only.** No sandbox, no detonation. A packer that only unpacks at
  runtime will limit what any module can see.
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

1129 tests, green on the host and inside the image on a machine that has the
malware corpus. `pytest` is not part of `.[analysis]`, so install it first.

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

**On a machine without the malware corpus, the 23 tests that scan real samples
skip rather than fail** — 1106 passed, 23 skipped, and the exit status is still
0. A skipped test looks exactly like a passing one in the tally, so read the
skip count and not just the exit status. With the corpus present it is 1129
passed and nothing skipped. `tests/_corpus.py` resolves the path in one place
and `THREATLENS_CORPUS` overrides it:

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
