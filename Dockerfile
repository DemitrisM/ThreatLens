# ThreatLens — portable CLI malware analysis.
#
# Two stages. Stage 1 has a compiler and is thrown away; stage 2 ships.
#
# Base is Debian (trixie) and glibc, NOT Alpine: py-tlsh and ssdeep compile
# against glibc, and musl would also be unable to run the PyInstaller
# binaries this image deliberately replaces.
#
# x86-64 only, and that is a property of the project rather than of this
# file: peepdf-3 requires STPyV8, which publishes no arm64 wheel.

# The capa version and its data must move together. capa does not refuse a
# mismatched rule set — it just matches differently — so this ARG feeds the
# rules and signature checkouts, and it must equal the flare-capa pin in
# requirements.lock. tests/test_requirements_lock.py holds that pin and
# pyproject.toml in agreement; this is the third copy and the reason it is a
# single ARG.
ARG CAPA_VERSION=v9.4.0

# ---------------------------------------------------------------------------
# Stage 1 — builder. Compiles the two source-only packages, fetches capa data.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

# build-essential for py-tlsh (C++) and ssdeep (cffi); libfuzzy-dev for
# ssdeep's fuzzy.h; git for the capa checkouts.
#
# NOT python3-dev: the base image already carries
# /usr/local/include/python3.12/Python.h, and apt's python3-dev in trixie is
# for 3.13, so installing it would drag in a second interpreter and build
# extensions against the wrong headers.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        libfuzzy-dev \
        git \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Only the lockfile, so this layer caches independently of the source.
COPY requirements.lock ./

# Two wheel passes, because two packages in the lockfile want opposite
# things and a single command cannot satisfy both. Measured, not guessed —
# the first attempt used one command with isolation off and the build failed
# in 12 seconds:
#
#   ssdeep 3.4       needs isolation OFF **and** setuptools<81. Its setup.py
#                    imports pkg_resources, and modern setuptools no longer
#                    ships it — measured in this base image: 84.0.0 has no
#                    pkg_resources, `setuptools<81` resolves to 80.10.2 which
#                    does. With isolation off, providing that is this stage's
#                    job. (This is also a case the host could not have caught:
#                    the development venv was created with
#                    --system-site-packages and silently borrowed
#                    pkg_resources from the system, so ssdeep built there and
#                    failed here. The container found a real gap the host had
#                    been papering over.) It also imports `six` and `cffi` in
#                    its own __init__ during metadata generation, so both are
#                    installed first, pinned from the lockfile so this stage
#                    cannot drift from the versions that ship.
#   binary2strings   needs isolation ON. It ships only an sdist for cp312 and
#                    declares its build backend in pyproject.toml, so with
#                    isolation off "Preparing metadata" fails outright.
#
# So: ssdeep alone first, then everything else with isolation on and
# --find-links pointing at the wheel just built, which stops pip rebuilding
# it. Isolation-off is safe for that one package precisely because the
# lockfile is fully pinned.
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir "setuptools<81" wheel \
        "$(grep -i '^cffi==' requirements.lock)" \
        "$(grep -i '^six==' requirements.lock)" \
 && pip wheel --no-build-isolation --wheel-dir /wheels \
        "$(grep -i '^ssdeep==' requirements.lock)" \
 && pip wheel --wheel-dir /wheels --find-links /wheels -r requirements.lock

# capa's rule set. Pinned to the tag, never a branch.
ARG CAPA_VERSION
RUN git clone --quiet --depth 1 --branch "${CAPA_VERSION}" \
        https://github.com/mandiant/capa-rules.git /opt/capa-rules \
 && rm -rf /opt/capa-rules/.git

# capa's FLIRT signatures, which live in the main repo. A sparse checkout
# preserves the repository tree, so the .sig files land in <checkout>/sigs —
# they are copied out flat so capa_signatures_dir can point at one directory
# and not at a path that depends on how the checkout was done.
RUN git clone --quiet --depth 1 --branch "${CAPA_VERSION}" \
        --filter=blob:none --sparse \
        https://github.com/mandiant/capa.git /tmp/capa-src \
 && cd /tmp/capa-src \
 && git sparse-checkout set sigs \
 && mkdir -p /opt/capa-sigs \
 && cp /tmp/capa-src/sigs/*.sig /opt/capa-sigs/ \
 && rm -rf /tmp/capa-src

# ---------------------------------------------------------------------------
# Stage 2 — runtime. No compiler.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

# Runtime libraries and the external processes the modules shell out to.
#
#   libmagic1t64 + libmagic-mgc  file typing. NOT "libmagic1" — trixie
#                                renamed it in the 64-bit time_t transition,
#                                and libmagic-mgc is the signature database
#                                without which python-magic is useless.
#   libfuzzy2                    ssdeep's runtime half.
#   cabextract                   archive_analysis shells out to it.
#   unar                         RAR extraction. Chosen over unrar, which is
#                                non-free and simply absent from this base;
#                                rarfile supports unar natively. The RAR
#                                corpus is verified against it.
#   git                          rule_updater shells out to it.
#   gosu                         the privilege drop in entrypoint.sh.
#
# pcodedmp needs no apt package: it is a console script from the lockfile,
# already on PATH, which is all doc_analysis's subprocess call needs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libmagic1t64 \
        libmagic-mgc \
        libfuzzy2 \
        cabextract \
        unar \
        git \
        gosu \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Dependencies only — ThreatLens itself is never installed as a package. The
# source is copied to /app and run from there, so /app leads sys.path and an
# installed copy would be shadowed dead weight that could silently go stale.
COPY --from=builder /wheels /wheels
COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
        -r /tmp/requirements.lock \
 && rm -rf /wheels /tmp/requirements.lock

COPY --from=builder /opt/capa-rules /opt/capa-rules
COPY --from=builder /opt/capa-sigs  /opt/capa-sigs

WORKDIR /app
COPY . /app

# To the root, not /app: `COPY . /app` already put a copy at
# /app/entrypoint.sh, and ENTRYPOINT ["/entrypoint.sh"] would fail with
# "executable file not found". The root copy also survives someone
# bind-mounting over /app while debugging.
COPY entrypoint.sh /entrypoint.sh

# No `USER analyst` here, deliberately. entrypoint.sh must start as root to
# correct the ownership of mounts Docker created as root, then drop
# privileges with gosu. The two mechanisms are mutually exclusive: with USER
# set, the chown would fail with EPERM.
RUN chmod +x /entrypoint.sh \
 && useradd --create-home --uid 1000 analyst \
 && mkdir -p /app/rules/yara /reports \
 && chown -R analyst:analyst /app/rules/yara /reports

ENV THREATLENS_CONFIG=/app/config.docker.yaml \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["/entrypoint.sh"]
