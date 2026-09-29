#!/bin/sh
# Fix mount ownership, then drop privileges. Runs as root, and only for as
# long as that takes.
#
# Why root at all, given that analysing hostile input as root is
# indefensible: Docker creates a missing bind-mount source on the host as
# root:root, and a named volume inherits ownership from the image directory
# it was seeded from. Neither can be fixed from inside an already-unprivileged
# process, and a static `USER` in the Dockerfile cannot match an arbitrary
# host UID. So ownership is corrected here and then dropped, before anything
# has looked at a sample.
set -e

TL_UID="${TL_UID:-1000}"
TL_GID="${TL_GID:-1000}"

# -R on the named rules volume only. /reports is a bind mount onto the host,
# and recursing it would rewrite ownership of every report the analyst has
# ever produced — silently taking their own files off them whenever TL_UID
# falls back to the default and their real UID is something else. It also
# costs I/O on every start as that directory grows. Chowning the directory
# alone is enough: files created inside it are owned by the creating user.
chown -R "$TL_UID:$TL_GID" /app/rules/yara 2>/dev/null || true
chown    "$TL_UID:$TL_GID" /reports        2>/dev/null || true

# `--exec` runs an arbitrary command through the privilege drop. It exists so
# the test suite can be run as the same unprivileged user a real scan uses:
# overriding the entrypoint instead would bypass gosu and run the tests as
# root, hiding exactly the permission failures a real user would hit.
if [ "$1" = "--exec" ]; then
    shift
    exec gosu "$TL_UID:$TL_GID" "$@"
fi

exec gosu "$TL_UID:$TL_GID" python /app/main.py "$@"
