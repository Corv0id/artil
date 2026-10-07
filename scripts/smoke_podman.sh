#!/usr/bin/env bash
#
# smoke_podman.sh — verify the isolation primitive artil depends on.
#
#   1. Start the Podman machine (idempotent: a no-op if already up).
#   2. Pull alpine once (cached afterwards).
#   3. Run an alpine container with --network=none and prove it has NO
#      network access at all: a connection to the host's localhost
#      (the classic exfil channel / exfil sink) must fail. If it could
#      connect, that is a HARD FAILURE -- the isolation guarantee is broken.
#
# Exit status: 0 when isolation holds, non-zero on any failure.
#
# IMAGE defaults to alpine:3, but if the Podman VM cannot reach the registry
# (offline), substitute any locally-cached alpine/busybox image that ships
# wget, e.g.  IMAGE=docker.io/library/redis:7-alpine ./smoke_podman.sh

set -euo pipefail

HOST_TARGET_HOST="${HOST_TARGET_HOST:-127.0.0.1}"
HOST_TARGET_PORT="${HOST_TARGET_PORT:-11434}"
IMAGE="${IMAGE:-alpine:3}"
export HOST_TARGET_HOST HOST_TARGET_PORT

log()  { printf '» %s\n' "$*"; }
ok()   { printf '  OK  %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*" >&2; }

command -v podman >/dev/null 2>&1 || { fail "podman not found on PATH"; exit 127; }

log "Starting Podman machine (idempotent)..."
if podman machine list --format json | grep -q '"Running": *true'; then
  ok "machine already running"
else
  podman machine start
  ok "machine started"
fi

log "Ensuring ${IMAGE} is available (cached afterwards)..."
if podman image exists "${IMAGE}"; then
  ok "image already present locally"
else
  podman pull "${IMAGE}" >/dev/null
  ok "image pulled"
fi

log "Running ${IMAGE} with --network=none and probing ${HOST_TARGET_HOST}:${HOST_TARGET_PORT}..."

# From inside the container: SUCCESS means the probe CONNECTED (bad).
# We invert it: isolation holds only if the connection fails.
ISOLATED="$(
  podman run --rm --network=none \
       -e HOST_TARGET_HOST -e HOST_TARGET_PORT \
       "${IMAGE}" sh -c '
    if wget -q -T 3 -O /dev/null \
         "http://${HOST_TARGET_HOST}:${HOST_TARGET_PORT}" >/dev/null 2>&1; then
        echo "reached"
    else
        echo "blocked"
    fi
  '
)"

if [ "${ISOLATED}" = "blocked" ]; then
  ok "container could NOT reach ${HOST_TARGET_HOST}:${HOST_TARGET_PORT} (isolation holds)"
  log "smoke_podman.sh: PASS"
  exit 0
fi

fail "container REACHED ${HOST_TARGET_HOST}:${HOST_TARGET_PORT} despite --network=none"
fail "isolation guarantee broken -- do not run attacks yet"
exit 1
