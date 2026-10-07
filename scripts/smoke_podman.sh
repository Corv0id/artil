#!/usr/bin/env bash
#
# smoke_podman.sh — verify the isolation primitive artil depends on.
#
#    1. Start the Podman machine (idempotent: a no-op if already up).
#    2. Ensure an image is available (cached afterwards; offline-safe).
#    3. Run a container with --network=none and prove it has NO network access
#       at all. It must fail to reach BOTH:
#           - 127.0.0.1 : the container's own loopback AND the host's exfil sink
#           - an external IP 1.1.1.1 : catches any "network but no loopback"
#                case, i.e. proves the container cannot reach ANY host.
#       If either probe SUCCEEDS, that is a HARD FAILURE -- the isolation
#       guarantee is broken. We invert the probes: isolation holds only if the
#       connection fails.
#
# Exit status: 0 when isolation holds, non-zero on any failure.
#
# IMAGE defaults to alpine:3, but if the Podman VM cannot reach the registry
# (offline), substitute any locally-cached alpine/busybox image that ships
# wget, e.g.  IMAGE=docker.io/library/redis:7-alpine ./smoke_podman.sh

set -euo pipefail

HOST_TARGET_HOST="${HOST_TARGET_HOST:-127.0.0.1}"
HOST_TARGET_PORT="${HOST_TARGET_PORT:-11434}"
EXTERNAL_TARGET_HOST="${EXTERNAL_TARGET_HOST:-1.1.1.1}"
EXTERNAL_TARGET_PORT="${EXTERNAL_TARGET_PORT:-80}"
IMAGE="${IMAGE:-alpine:3}"
export HOST_TARGET_HOST HOST_TARGET_PORT EXTERNAL_TARGET_HOST EXTERNAL_TARGET_PORT

log()  { printf '» %s\n' "$*"; }
ok()   { printf '  OK   %s\n' "$*"; }
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

# probe <host> <port> -> echoes "blocked" if the connection failed (good),
# "reached" if it connected (bad). Runs entirely inside --network=none.
# shellcheck disable=SC2029
probe() {
    podman run --rm --network=none \
        -e PROBE_HOST="$1" -e PROBE_PORT="$2" \
        "${IMAGE}" sh -c '
        if wget -q -T 3 -O /dev/null "http://${PROBE_HOST}:${PROBE_PORT}" \
            >/dev/null 2>&1; then
            echo "reached"
        else
            echo "blocked"
        fi
    '
}

log "Probing ${HOST_TARGET_HOST}:${HOST_TARGET_PORT} (own loopback / host exfil sink)..."
HOST_PROBE="$(probe "${HOST_TARGET_HOST}" "${HOST_TARGET_PORT}")"
if [ "${HOST_PROBE}" = "blocked" ]; then
  ok "container could NOT reach ${HOST_TARGET_HOST}:${HOST_TARGET_PORT}"
else
  fail "container REACHED ${HOST_TARGET_HOST}:${HOST_TARGET_PORT} despite --network=none"
  exit 1
fi

log "Probing ${EXTERNAL_TARGET_HOST}:${EXTERNAL_TARGET_PORT} (external IP, 3s timeout)..."
EXT_PROBE="$(probe "${EXTERNAL_TARGET_HOST}" "${EXTERNAL_TARGET_PORT}")"
if [ "${EXT_PROBE}" = "blocked" ]; then
  ok "container could NOT reach ${EXTERNAL_TARGET_HOST} (no egress at all)"
  log "smoke_podman.sh: PASS"
  exit 0
fi

fail "container REACHED external ${EXTERNAL_TARGET_HOST}:${EXTERNAL_TARGET_PORT} despite --network=none"
fail "isolation guarantee broken -- do not run attacks yet"
exit 1
