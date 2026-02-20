#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
GATEWAY_SERVICE="${GATEWAY_SERVICE:-gateway}"
HTTP_PORT="${HTTP_PORT:-8080}"
QUIC_PORT="${QUIC_PORT:-443}"

# If your compose has different service names, set env:
# GATEWAY_SERVICE=gateway HTTP_PORT=8080 QUIC_PORT=443 ./vlf_e2e.sh

log() { echo -e "\n==> $*\n"; }
die() { echo -e "\n[FAIL] $*\n"; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Command not found: $1"
}

log "Project dir: $PROJECT_DIR"
cd "$PROJECT_DIR"

need_cmd docker
need_cmd curl
need_cmd awk
need_cmd sed

# Docker compose v2 plugin is expected: `docker compose`
if ! docker compose version >/dev/null 2>&1; then
  die "'docker compose' not available. Install docker compose v2 plugin."
fi

log "Build & start services"
docker compose up -d --build

log "Services status"
docker compose ps

log "Wait for gateway HTTP to be ready on :${HTTP_PORT}"
for i in {1..40}; do
  if curl -fsS "http://127.0.0.1:${HTTP_PORT}/metrics" >/dev/null 2>&1; then
    echo "HTTP ready."
    break
  fi
  sleep 0.5
  if [[ "$i" == "40" ]]; then
    docker compose logs -n 200 "$GATEWAY_SERVICE" || true
    die "Gateway HTTP not ready on :${HTTP_PORT}"
  fi
done

log "Check /metrics contains expected lines (basic sanity)"
METRICS="$(curl -fsS "http://127.0.0.1:${HTTP_PORT}/metrics" | head -n 200)"
echo "$METRICS" | grep -E "active_(sessions|relay_conns)|bytes_(in|out)|auth_(failures|replay)|udp_pps" >/dev/null 2>&1 \
  || die "Metrics sanity check failed: expected basic metric names not found. Check /metrics output."

log "Check that UDP ${QUIC_PORT} is listening inside container (best-effort)"
# This is best-effort; container images may not include ss/netstat.
if docker compose exec -T "$GATEWAY_SERVICE" sh -lc 'command -v ss >/dev/null 2>&1'; then
  docker compose exec -T "$GATEWAY_SERVICE" sh -lc "ss -lunp | grep -E \":${QUIC_PORT}\\b\" || true"
else
  echo "No 'ss' in container; skipping UDP listen check."
fi

log "Run RELAY smoke test"
if [[ -f "./scripts/relay_smoke.sh" ]]; then
  chmod +x ./scripts/relay_smoke.sh || true
  ./scripts/relay_smoke.sh || {
    log "Relay smoke failed. Dump logs:"
    docker compose logs -n 250 "$GATEWAY_SERVICE" || true
    die "RELAY smoke test failed"
  }
else
  die "scripts/relay_smoke.sh not found"
fi

log "Run SESSION (QUIC) smoke test"
# Prefer script if present, else go run.
if [[ -f "./scripts/session_smoke.sh" ]]; then
  chmod +x ./scripts/session_smoke.sh || true
  ./scripts/session_smoke.sh || {
    log "Session smoke failed. Dump logs:"
    docker compose logs -n 250 "$GATEWAY_SERVICE" || true
    die "SESSION smoke test failed"
  }
elif [[ -f "./scripts/session_smoke.go" ]]; then
  need_cmd go
  go run ./scripts/session_smoke.go || {
    log "Session smoke failed. Dump logs:"
    docker compose logs -n 250 "$GATEWAY_SERVICE" || true
    die "SESSION smoke test failed"
  }
else
  die "No session smoke test found (scripts/session_smoke.sh or scripts/session_smoke.go)"
fi

log "All tests PASS ✅"

log "Optional: show short gateway logs tail"
docker compose logs -n 60 "$GATEWAY_SERVICE" || true
