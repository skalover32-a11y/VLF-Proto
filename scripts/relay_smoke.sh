#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="${NET:-$(docker network ls --format '{{.Name}}' | grep -E 'vlf|VLF|proto' | head -n1 || true)}"
RELAY_BASE="${RELAY_BASE:-http://gateway:8080}"
RELAY_DIAL_HOST="${RELAY_DIAL_HOST:-tcp-echo}"
RELAY_DIAL_PORT="${RELAY_DIAL_PORT:-9000}"
VLF_CLIENT="${VLF_CLIENT:-${VLF_CLIENT_ID:-smoke-client}}"
VLF_CLIENT_ID="${VLF_CLIENT_ID:-$VLF_CLIENT}"
VLF_SECRET="${VLF_SECRET:-smoke-secret}"

if [[ -z "$NET" ]]; then
  echo "relay_smoke.sh: could not detect docker network. Set NET=<network>."
  exit 1
fi

docker run --rm --network "$NET" \
  -e RELAY_BASE \
  -e RELAY_DIAL_HOST \
  -e RELAY_DIAL_PORT \
  -e VLF_CLIENT \
  -e VLF_CLIENT_ID \
  -e VLF_SECRET \
  -v "$ROOT":/src -w /src golang:1.24-alpine sh -c '
  apk add --no-cache git ca-certificates &&
  go run ./scripts/relay_smoke.go
'
