#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="${NET:-$(docker network ls --format '{{.Name}}' | grep -E 'vlf|VLF|proto' | head -n1 || true)}"
GATEWAY_HOST="${GATEWAY_HOST:-gateway}"
GATEWAY_PORT_UDP="${GATEWAY_PORT_UDP:-443}"
GATEWAY_PORT_TCP="${GATEWAY_PORT_TCP:-443}"
SESSION_ADDR="${SESSION_ADDR:-${GATEWAY_HOST}:${GATEWAY_PORT_UDP}}"
RELAY_BASE="${RELAY_BASE:-http://${GATEWAY_HOST}:8080}"
VLF_CLIENT_ID="${VLF_CLIENT_ID:-${VLF_CLIENT:-smoke-client}}"
VLF_SECRET="${VLF_SECRET:-smoke-secret}"
VLF_PROTO_ID="${VLF_PROTO_ID:-vlf-runtime/0.1}"
DST_TCP_HOST="${DST_TCP_HOST:-tcp-echo}"
DST_TCP_PORT="${DST_TCP_PORT:-9000}"
DST_UDP_HOST="${DST_UDP_HOST:-udp-echo}"
DST_UDP_PORT="${DST_UDP_PORT:-9001}"
MAX_DGRAM_PAYLOAD="${MAX_DGRAM_PAYLOAD:-1200}"
VLF_PIN_SPKI="${VLF_PIN_SPKI:-}"

if [[ -z "$NET" ]]; then
  echo "session_smoke.sh: could not detect docker network. Set NET=<network>."
  exit 1
fi

docker run --rm --network "$NET" \
  -e GATEWAY_HOST \
  -e GATEWAY_PORT_UDP \
  -e GATEWAY_PORT_TCP \
  -e SESSION_ADDR \
  -e RELAY_BASE \
  -e VLF_CLIENT_ID \
  -e VLF_SECRET \
  -e VLF_PROTO_ID \
  -e DST_TCP_HOST \
  -e DST_TCP_PORT \
  -e DST_UDP_HOST \
  -e DST_UDP_PORT \
  -e MAX_DGRAM_PAYLOAD \
  -e VLF_PIN_SPKI \
  -v "$ROOT":/src -w /src golang:1.24-alpine sh -c '
  apk add --no-cache git ca-certificates &&
  go run ./scripts/session_smoke.go
'
