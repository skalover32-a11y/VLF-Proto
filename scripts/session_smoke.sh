#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="${NET:-$(docker network ls --format '{{.Name}}' | grep -E 'vlf|VLF|proto' | head -n1)}"

docker run --rm --network "$NET" -v "$ROOT":/src -w /src golang:1.24-alpine sh -c '
  apk add --no-cache git ca-certificates &&
  SESSION_ADDR=gateway:443 \
  VLF_CLIENT_ID=smoke-client VLF_SECRET=smoke-secret VLF_PROTO_ID=vlf-runtime/0.1 \
  DST_TCP_HOST=tcp-echo DST_TCP_PORT=9000 \
  DST_UDP_HOST=udp-echo DST_UDP_PORT=9001 \
  MAX_DGRAM_PAYLOAD=1200 \
  go run ./scripts/session_smoke.go
'
