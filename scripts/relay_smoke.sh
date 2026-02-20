#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="${NET:-$(docker network ls --format '{{.Name}}' | grep -E 'vlf|VLF|proto' | head -n1)}"

docker run --rm --network "$NET" -v "$ROOT":/src -w /src golang:1.24-alpine sh -c '
  apk add --no-cache git ca-certificates &&
  RELAY_BASE=http://gateway:8080 RELAY_DIAL_HOST=tcp-echo RELAY_DIAL_PORT=9000 \
  VLF_CLIENT=smoke-client VLF_SECRET=smoke-secret \
  go run ./scripts/relay_smoke.go
'
