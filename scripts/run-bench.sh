#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/scripts/.env" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    [[ "$line" == export* ]] && line="${line#export }"
    key="${line%%=*}"
    val="${line#*=}"
    key="$(echo "$key" | xargs)"
    val="$(echo "$val" | sed -e 's/^ *//' -e 's/ *$//')"
    if [[ "$val" =~ ^\".*\"$ || "$val" =~ ^\'.*\'$ ]]; then
      val="${val:1:${#val}-2}"
    fi
    if [[ -z "${!key:-}" ]]; then
      export "$key=$val"
    fi
  done < "$ROOT/scripts/.env"
fi

if command -v go >/dev/null 2>&1; then
  go run ./cmd/proto_bench "$@"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "run-bench.sh: neither 'go' nor 'docker' found" >&2
  exit 1
fi

NET="${NET:-}"
if [[ -z "$NET" ]]; then
  NET="$(docker network ls --format '{{.Name}}' | grep -E 'vlf-proto|vlf' | head -n1 || true)"
fi

DOCKER_ARGS=(run --rm -v "$ROOT":/src -w /src)
if [[ -n "$NET" ]]; then
  DOCKER_ARGS+=(--network "$NET")
fi

for key in \
  GATEWAY_HOST GATEWAY_PORT GATEWAY_PORT_UDP GATEWAY_PORT_TCP \
  RELAY_BASE VLF_CLIENT VLF_CLIENT_ID VLF_SECRET VLF_PIN_SPKI \
  VLF_PREFER_QUIC VLF_DISABLE_QUIC VLF_DISABLE_TCP_SESSION VLF_DISABLE_RELAY_FALLBACK \
  BENCH_TARGET_TCP_HOST BENCH_TARGET_TCP_PORT BENCH_TARGET_UDP_HOST BENCH_TARGET_UDP_PORT; do
  if [[ -n "${!key:-}" ]]; then
    DOCKER_ARGS+=(-e "$key=${!key}")
  fi
done

DOCKER_ARGS+=(golang:1.24-alpine sh -lc "apk add --no-cache git ca-certificates >/dev/null && go run ./cmd/proto_bench $*")
docker "${DOCKER_ARGS[@]}"
