#!/usr/bin/env bash
set -euo pipefail

go run ./scripts/relay_smoke/main.go "$@"
