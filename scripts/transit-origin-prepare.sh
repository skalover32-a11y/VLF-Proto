#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
CONFIG_FILE="/etc/vlf-proto/config.yaml"
ENV_FILE="/etc/vlf-proto/.env"
SERVICE_NAME="vlf-gateway"
BIND_HOST="0.0.0.0"
PORT="8080"
ENABLE_UFW=0
ALLOW_SOURCE=""
EXPLICIT_BIND_HOST=0
EXPLICIT_PORT=0

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [flags]

Flags:
  --bind-host <host>    Relay bind host for origin gateway (default: 0.0.0.0)
  --port <port>         Relay bind port (default: current or 8080)
  --ufw                 Add source-scoped UFW allow rule
  --allow-source <cidr> Transit node IP/CIDR allowed to hit relay port
  -h, --help            Show help
EOF
}

log() { printf '[transit-origin] %s\n' "$*"; }
warn() { printf '[transit-origin][warn] %s\n' "$*" >&2; }
die() { printf '[transit-origin][error] %s\n' "$*" >&2; exit 1; }
run() { log "run: $*"; "$@"; }
require_root() { [[ "${EUID}" -eq 0 ]] || die "run as root: sudo bash ${SCRIPT_NAME} ..."; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" >= 1 && "$1" <= 65535 )); }
can_prompt() { [[ -t 0 ]]; }

prompt_value() {
  local prompt="$1"
  local default_value="$2"
  local current=""
  read -r -p "${prompt} [${default_value}]: " current || true
  printf '%s' "${current:-${default_value}}"
}

parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bind-host) BIND_HOST="${2:-}"; EXPLICIT_BIND_HOST=1; shift 2 ;;
      --port) PORT="${2:-}"; EXPLICIT_PORT=1; shift 2 ;;
      --ufw) ENABLE_UFW=1; shift ;;
      --allow-source) ALLOW_SOURCE="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown flag: $1" ;;
    esac
  done
}

load_existing_defaults() {
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${ENV_FILE}" || true
    [[ "${EXPLICIT_BIND_HOST}" -eq 1 ]] || BIND_HOST="${VLF_METRICS_ADDR:-${BIND_HOST}}"
    [[ "${EXPLICIT_PORT}" -eq 1 ]] || PORT="${VLF_METRICS_PORT:-${PORT}}"
  fi
}

ensure_inputs() {
  valid_port "${PORT}" || die "invalid --port: ${PORT}"
  [[ -n "${BIND_HOST}" ]] || die "bind host cannot be empty"
  if [[ "${ENABLE_UFW}" -eq 1 && -z "${ALLOW_SOURCE}" ]]; then
    if can_prompt; then
      ALLOW_SOURCE="$(prompt_value 'Transit node IP/CIDR to allow to relay port' '')"
    fi
    [[ -n "${ALLOW_SOURCE}" ]] || die "--allow-source is required when --ufw is used"
  fi
}

update_env_file() {
  touch "${ENV_FILE}"
  if grep -q '^VLF_METRICS_ADDR=' "${ENV_FILE}"; then
    sed -i "s|^VLF_METRICS_ADDR=.*$|VLF_METRICS_ADDR=${BIND_HOST}|" "${ENV_FILE}"
  else
    echo "VLF_METRICS_ADDR=${BIND_HOST}" >> "${ENV_FILE}"
  fi
  if grep -q '^VLF_METRICS_PORT=' "${ENV_FILE}"; then
    sed -i "s|^VLF_METRICS_PORT=.*$|VLF_METRICS_PORT=${PORT}|" "${ENV_FILE}"
  else
    echo "VLF_METRICS_PORT=${PORT}" >> "${ENV_FILE}"
  fi
}

update_config_file() {
  [[ -f "${CONFIG_FILE}" ]] || die "missing ${CONFIG_FILE}; install gateway first"
  cp "${CONFIG_FILE}" "${CONFIG_FILE}.bak.$(date +%s)"
  awk -v target="${BIND_HOST}:${PORT}" '
    BEGIN { changed=0 }
    /^listen_http:/ { print "listen_http: \"" target "\""; changed=1; next }
    { print }
    END {
      if (changed == 0) {
        print "listen_http: \"" target "\""
      }
    }
  ' "${CONFIG_FILE}" > "${CONFIG_FILE}.tmp"
  mv "${CONFIG_FILE}.tmp" "${CONFIG_FILE}"
}

configure_ufw() {
  if [[ "${ENABLE_UFW}" -ne 1 ]]; then
    return 0
  fi
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw not installed; skipping rule"
    return 0
  fi
  if ! ufw status | grep -q '^Status: active'; then
    warn "ufw is inactive; skipping rule"
    return 0
  fi
  run ufw allow from "${ALLOW_SOURCE}" to any port "${PORT}" proto tcp
}

restart_service() {
  run systemctl restart "${SERVICE_NAME}"
  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl status "${SERVICE_NAME}" --no-pager || true
    journalctl -u "${SERVICE_NAME}" -n 80 --no-pager || true
    die "${SERVICE_NAME} failed to restart"
  fi
}

main() {
  require_root
  parse_flags "$@"
  load_existing_defaults
  ensure_inputs
  update_env_file
  update_config_file
  configure_ufw
  restart_service
  log "origin relay bind updated to ${BIND_HOST}:${PORT}"
}

main "$@"
