#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SERVICE_NAME="vlf-gateway"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/vlf-proto/.env"
BIN_PATH="/usr/local/bin/vlf-gateway"
CONFIG_DIR="/etc/vlf-proto"
INSTALL_DIR="/opt/vlf-proto"
SERVICE_USER="vlfproto"
REMOVE_FILES=0
REMOVE_USER=0

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [flags]

Flags:
  --purge           Remove ${CONFIG_DIR}, ${INSTALL_DIR}, and service user
  --remove-files    Remove ${CONFIG_DIR} and ${INSTALL_DIR}
  --remove-user     Remove ${SERVICE_USER} user/group
  -h, --help        Show help
EOF
}

log() { printf '[uninstall] %s\n' "$*"; }
die() { printf '[uninstall][error] %s\n' "$*" >&2; exit 1; }

run() {
  log "run: $*"
  "$@"
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run as root: sudo bash ${SCRIPT_NAME} ..."
}

parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge)
        REMOVE_FILES=1
        REMOVE_USER=1
        shift
        ;;
      --remove-files)
        REMOVE_FILES=1
        shift
        ;;
      --remove-user)
        REMOVE_USER=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown flag: $1"
        ;;
    esac
  done
}

load_install_paths_from_env() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    return 0
  fi
  # shellcheck disable=SC1090
  source "${ENV_FILE}" || true
  if [[ -n "${VLF_INSTALL_DIR:-}" ]]; then
    INSTALL_DIR="${VLF_INSTALL_DIR}"
  fi
  if [[ -n "${VLF_CONFIG_FILE:-}" ]]; then
    CONFIG_DIR="$(dirname "${VLF_CONFIG_FILE}")"
  fi
}

cleanup_udp_alt_redirect() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    return 0
  fi
  # shellcheck disable=SC1090
  source "${ENV_FILE}" || true
  local port_udp="${VLF_PORT_UDP:-443}"
  local port_alt="${VLF_PORT_UDP_ALT:-8443}"
  if [[ -z "${port_alt}" || "${port_alt}" == "${port_udp}" ]]; then
    return 0
  fi
  if ! command -v iptables >/dev/null 2>&1; then
    return 0
  fi
  iptables -t nat -D PREROUTING -p udp --dport "${port_alt}" -j REDIRECT --to-ports "${port_udp}" >/dev/null 2>&1 || true
  iptables -t nat -D OUTPUT -p udp -d 127.0.0.1 --dport "${port_alt}" -j REDIRECT --to-ports "${port_udp}" >/dev/null 2>&1 || true
}

stop_and_remove_service() {
  run systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
  run systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  if [[ -f "${SERVICE_FILE}" ]]; then
    run rm -f "${SERVICE_FILE}"
  fi
  run systemctl daemon-reload
  run systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true
}

remove_binary() {
  if [[ -f "${BIN_PATH}" ]]; then
    run rm -f "${BIN_PATH}"
  fi
}

remove_files_if_requested() {
  if [[ "${REMOVE_FILES}" -ne 1 ]]; then
    log "keeping files in ${CONFIG_DIR} and ${INSTALL_DIR} (use --remove-files or --purge to delete)"
    return 0
  fi
  run rm -rf "${CONFIG_DIR}"
  run rm -rf "${INSTALL_DIR}"
}

remove_user_if_requested() {
  if [[ "${REMOVE_USER}" -ne 1 ]]; then
    return 0
  fi
  if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    run userdel "${SERVICE_USER}" >/dev/null 2>&1 || true
  fi
  if getent group "${SERVICE_USER}" >/dev/null 2>&1; then
    run groupdel "${SERVICE_USER}" >/dev/null 2>&1 || true
  fi
}

main() {
  parse_flags "$@"
  require_root
  load_install_paths_from_env
  cleanup_udp_alt_redirect
  stop_and_remove_service
  remove_binary
  remove_files_if_requested
  remove_user_if_requested
  log "uninstall complete"
}

main "$@"
