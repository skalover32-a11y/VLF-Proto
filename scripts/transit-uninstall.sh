#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SERVICE_NAME="vlf-transit"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/vlf-transit/.env"
CONFIG_DIR="/etc/vlf-transit"
INSTALL_DIR_DEFAULT="/opt/vlf-proto-transit"
BIN_PATH="/usr/local/bin/vlf-transit"
SERVICE_USER="vlftransit"
PURGE=0
INSTALL_DIR="${INSTALL_DIR_DEFAULT}"

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [flags]

Flags:
  --install-dir <path>  Override repo/install directory (default: ${INSTALL_DIR_DEFAULT})
  --purge               Remove ${CONFIG_DIR}, ${INSTALL_DIR_DEFAULT}, and service user
  -h, --help            Show help
EOF
}

log() { printf '[transit-uninstall] %s\n' "$*"; }
die() { printf '[transit-uninstall][error] %s\n' "$*" >&2; exit 1; }
run() { log "run: $*"; "$@"; }
require_root() { [[ "${EUID}" -eq 0 ]] || die "run as root: sudo bash ${SCRIPT_NAME} ..."; }

parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
      --purge) PURGE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown flag: $1" ;;
    esac
  done
}

load_defaults_from_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${ENV_FILE}" || true
    INSTALL_DIR="${VLF_TRANSIT_INSTALL_DIR:-${INSTALL_DIR}}"
  fi
}

main() {
  require_root
  parse_flags "$@"
  load_defaults_from_env

  if systemctl list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
    run systemctl disable --now "${SERVICE_NAME}" || true
  fi
  run rm -f "${SERVICE_FILE}"
  run systemctl daemon-reload
  run rm -f "${BIN_PATH}"

  if [[ "${PURGE}" -eq 1 ]]; then
    run rm -rf "${CONFIG_DIR}" "${INSTALL_DIR}"
    if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
      run userdel "${SERVICE_USER}" || true
    fi
  fi

  log "transit uninstall complete"
}

main "$@"
