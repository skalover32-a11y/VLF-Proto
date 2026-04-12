#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
REPO_URL_DEFAULT="https://github.com/skalover32-a11y/VLF-Proto.git"
REF_DEFAULT="main"
GO_VERSION_DEFAULT="1.25.1"
INSTALL_DIR_DEFAULT="/opt/vlf-proto-transit"
ENV_FILE="/etc/vlf-transit/.env"
SERVICE_FILE="/etc/systemd/system/vlf-transit.service"

REPO_URL="${REPO_URL_DEFAULT}"
REF="${REF_DEFAULT}"
GO_VERSION="${GO_VERSION_DEFAULT}"
INSTALL_DIR="${INSTALL_DIR_DEFAULT}"
BOOTSTRAP_ARGS=()

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [flags]

Flags:
  --repo <url>               Repository URL (default: ${REPO_URL_DEFAULT})
  --ref <ref>                Git ref to deploy (default: ${REF_DEFAULT})
  --go-version <ver>         Go version if installation is needed (default: ${GO_VERSION_DEFAULT})
  --install-dir <dir>        Repository path (default: ${INSTALL_DIR_DEFAULT})
  --backend-host <host>      Forwarded to transit-install.sh
  --backend-tcp-port <port>  Forwarded to transit-install.sh
  --backend-udp-port <port>  Forwarded to transit-install.sh
  --backend-relay-port <p>   Forwarded to transit-install.sh
  --listen-host <host>       Forwarded to transit-install.sh
  --port-tcp <port>          Forwarded to transit-install.sh
  --port-udp <port>          Forwarded to transit-install.sh
  --port-udp-alt <port>      Forwarded to transit-install.sh
  --relay-port <port>        Forwarded to transit-install.sh
  --no-relay                 Forwarded to transit-install.sh
  --metrics-listen <addr>    Forwarded to transit-install.sh
  --no-metrics               Forwarded to transit-install.sh
  --log-level <level>        Forwarded to transit-install.sh
  --ufw                      Forwarded to transit-install.sh
  -h, --help                 Show help
EOF
}

log() { printf '[transit-update] %s\n' "$*"; }
die() { printf '[transit-update][error] %s\n' "$*" >&2; exit 1; }
run() { log "run: $*"; "$@"; }
require_root() { [[ "${EUID}" -eq 0 ]] || die "run as root: sudo bash ${SCRIPT_NAME} ..."; }

remember_arg() {
  BOOTSTRAP_ARGS+=("$@")
}

parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO_URL="${2:-}"; shift 2 ;;
      --ref) REF="${2:-}"; shift 2 ;;
      --go-version) GO_VERSION="${2:-}"; shift 2 ;;
      --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
      --backend-host|--backend-tcp-port|--backend-udp-port|--backend-relay-port|--listen-host|--port-tcp|--port-udp|--port-udp-alt|--relay-port|--metrics-listen|--log-level)
        remember_arg "$1" "${2:-}"; shift 2 ;;
      --no-relay|--no-metrics|--ufw)
        remember_arg "$1"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown flag: $1" ;;
    esac
  done
}

load_defaults_from_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${ENV_FILE}" || true
    [[ "${REPO_URL}" != "${REPO_URL_DEFAULT}" ]] || REPO_URL="${VLF_TRANSIT_REPO_URL:-${REPO_URL}}"
    [[ "${REF}" != "${REF_DEFAULT}" ]] || REF="${VLF_TRANSIT_REF:-${REF}}"
    [[ "${INSTALL_DIR}" != "${INSTALL_DIR_DEFAULT}" ]] || INSTALL_DIR="${VLF_TRANSIT_INSTALL_DIR:-${INSTALL_DIR}}"
  fi
}

load_defaults_from_service() {
  local unit_install_dir
  if [[ ! -f "${SERVICE_FILE}" ]]; then
    return 0
  fi
  if [[ "${INSTALL_DIR}" != "${INSTALL_DIR_DEFAULT}" ]]; then
    return 0
  fi
  unit_install_dir="$(awk -F= '/^WorkingDirectory=/{print $2; exit}' "${SERVICE_FILE}" 2>/dev/null || true)"
  unit_install_dir="$(printf '%s' "${unit_install_dir}" | tr -d '[:space:]')"
  if [[ -n "${unit_install_dir}" ]]; then
    INSTALL_DIR="${unit_install_dir}"
  fi
}

ensure_base_dependencies() {
  run apt-get update -y
  DEBIAN_FRONTEND=noninteractive run apt-get install -y git curl ca-certificates
}

deploy_via_install() {
  local tmp_dir install_cmd rc
  tmp_dir="$(mktemp -d)"
  rc=0
  if ! run git clone "${REPO_URL}" "${tmp_dir}"; then
    rc=$?
  elif ! run git -c safe.directory="${tmp_dir}" -C "${tmp_dir}" checkout --force "${REF}"; then
    rc=$?
  else
    install_cmd=(
      bash "${tmp_dir}/scripts/transit-install.sh"
      --repo "${REPO_URL}"
      --ref "${REF}"
      --go-version "${GO_VERSION}"
      --install-dir "${INSTALL_DIR}"
      --force
    )
    if [[ "${#BOOTSTRAP_ARGS[@]}" -gt 0 ]]; then
      install_cmd+=("${BOOTSTRAP_ARGS[@]}")
    fi
    if ! run "${install_cmd[@]}"; then
      rc=$?
    fi
  fi
  rm -rf "${tmp_dir}"
  [[ "${rc}" -eq 0 ]] || exit "${rc}"
}

main() {
  require_root
  parse_flags "$@"
  load_defaults_from_env
  load_defaults_from_service
  ensure_base_dependencies
  deploy_via_install
}

main "$@"
