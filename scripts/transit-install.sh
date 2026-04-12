#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SERVICE_NAME="vlf-transit"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_USER="vlftransit"
SERVICE_GROUP="vlftransit"

INSTALL_DIR_DEFAULT="/opt/vlf-proto-transit"
CONFIG_DIR="/etc/vlf-transit"
ENV_FILE="${CONFIG_DIR}/.env"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
BIN_PATH="/usr/local/bin/vlf-transit"

REPO_URL_DEFAULT="https://github.com/skalover32-a11y/VLF-Proto.git"
REF_DEFAULT="main"
GO_VERSION_DEFAULT="1.25.1"
LOG_LEVEL_DEFAULT="info"

REPO_URL="${REPO_URL_DEFAULT}"
REF="${REF_DEFAULT}"
GO_VERSION="${GO_VERSION_DEFAULT}"
INSTALL_DIR="${INSTALL_DIR_DEFAULT}"
BACKEND_HOST=""
BACKEND_TCP_PORT=443
BACKEND_UDP_PORT=443
BACKEND_RELAY_PORT=8080
LISTEN_HOST="0.0.0.0"
PORT_TCP=443
PORT_UDP=443
PORT_UDP_ALT=8443
ENABLE_RELAY=1
RELAY_PORT=8080
ENABLE_METRICS=1
METRICS_LISTEN="127.0.0.1:9091"
ENABLE_UFW=0
FORCE=0
LOG_LEVEL="${LOG_LEVEL_DEFAULT}"
GO_BIN=""

EXPLICIT_BACKEND_HOST=0
EXPLICIT_BACKEND_TCP_PORT=0
EXPLICIT_BACKEND_UDP_PORT=0
EXPLICIT_BACKEND_RELAY_PORT=0
EXPLICIT_LISTEN_HOST=0
EXPLICIT_PORT_TCP=0
EXPLICIT_PORT_UDP=0
EXPLICIT_PORT_UDP_ALT=0
EXPLICIT_ENABLE_RELAY=0
EXPLICIT_RELAY_PORT=0
EXPLICIT_ENABLE_METRICS=0
EXPLICIT_METRICS_LISTEN=0
EXPLICIT_LOG_LEVEL=0

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [flags]

Flags:
  --repo <url>               Git repository URL (default: ${REPO_URL_DEFAULT})
  --ref <ref>                Git ref (branch/tag/commit, default: ${REF_DEFAULT})
  --go-version <ver>         Go version if install needed (default: ${GO_VERSION_DEFAULT})
  --install-dir <path>       Repo checkout directory (default: ${INSTALL_DIR_DEFAULT})
  --backend-host <host>      Required origin VLF gateway host/IP
  --backend-tcp-port <port>  Origin TCP session port (default: 443)
  --backend-udp-port <port>  Origin UDP session port (default: 443)
  --backend-relay-port <p>   Origin relay HTTP port (default: 8080)
  --listen-host <host>       Public bind host (default: 0.0.0.0)
  --port-tcp <port>          Public TCP session port (default: 443)
  --port-udp <port>          Public UDP session port (default: 443)
  --port-udp-alt <port>      Public UDP alt port (default: 8443, 0 disables)
  --relay-port <port>        Public relay TCP port (default: 8080)
  --no-relay                 Disable relay TCP forwarding on transit
  --metrics-listen <addr>    Metrics bind addr (default: 127.0.0.1:9091)
  --no-metrics               Disable transit /metrics endpoint
  --log-level <level>        Transit log level (default: ${LOG_LEVEL_DEFAULT})
  --ufw                      Open public ports in UFW
  --force                    Reinstall/overwrite existing installation
  -h, --help                 Show help
EOF
}

log() { printf '[transit-install] %s\n' "$*"; }
warn() { printf '[transit-install][warn] %s\n' "$*" >&2; }
die() { printf '[transit-install][error] %s\n' "$*" >&2; exit 1; }
run() { log "run: $*"; "$@"; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }
require_root() { [[ "${EUID}" -eq 0 ]] || die "run as root: sudo bash ${SCRIPT_NAME} ..."; }

valid_port_or_zero() {
  [[ "$1" =~ ^[0-9]+$ ]] || return 1
  (( "$1" >= 0 && "$1" <= 65535 ))
}

valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] || return 1
  (( "$1" >= 1 && "$1" <= 65535 ))
}

join_host_port() {
  local host="$1"
  local port="$2"
  if [[ "${host}" == *:* && "${host}" != \[*\] ]]; then
    printf '[%s]:%s' "${host}" "${port}"
  else
    printf '%s:%s' "${host}" "${port}"
  fi
}

prompt_value() {
  local prompt="$1"
  local default_value="$2"
  local current=""
  if [[ -n "${default_value}" ]]; then
    read -r -p "${prompt} [${default_value}]: " current || true
    printf '%s' "${current:-${default_value}}"
    return 0
  fi
  read -r -p "${prompt}: " current || true
  printf '%s' "${current}"
}

prompt_yes_no() {
  local prompt="$1"
  local default_value="$2"
  local answer=""
  read -r -p "${prompt} [${default_value}]: " answer || true
  answer="${answer:-${default_value}}"
  case "${answer}" in
    y|Y|yes|YES) printf '1' ;;
    n|N|no|NO) printf '0' ;;
    *) printf '0' ;;
  esac
}

can_prompt() {
  [[ -t 0 ]]
}

parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO_URL="${2:-}"; shift 2 ;;
      --ref) REF="${2:-}"; shift 2 ;;
      --go-version) GO_VERSION="${2:-}"; shift 2 ;;
      --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
      --backend-host) BACKEND_HOST="${2:-}"; EXPLICIT_BACKEND_HOST=1; shift 2 ;;
      --backend-tcp-port) BACKEND_TCP_PORT="${2:-}"; EXPLICIT_BACKEND_TCP_PORT=1; shift 2 ;;
      --backend-udp-port) BACKEND_UDP_PORT="${2:-}"; EXPLICIT_BACKEND_UDP_PORT=1; shift 2 ;;
      --backend-relay-port) BACKEND_RELAY_PORT="${2:-}"; EXPLICIT_BACKEND_RELAY_PORT=1; shift 2 ;;
      --listen-host) LISTEN_HOST="${2:-}"; EXPLICIT_LISTEN_HOST=1; shift 2 ;;
      --port-tcp) PORT_TCP="${2:-}"; EXPLICIT_PORT_TCP=1; shift 2 ;;
      --port-udp) PORT_UDP="${2:-}"; EXPLICIT_PORT_UDP=1; shift 2 ;;
      --port-udp-alt) PORT_UDP_ALT="${2:-}"; EXPLICIT_PORT_UDP_ALT=1; shift 2 ;;
      --relay-port) RELAY_PORT="${2:-}"; EXPLICIT_RELAY_PORT=1; shift 2 ;;
      --no-relay) ENABLE_RELAY=0; EXPLICIT_ENABLE_RELAY=1; shift ;;
      --metrics-listen) METRICS_LISTEN="${2:-}"; EXPLICIT_METRICS_LISTEN=1; shift 2 ;;
      --no-metrics) ENABLE_METRICS=0; EXPLICIT_ENABLE_METRICS=1; shift ;;
      --log-level) LOG_LEVEL="${2:-}"; EXPLICIT_LOG_LEVEL=1; shift 2 ;;
      --ufw) ENABLE_UFW=1; shift ;;
      --force) FORCE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown flag: $1" ;;
    esac
  done
}

check_existing_installation() {
  local installed=0
  [[ -f "${SERVICE_FILE}" ]] && installed=1
  [[ -x "${BIN_PATH}" ]] && installed=1
  [[ -f "${ENV_FILE}" ]] && installed=1

  if [[ "${installed}" -eq 1 && "${FORCE}" -ne 1 ]]; then
    die "existing transit installation detected. Re-run with --force to overwrite."
  fi
}

load_existing_defaults() {
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${ENV_FILE}" || true
    [[ "${EXPLICIT_BACKEND_HOST}" -eq 1 ]] || BACKEND_HOST="${VLF_TRANSIT_BACKEND_HOST:-${BACKEND_HOST}}"
    [[ "${EXPLICIT_BACKEND_TCP_PORT}" -eq 1 ]] || BACKEND_TCP_PORT="${VLF_TRANSIT_BACKEND_TCP_PORT:-${BACKEND_TCP_PORT}}"
    [[ "${EXPLICIT_BACKEND_UDP_PORT}" -eq 1 ]] || BACKEND_UDP_PORT="${VLF_TRANSIT_BACKEND_UDP_PORT:-${BACKEND_UDP_PORT}}"
    [[ "${EXPLICIT_BACKEND_RELAY_PORT}" -eq 1 ]] || BACKEND_RELAY_PORT="${VLF_TRANSIT_BACKEND_RELAY_PORT:-${BACKEND_RELAY_PORT}}"
    [[ "${EXPLICIT_LISTEN_HOST}" -eq 1 ]] || LISTEN_HOST="${VLF_TRANSIT_LISTEN_HOST:-${LISTEN_HOST}}"
    [[ "${EXPLICIT_PORT_TCP}" -eq 1 ]] || PORT_TCP="${VLF_TRANSIT_PORT_TCP:-${PORT_TCP}}"
    [[ "${EXPLICIT_PORT_UDP}" -eq 1 ]] || PORT_UDP="${VLF_TRANSIT_PORT_UDP:-${PORT_UDP}}"
    [[ "${EXPLICIT_PORT_UDP_ALT}" -eq 1 ]] || PORT_UDP_ALT="${VLF_TRANSIT_PORT_UDP_ALT:-${PORT_UDP_ALT}}"
    [[ "${EXPLICIT_ENABLE_RELAY}" -eq 1 ]] || ENABLE_RELAY="${VLF_TRANSIT_ENABLE_RELAY:-${ENABLE_RELAY}}"
    [[ "${EXPLICIT_RELAY_PORT}" -eq 1 ]] || RELAY_PORT="${VLF_TRANSIT_RELAY_PORT:-${RELAY_PORT}}"
    [[ "${EXPLICIT_ENABLE_METRICS}" -eq 1 ]] || ENABLE_METRICS="${VLF_TRANSIT_ENABLE_METRICS:-${ENABLE_METRICS}}"
    [[ "${EXPLICIT_METRICS_LISTEN}" -eq 1 ]] || METRICS_LISTEN="${VLF_TRANSIT_METRICS_LISTEN:-${METRICS_LISTEN}}"
    [[ "${EXPLICIT_LOG_LEVEL}" -eq 1 ]] || LOG_LEVEL="${VLF_TRANSIT_LOG_LEVEL:-${LOG_LEVEL}}"
  fi
}

ensure_prompted_values() {
  if [[ -z "${BACKEND_HOST}" ]]; then
    if can_prompt; then
      BACKEND_HOST="$(prompt_value 'Origin gateway host or IP' '')"
      [[ -n "${BACKEND_HOST}" ]] || die "backend host is required"
    else
      die "missing required --backend-host for non-interactive install"
    fi
  fi

  if [[ "${EXPLICIT_ENABLE_RELAY}" -ne 1 && -f /dev/tty && -t 0 ]]; then
    ENABLE_RELAY="$(prompt_yes_no 'Enable relay TCP forwarding on transit' 'Y')"
  fi

  if [[ "${ENABLE_UFW}" -eq 0 && -f /dev/tty && -t 0 ]]; then
    ENABLE_UFW="$(prompt_yes_no 'Open transit public ports in UFW' 'N')"
  fi
}

validate_flags() {
  [[ -n "${REPO_URL}" ]] || die "--repo cannot be empty"
  [[ -n "${REF}" ]] || die "--ref cannot be empty"
  [[ -n "${INSTALL_DIR}" ]] || die "--install-dir cannot be empty"
  [[ -n "${BACKEND_HOST}" ]] || die "backend host cannot be empty"
  [[ -n "${LISTEN_HOST}" ]] || die "listen host cannot be empty"
  [[ -n "${METRICS_LISTEN}" || "${ENABLE_METRICS}" -eq 0 ]] || die "metrics listen cannot be empty when metrics are enabled"
  [[ -n "${LOG_LEVEL}" ]] || die "log level cannot be empty"

  valid_port "${BACKEND_TCP_PORT}" || die "invalid --backend-tcp-port: ${BACKEND_TCP_PORT}"
  valid_port "${BACKEND_UDP_PORT}" || die "invalid --backend-udp-port: ${BACKEND_UDP_PORT}"
  if [[ "${ENABLE_RELAY}" -eq 1 ]]; then
    valid_port "${BACKEND_RELAY_PORT}" || die "invalid --backend-relay-port: ${BACKEND_RELAY_PORT}"
    valid_port "${RELAY_PORT}" || die "invalid --relay-port: ${RELAY_PORT}"
  fi
  valid_port "${PORT_TCP}" || die "invalid --port-tcp: ${PORT_TCP}"
  valid_port "${PORT_UDP}" || die "invalid --port-udp: ${PORT_UDP}"
  valid_port_or_zero "${PORT_UDP_ALT}" || die "invalid --port-udp-alt: ${PORT_UDP_ALT}"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

go_version_ge() {
  local current="$1"
  local required="$2"
  local c_major c_minor c_patch r_major r_minor r_patch
  IFS='.' read -r c_major c_minor c_patch <<<"${current}"
  IFS='.' read -r r_major r_minor r_patch <<<"${required}"
  c_patch="${c_patch:-0}"
  r_patch="${r_patch:-0}"
  if (( c_major > r_major )); then return 0; fi
  if (( c_major < r_major )); then return 1; fi
  if (( c_minor > r_minor )); then return 0; fi
  if (( c_minor < r_minor )); then return 1; fi
  (( c_patch >= r_patch ))
}

ensure_dependencies() {
  local packages=(curl git ca-certificates iproute2 iptables)
  if [[ "${ENABLE_UFW}" -eq 1 ]]; then
    packages+=(ufw)
  fi
  log "installing dependencies: ${packages[*]}"
  run apt-get update -y
  DEBIAN_FRONTEND=noninteractive run apt-get install -y "${packages[@]}"
}

ensure_go() {
  if need_cmd go; then
    local found raw ver
    found="$(command -v go)"
    raw="$(${found} version | awk '{print $3}')"
    ver="${raw#go}"
    if go_version_ge "${ver}" "${GO_VERSION}"; then
      GO_BIN="${found}"
      log "using existing Go ${ver} (${GO_BIN})"
      return 0
    fi
    log "existing Go ${ver} is lower than ${GO_VERSION}; installing pinned Go"
  else
    log "Go not found; installing pinned Go ${GO_VERSION}"
  fi

  local arch tarball url tmp
  arch="$(detect_arch)"
  tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
  url="https://go.dev/dl/${tarball}"
  tmp="/tmp/${tarball}"
  run curl -fL "${url}" -o "${tmp}"
  run rm -rf /usr/local/go
  run tar -C /usr/local -xzf "${tmp}"
  run rm -f "${tmp}"
  GO_BIN="/usr/local/go/bin/go"
}

ensure_service_user() {
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    log "creating system user ${SERVICE_USER}"
    run useradd --system --home /nonexistent --shell /usr/sbin/nologin --no-create-home "${SERVICE_USER}"
  fi
}

checkout_repo() {
  run mkdir -p "${CONFIG_DIR}"
  run mkdir -p "${INSTALL_DIR}"
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    log "updating existing repo in ${INSTALL_DIR}"
    run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" remote set-url origin "${REPO_URL}"
    run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" fetch --tags --prune origin
    run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" checkout --force "${REF}"
    if git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" rev-parse --verify "origin/${REF}" >/dev/null 2>&1; then
      run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" reset --hard "origin/${REF}"
    fi
  else
    if [[ -d "${INSTALL_DIR}" ]]; then
      run rm -rf "${INSTALL_DIR}"
    fi
    log "cloning ${REPO_URL} -> ${INSTALL_DIR}"
    run git clone "${REPO_URL}" "${INSTALL_DIR}"
    run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" checkout --force "${REF}"
  fi
  run chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
}

build_binary() {
  local build_dir
  build_dir="$(mktemp -d)"
  log "building transit binary"
  log "run: tar -C ${INSTALL_DIR} --exclude=.git -cf - . | tar -C ${build_dir} -xf -"
  tar -C "${INSTALL_DIR}" --exclude=.git -cf - . | tar -C "${build_dir}" -xf -
  (
    cd "${build_dir}"
    GOFLAGS="-buildvcs=false ${GOFLAGS:-}" CGO_ENABLED=0 "${GO_BIN}" build -trimpath -ldflags "-s -w" -o "${BIN_PATH}" ./cmd/transit
  )
  run rm -rf "${build_dir}"
  run chown root:root "${BIN_PATH}"
  run chmod 0755 "${BIN_PATH}"
}

write_env_file() {
  cat > "${ENV_FILE}" <<EOF
VLF_TRANSIT_REPO_URL=${REPO_URL}
VLF_TRANSIT_REF=${REF}
VLF_TRANSIT_INSTALL_DIR=${INSTALL_DIR}
VLF_TRANSIT_BACKEND_HOST=${BACKEND_HOST}
VLF_TRANSIT_BACKEND_TCP_PORT=${BACKEND_TCP_PORT}
VLF_TRANSIT_BACKEND_UDP_PORT=${BACKEND_UDP_PORT}
VLF_TRANSIT_BACKEND_RELAY_PORT=${BACKEND_RELAY_PORT}
VLF_TRANSIT_LISTEN_HOST=${LISTEN_HOST}
VLF_TRANSIT_PORT_TCP=${PORT_TCP}
VLF_TRANSIT_PORT_UDP=${PORT_UDP}
VLF_TRANSIT_PORT_UDP_ALT=${PORT_UDP_ALT}
VLF_TRANSIT_ENABLE_RELAY=${ENABLE_RELAY}
VLF_TRANSIT_RELAY_PORT=${RELAY_PORT}
VLF_TRANSIT_ENABLE_METRICS=${ENABLE_METRICS}
VLF_TRANSIT_METRICS_LISTEN=${METRICS_LISTEN}
VLF_TRANSIT_LOG_LEVEL=${LOG_LEVEL}
EOF
  run chown root:root "${ENV_FILE}"
  run chmod 0600 "${ENV_FILE}"
}

write_config_file() {
  local backend_tcp backend_udp backend_relay listen_tcp listen_udp listen_udp_alt listen_relay
  backend_tcp="$(join_host_port "${BACKEND_HOST}" "${BACKEND_TCP_PORT}")"
  backend_udp="$(join_host_port "${BACKEND_HOST}" "${BACKEND_UDP_PORT}")"
  listen_tcp="$(join_host_port "${LISTEN_HOST}" "${PORT_TCP}")"
  listen_udp="$(join_host_port "${LISTEN_HOST}" "${PORT_UDP}")"
  listen_udp_alt=""
  if [[ "${PORT_UDP_ALT}" -gt 0 ]]; then
    listen_udp_alt="$(join_host_port "${LISTEN_HOST}" "${PORT_UDP_ALT}")"
  fi
  if [[ "${ENABLE_RELAY}" -eq 1 ]]; then
    backend_relay="$(join_host_port "${BACKEND_HOST}" "${BACKEND_RELAY_PORT}")"
    listen_relay="$(join_host_port "${LISTEN_HOST}" "${RELAY_PORT}")"
  fi

  {
    echo "log_level: \"${LOG_LEVEL}\""
    echo "listen_tcp: \"${listen_tcp}\""
    echo "backend_tcp: \"${backend_tcp}\""
    echo "listen_udp: \"${listen_udp}\""
    echo "backend_udp: \"${backend_udp}\""
    if [[ -n "${listen_udp_alt}" ]]; then
      echo "listen_udp_alt: \"${listen_udp_alt}\""
    else
      echo 'listen_udp_alt: ""'
    fi
    if [[ "${ENABLE_RELAY}" -eq 1 ]]; then
      echo 'enable_relay: true'
      echo "listen_relay: \"${listen_relay}\""
      echo "backend_relay: \"${backend_relay}\""
    else
      echo 'enable_relay: false'
      echo 'listen_relay: ""'
      echo 'backend_relay: ""'
    fi
    if [[ "${ENABLE_METRICS}" -eq 1 ]]; then
      echo 'enable_metrics: true'
      echo "metrics_listen: \"${METRICS_LISTEN}\""
    else
      echo 'enable_metrics: false'
      echo 'metrics_listen: ""'
    fi
    cat <<EOF

timeouts:
  dial_timeout: "10s"
  udp_idle: "60s"
  shutdown_timeout: "10s"
EOF
  } > "${CONFIG_FILE}"
  run chown root:${SERVICE_GROUP} "${CONFIG_FILE}"
  run chmod 0640 "${CONFIG_FILE}"
}

write_systemd_unit() {
  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=VLF Transit Hop
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH} -config ${CONFIG_FILE}
Restart=always
RestartSec=1
LimitNOFILE=1048576
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF
}

configure_ufw() {
  if [[ "${ENABLE_UFW}" -ne 1 ]]; then
    return 0
  fi
  if ! need_cmd ufw; then
    warn "ufw not installed; skipping ufw rules"
    return 0
  fi
  if ! ufw status | grep -q '^Status: active'; then
    warn "ufw is installed but inactive; skipping ufw rules"
    return 0
  fi
  log "applying UFW rules"
  run ufw allow "${PORT_TCP}/tcp"
  run ufw allow "${PORT_UDP}/udp"
  if [[ "${PORT_UDP_ALT}" -gt 0 && "${PORT_UDP_ALT}" != "${PORT_UDP}" ]]; then
    run ufw allow "${PORT_UDP_ALT}/udp"
  fi
  if [[ "${ENABLE_RELAY}" -eq 1 ]]; then
    run ufw allow "${RELAY_PORT}/tcp"
  fi
}

start_and_verify_service() {
  run systemctl daemon-reload
  run systemctl enable --now "${SERVICE_NAME}"
  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl status "${SERVICE_NAME}" --no-pager || true
    journalctl -u "${SERVICE_NAME}" -n 80 --no-pager || true
    die "${SERVICE_NAME} failed to start"
  fi
}

post_checks() {
  local ports_pattern
  ports_pattern=":${PORT_TCP}|:${PORT_UDP}"
  if [[ "${PORT_UDP_ALT}" -gt 0 ]]; then
    ports_pattern="${ports_pattern}|:${PORT_UDP_ALT}"
  fi
  if [[ "${ENABLE_RELAY}" -eq 1 ]]; then
    ports_pattern="${ports_pattern}|:${RELAY_PORT}"
  fi
  if [[ "${ENABLE_METRICS}" -eq 1 ]]; then
    ports_pattern="${ports_pattern}|:${METRICS_LISTEN##*:}"
  fi

  log "post-check: systemctl status"
  systemctl status "${SERVICE_NAME}" --no-pager || true
  log "post-check: listening sockets"
  ss -lntup | egrep "(${ports_pattern})\\s" || true
  if [[ "${ENABLE_METRICS}" -eq 1 ]]; then
    log "post-check: metrics endpoint"
    curl -fsS "http://${METRICS_LISTEN}/metrics" | head || true
  fi
}

print_summary() {
  echo
  echo "================= VLF TRANSIT INSTALL SUMMARY ================="
  echo "Service:              ${SERVICE_NAME}"
  echo "Binary:               ${BIN_PATH}"
  echo "Repo dir:             ${INSTALL_DIR}"
  echo "Config file:          ${CONFIG_FILE}"
  echo "Env file:             ${ENV_FILE}"
  echo "Origin backend host:  ${BACKEND_HOST}"
  echo "Origin TCP/UDP:       ${BACKEND_TCP_PORT}/${BACKEND_UDP_PORT}"
  if [[ "${ENABLE_RELAY}" -eq 1 ]]; then
    echo "Origin relay port:    ${BACKEND_RELAY_PORT}"
    echo "Public relay port:    ${RELAY_PORT}"
  else
    echo "Relay forwarding:     disabled"
  fi
  echo "Public session ports: tcp=${PORT_TCP} udp=${PORT_UDP} udp-alt=${PORT_UDP_ALT}"
  if [[ "${ENABLE_METRICS}" -eq 1 ]]; then
    echo "Metrics:              enabled (${METRICS_LISTEN})"
  else
    echo "Metrics:              disabled"
  fi
  echo "Service status:       $(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || true)"
  echo "==============================================================="
}

main() {
  require_root
  parse_flags "$@"
  check_existing_installation
  load_existing_defaults
  ensure_prompted_values
  validate_flags
  ensure_dependencies
  ensure_go
  ensure_service_user
  checkout_repo
  build_binary
  write_env_file
  write_config_file
  write_systemd_unit
  configure_ufw
  start_and_verify_service
  post_checks
  print_summary
}

main "$@"
