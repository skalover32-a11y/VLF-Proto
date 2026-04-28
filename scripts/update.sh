#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SERVICE_NAME="vlf-gateway"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/vlf-proto/.env"
REPO_URL_DEFAULT="https://github.com/skalover32-a11y/VLF-Proto.git"
REF_DEFAULT="main"
GO_VERSION_DEFAULT="1.25.1"
INSTALL_DIR_DEFAULT="/opt/vlf-proto"
BIN_PATH="/usr/local/bin/vlf-gateway"

REPO_URL="${REPO_URL_DEFAULT}"
REF="${REF_DEFAULT}"
GO_VERSION="${GO_VERSION_DEFAULT}"
INSTALL_DIR="${INSTALL_DIR_DEFAULT}"
GO_BIN=""
BOOTSTRAP_IF_MISSING=1
BOOTSTRAP_FORCE=0
INSTALL_ARG_NAMES=()
INSTALL_FORWARD_ARGS=()
DEPLOY_ACTION="update"

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [flags]

Flags:
  --repo <url>         Repository URL (default: from ${ENV_FILE} or ${REPO_URL_DEFAULT})
  --ref <ref>          Git ref to deploy (default: from ${ENV_FILE} or ${REF_DEFAULT})
  --go-version <ver>   Go version if installation is needed (default: ${GO_VERSION_DEFAULT})
  --install-dir <dir>  Repository path (default: from ${ENV_FILE} or ${INSTALL_DIR_DEFAULT})
  --no-bootstrap       Fail if gateway is not installed instead of auto-running install.sh
  --port-tcp <port>    Forwarded to install.sh when bootstrapping a missing deployment
  --port-udp <port>    Forwarded to install.sh when bootstrapping a missing deployment
  --port-udp-alt <p>   Forwarded to install.sh when bootstrapping a missing deployment
  --metrics-addr <a>   Forwarded to install.sh when bootstrapping a missing deployment
  --metrics-port <p>   Forwarded to install.sh when bootstrapping a missing deployment
  --no-metrics         Forwarded to install.sh when bootstrapping a missing deployment
  --ufw                Forwarded to install.sh when bootstrapping a missing deployment
  --domain <name>      Forwarded to install.sh when bootstrapping a missing deployment
  --tls-server-name <sni>
                       Forwarded to install.sh when bootstrapping a missing deployment
  --client-id <id>     Forwarded to install.sh when bootstrapping a missing deployment
  --secret <value>     Forwarded to install.sh when bootstrapping a missing deployment
  --phase1-auth        Forwarded to install.sh: enable Phase-1 UUID-as-key auth mode
  --log-level <level>  Forwarded to install.sh when bootstrapping a missing deployment
  --show-secrets       Forwarded to install.sh when bootstrapping a missing deployment
  -h, --help           Show help
EOF
}

log() { printf '[update] %s\n' "$*"; }
warn() { printf '[update][warn] %s\n' "$*" >&2; }
die() { printf '[update][error] %s\n' "$*" >&2; exit 1; }

run() {
  log "run: $*"
  "$@"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run as root: sudo bash ${SCRIPT_NAME} ..."
}

remember_install_arg() {
  INSTALL_ARG_NAMES+=("$1")
  INSTALL_FORWARD_ARGS+=("$@")
}

parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO_URL="${2:-}"; shift 2 ;;
      --ref) REF="${2:-}"; shift 2 ;;
      --go-version) GO_VERSION="${2:-}"; shift 2 ;;
      --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
      --no-bootstrap) BOOTSTRAP_IF_MISSING=0; shift ;;
      --port-tcp) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --port-udp) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --port-udp-alt) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --metrics-addr) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --metrics-port) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --no-metrics) remember_install_arg "$1"; shift ;;
      --ufw) remember_install_arg "$1"; shift ;;
      --domain) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --tls-server-name) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --client-id) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --secret) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --phase1-auth) remember_install_arg "$1"; shift ;;
      --log-level) remember_install_arg "$1" "${2:-}"; shift 2 ;;
      --show-secrets) remember_install_arg "$1"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown flag: $1" ;;
    esac
  done
}

load_defaults_from_env() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    return 0
  fi
  # shellcheck disable=SC1090
  source "${ENV_FILE}" || true
  if [[ "${REPO_URL}" == "${REPO_URL_DEFAULT}" && -n "${VLF_REPO_URL:-}" ]]; then
    REPO_URL="${VLF_REPO_URL}"
  fi
  if [[ "${REF}" == "${REF_DEFAULT}" && -n "${VLF_REF:-}" ]]; then
    REF="${VLF_REF}"
  fi
  if [[ "${INSTALL_DIR}" == "${INSTALL_DIR_DEFAULT}" && -n "${VLF_INSTALL_DIR:-}" ]]; then
    INSTALL_DIR="${VLF_INSTALL_DIR}"
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

ensure_go() {
  if need_cmd go; then
    local found raw ver
    found="$(command -v go)"
    raw="$("${found}" version | awk '{print $3}')"
    ver="${raw#go}"
    if go_version_ge "${ver}" "${GO_VERSION}"; then
      GO_BIN="${found}"
      log "using existing Go ${ver}"
      return 0
    fi
    log "existing Go ${ver} is lower than ${GO_VERSION}; installing pinned Go"
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

deployment_ready_for_update() {
  [[ -d "${INSTALL_DIR}/.git" ]] || return 1
  [[ -f "${ENV_FILE}" ]] || return 1
  [[ -f "${SERVICE_FILE}" ]] || return 1
  return 0
}

any_installation_markers_present() {
  [[ -d "${INSTALL_DIR}/.git" ]] && return 0
  [[ -f "${ENV_FILE}" ]] && return 0
  [[ -f "${SERVICE_FILE}" ]] && return 0
  [[ -x "${BIN_PATH}" ]] && return 0
  return 1
}

warn_ignored_install_args_on_update() {
  if [[ "${#INSTALL_ARG_NAMES[@]}" -eq 0 ]]; then
    return 0
  fi
  warn "install-only flags are ignored on in-place update: ${INSTALL_ARG_NAMES[*]}"
}

bootstrap_install_if_missing() {
  local tmp_dir rc
  if [[ "${BOOTSTRAP_IF_MISSING}" -ne 1 ]]; then
    die "gateway is not fully installed in ${INSTALL_DIR}. Run install.sh first or omit --no-bootstrap."
  fi

  if any_installation_markers_present; then
    BOOTSTRAP_FORCE=1
    warn "partial installation detected; bootstrapping with install.sh --force"
  else
    log "gateway is not installed; bootstrapping with install.sh"
  fi

  tmp_dir="$(mktemp -d)"
  rc=0
  if ! run git clone "${REPO_URL}" "${tmp_dir}"; then
    rc=$?
  elif ! run git -c safe.directory="${tmp_dir}" -C "${tmp_dir}" checkout --force "${REF}"; then
    rc=$?
  else
    local install_cmd=(
      bash "${tmp_dir}/scripts/install.sh"
      --repo "${REPO_URL}"
      --ref "${REF}"
      --go-version "${GO_VERSION}"
      --install-dir "${INSTALL_DIR}"
    )
    if [[ "${BOOTSTRAP_FORCE}" -eq 1 ]]; then
      install_cmd+=(--force)
    fi
    if [[ "${#INSTALL_FORWARD_ARGS[@]}" -gt 0 ]]; then
      install_cmd+=("${INSTALL_FORWARD_ARGS[@]}")
    fi
    DEPLOY_ACTION="install"
    if ! run "${install_cmd[@]}"; then
      rc=$?
    fi
  fi
  rm -rf "${tmp_dir}"
  [[ "${rc}" -eq 0 ]] || exit "${rc}"
}

update_repo() {
  [[ -d "${INSTALL_DIR}/.git" ]] || die "repo not found in ${INSTALL_DIR}"
  run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" remote set-url origin "${REPO_URL}"
  run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" fetch --tags --prune origin
  run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" checkout --force "${REF}"
  if git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" rev-parse --verify "origin/${REF}" >/dev/null 2>&1; then
    run git -c safe.directory="${INSTALL_DIR}" -C "${INSTALL_DIR}" reset --hard "origin/${REF}"
  fi
}

build_binary() {
  (
    cd "${INSTALL_DIR}"
    CGO_ENABLED=0 "${GO_BIN}" build -buildvcs=false -trimpath -ldflags='-s -w' -o "${BIN_PATH}" ./cmd/gateway
  )
  run chmod 0755 "${BIN_PATH}"
  run chown root:root "${BIN_PATH}"
}

restart_service() {
  run systemctl daemon-reload
  run systemctl restart "${SERVICE_NAME}"
  sleep 1
  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    journalctl -u "${SERVICE_NAME}" --no-pager -n 200 >&2 || true
    die "${SERVICE_NAME} failed after update"
  fi
}

print_result() {
  log "${DEPLOY_ACTION} complete"
  systemctl status "${SERVICE_NAME}" --no-pager | sed -n '1,20p'
}

main() {
  parse_flags "$@"
  require_root
  load_defaults_from_env
  load_defaults_from_service
  [[ -n "${REPO_URL}" ]] || die "--repo cannot be empty"
  [[ -n "${REF}" ]] || die "--ref cannot be empty"

  ensure_base_dependencies
  if ! deployment_ready_for_update; then
    bootstrap_install_if_missing
    print_result
    exit 0
  fi

  warn_ignored_install_args_on_update
  ensure_go
  update_repo
  build_binary
  restart_service
  print_result
}

main "$@"
