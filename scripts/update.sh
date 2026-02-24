#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SERVICE_NAME="vlf-gateway"
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

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [flags]

Flags:
  --repo <url>         Repository URL (default: from ${ENV_FILE} or ${REPO_URL_DEFAULT})
  --ref <ref>          Git ref to deploy (default: from ${ENV_FILE} or ${REF_DEFAULT})
  --go-version <ver>   Go version if installation is needed (default: ${GO_VERSION_DEFAULT})
  --install-dir <dir>  Repository path (default: from ${ENV_FILE} or ${INSTALL_DIR_DEFAULT})
  -h, --help           Show help
EOF
}

log() { printf '[update] %s\n' "$*"; }
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

parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO_URL="${2:-}"; shift 2 ;;
      --ref) REF="${2:-}"; shift 2 ;;
      --go-version) GO_VERSION="${2:-}"; shift 2 ;;
      --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
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

update_repo() {
  [[ -d "${INSTALL_DIR}/.git" ]] || die "repo not found in ${INSTALL_DIR}. Run install.sh first."
  run git -C "${INSTALL_DIR}" remote set-url origin "${REPO_URL}"
  run git -C "${INSTALL_DIR}" fetch --tags --prune origin
  run git -C "${INSTALL_DIR}" checkout --force "${REF}"
  if git -C "${INSTALL_DIR}" rev-parse --verify "origin/${REF}" >/dev/null 2>&1; then
    run git -C "${INSTALL_DIR}" reset --hard "origin/${REF}"
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
  log "update complete"
  systemctl status "${SERVICE_NAME}" --no-pager | sed -n '1,20p'
}

main() {
  parse_flags "$@"
  require_root
  load_defaults_from_env
  [[ -n "${REPO_URL}" ]] || die "--repo cannot be empty"
  [[ -n "${REF}" ]] || die "--ref cannot be empty"

  run apt-get update -y
  DEBIAN_FRONTEND=noninteractive run apt-get install -y git curl ca-certificates
  ensure_go
  update_repo
  build_binary
  restart_service
  print_result
}

main "$@"
