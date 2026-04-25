#!/usr/bin/env bash
# scripts/update-gateway.sh
#
# Phase-1 production update wrapper for the main VLF gateway.
#
# Responsibilities:
#   * Validate environment (root, deps).
#   * Snapshot current binary, env file and config to a timestamped backup dir.
#   * Inject Phase-1 safe defaults into the gateway env file if those keys are
#     missing - never overwrite values the operator already set.
#   * Delegate the actual git pull / build / systemctl restart to the proven
#     scripts/update.sh.
#   * Run a deterministic health check after restart. On failure, restore the
#     binary + env from backup and restart the previous service.
#
# Phase-1 risky transport flags MUST stay OFF for this rollout. The wrapper
# refuses to run if the env file explicitly enables any of them.
#
# One-command usage:
#   curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<ref>/scripts/update-gateway.sh \
#     | sudo VLF_REF=<ref> bash
#
# All flags after `--` are forwarded verbatim to scripts/update.sh.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SERVICE_NAME="vlf-gateway"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/vlf-proto/.env"
BIN_PATH="/usr/local/bin/vlf-gateway"
INSTALL_DIR_DEFAULT="/opt/vlf-proto"
CONFIG_FILE_DEFAULT="/etc/vlf-proto/config.yaml"
BACKUP_ROOT="/opt/vlf-proto/backups"
REPO_URL_DEFAULT="https://github.com/skalover32-a11y/VLF-Proto.git"

DRY_RUN=0
NO_RESTART=0
HEALTH_TIMEOUT="${VLF_HEALTH_TIMEOUT:-30}"
FORWARD_ARGS=()

PHASE1_RISKY_KEYS=(
  VLF_TRANSPORT_PROFILES_ENABLED
  VLF_PROFILE_SCORING_ENABLED
  VLF_PROFILE_MIGRATION_ENABLED
  VLF_RESUME_TOKENS_ENABLED
)
PHASE1_SAFE_DEFAULTS=(
  "VLF_TRANSPORT_PROFILES_ENABLED=0"
  "VLF_PROFILE_SCORING_ENABLED=0"
  "VLF_PROFILE_MIGRATION_ENABLED=0"
  "VLF_RESUME_TOKENS_ENABLED=0"
)

log()  { printf '[update-gateway] %s\n' "$*"; }
warn() { printf '[update-gateway][warn] %s\n' "$*" >&2; }
die()  { printf '[update-gateway][error] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [flags] [-- update.sh-flags...]

Flags:
  --dry-run              Print actions without changing anything.
  --no-restart           Build/update but do not restart service. Health check skipped.
  --health-timeout <s>   How long to wait for systemctl is-active (default: ${HEALTH_TIMEOUT}s).
  -h, --help             Show this help.

Environment:
  VLF_REF                Git ref/tag to deploy. Required for production.
  VLF_REPO_URL           Repository URL override. Default: ${REPO_URL_DEFAULT}
  VLF_INSTALL_DIR        Repo checkout dir. Default: ${INSTALL_DIR_DEFAULT}
  VLF_HEALTH_TIMEOUT     Same as --health-timeout.

Phase-1 safety:
  The following keys must NOT be set to 1 in ${ENV_FILE}:
    ${PHASE1_RISKY_KEYS[*]}
  If they are missing, this wrapper appends them as 0 (safe defaults).

Example:
  sudo VLF_REF=vlf-proto-pre-canary-2026-04-25 bash ${SCRIPT_NAME}
EOF
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "must run as root: sudo bash ${SCRIPT_NAME}"
}

require_pinned_ref() {
  if [[ -z "${VLF_REF:-}" ]]; then
    die "VLF_REF is required (pinned tag or commit sha). Refusing to deploy 'main' silently."
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_deps() {
  for c in curl tar systemctl bash awk grep sed install; do
    need_cmd "$c"
  done
}

parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift ;;
      --no-restart) NO_RESTART=1; shift ;;
      --health-timeout) HEALTH_TIMEOUT="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      --) shift; FORWARD_ARGS+=("$@"); break ;;
      *) FORWARD_ARGS+=("$1"); shift ;;
    esac
  done
}

run() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] %s\n' "$*"
    return 0
  fi
  log "run: $*"
  "$@"
}

require_safe_env() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    return 0
  fi
  local key
  for key in "${PHASE1_RISKY_KEYS[@]}"; do
    if grep -E "^${key}=1$" "${ENV_FILE}" >/dev/null 2>&1; then
      die "Phase-1 violation: ${key}=1 found in ${ENV_FILE}. Set it to 0 before update."
    fi
  done
}

inject_safe_defaults() {
  # Append missing Phase-1 keys as =0. Never overwrite operator values.
  if [[ ! -f "${ENV_FILE}" ]]; then
    return 0
  fi
  local pair key existing
  for pair in "${PHASE1_SAFE_DEFAULTS[@]}"; do
    key="${pair%%=*}"
    existing="$(grep -E "^${key}=" "${ENV_FILE}" || true)"
    if [[ -z "${existing}" ]]; then
      if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[dry-run] would append %s to %s\n' "${pair}" "${ENV_FILE}"
      else
        printf '%s\n' "${pair}" >>"${ENV_FILE}"
        log "appended ${pair} to ${ENV_FILE}"
      fi
    fi
  done
}

make_backup() {
  local stamp dir
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dir="${BACKUP_ROOT}/gateway-${stamp}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] would create backup at %s\n' "${dir}"
    BACKUP_DIR=""
    return 0
  fi
  mkdir -p "${dir}"
  if [[ -x "${BIN_PATH}" ]]; then
    install -m 0755 "${BIN_PATH}" "${dir}/vlf-gateway.bin"
  fi
  if [[ -f "${ENV_FILE}" ]]; then
    install -m 0640 "${ENV_FILE}" "${dir}/env"
  fi
  if [[ -f "${CONFIG_FILE_DEFAULT}" ]]; then
    install -m 0640 "${CONFIG_FILE_DEFAULT}" "${dir}/config.yaml"
  fi
  BACKUP_DIR="${dir}"
  log "backup created at ${BACKUP_DIR}"
}

rollback() {
  local dir="${BACKUP_DIR:-}"
  warn "update failed; attempting rollback"
  if [[ -z "${dir}" || ! -d "${dir}" ]]; then
    warn "no backup directory available; cannot rollback automatically"
    return
  fi
  if [[ -f "${dir}/vlf-gateway.bin" ]]; then
    install -m 0755 "${dir}/vlf-gateway.bin" "${BIN_PATH}" || warn "binary restore failed"
  fi
  if [[ -f "${dir}/env" ]]; then
    install -m 0640 "${dir}/env" "${ENV_FILE}" || warn "env restore failed"
  fi
  if [[ -f "${dir}/config.yaml" ]]; then
    install -m 0640 "${dir}/config.yaml" "${CONFIG_FILE_DEFAULT}" || warn "config restore failed"
  fi
  systemctl daemon-reload || true
  systemctl restart "${SERVICE_NAME}" || warn "rollback restart failed"
}

health_check() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "--dry-run set, skipping health check"
    return 0
  fi
  if [[ "${NO_RESTART}" -eq 1 ]]; then
    log "--no-restart set, skipping health check"
    return 0
  fi
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
      log "${SERVICE_NAME} is active"
      return 0
    fi
    sleep 1
  done
  warn "${SERVICE_NAME} did not become active within ${HEALTH_TIMEOUT}s"
  journalctl -u "${SERVICE_NAME}" --no-pager -n 200 >&2 || true
  return 1
}

run_inner_update() {
  local inner="${INSTALL_DIR_DEFAULT}/scripts/update.sh"
  if [[ -n "${VLF_INSTALL_DIR:-}" && -f "${VLF_INSTALL_DIR}/scripts/update.sh" ]]; then
    inner="${VLF_INSTALL_DIR}/scripts/update.sh"
  fi
  if [[ ! -f "${inner}" ]]; then
    # We were invoked from a fresh curl pipe before any clone exists; fall back
    # to the script next to us (this file lives in scripts/).
    local self_dir
    self_dir="$(cd "$(dirname "$0")" && pwd)"
    if [[ -f "${self_dir}/update.sh" ]]; then
      inner="${self_dir}/update.sh"
    fi
  fi
  [[ -f "${inner}" ]] || die "inner update.sh not found (looked in ${INSTALL_DIR_DEFAULT}/scripts and \$VLF_INSTALL_DIR)"

  local cmd=(bash "${inner}")
  if [[ -n "${VLF_REF:-}" ]]; then
    cmd+=(--ref "${VLF_REF}")
  fi
  if [[ -n "${VLF_REPO_URL:-}" ]]; then
    cmd+=(--repo "${VLF_REPO_URL}")
  fi
  if [[ -n "${VLF_INSTALL_DIR:-}" ]]; then
    cmd+=(--install-dir "${VLF_INSTALL_DIR}")
  fi
  if [[ "${#FORWARD_ARGS[@]}" -gt 0 ]]; then
    cmd+=("${FORWARD_ARGS[@]}")
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] would invoke:'
    printf ' %q' "${cmd[@]}"
    printf '\n'
    return 0
  fi
  "${cmd[@]}"
}

main() {
  parse_flags "$@"
  require_pinned_ref
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    require_root
    require_deps
  fi
  require_safe_env
  inject_safe_defaults
  make_backup

  if ! run_inner_update; then
    rollback
    die "update failed; rollback executed"
  fi

  if ! health_check; then
    rollback
    die "health check failed; rollback executed"
  fi

  log "gateway update complete (ref=${VLF_REF})"
}

main "$@"
