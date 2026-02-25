#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/vlf-proto/.env}"

fail() {
  echo "$1" >&2
  exit 1
}

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

require_non_empty() {
  local key="$1"
  local value="${!key:-}"
  if [[ -z "${value}" ]]; then
    fail "missing required env value: ${key}"
  fi
}

require_port_number() {
  local key="$1"
  local value="${!key:-}"
  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    fail "invalid numeric env value: ${key}"
  fi
}

if [[ ! -f "${ENV_FILE}" ]]; then
  fail "env file not found: ${ENV_FILE}"
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

require_non_empty "VLF_PUBLIC_IPV4"
require_non_empty "VLF_PORT_TCP"
require_non_empty "VLF_PORT_UDP"
require_non_empty "VLF_CLIENT_ID"
require_non_empty "VLF_CLIENT_SECRET"
require_port_number "VLF_PORT_TCP"
require_port_number "VLF_PORT_UDP"

host="${VLF_DOMAIN:-}"
if [[ -z "${host}" ]]; then
  host="${VLF_PUBLIC_IPV4}"
fi

relay_base="${VLF_RELAY_BASE_DOMAIN:-}"
if [[ -z "${relay_base}" ]]; then
  relay_base="${VLF_RELAY_BASE_IP:-}"
fi

printf '{\n'
printf '  "proto_gateway": {\n'
printf '    "host": "%s",\n' "$(json_escape "${host}")"
printf '    "ip_override": "%s",\n' "$(json_escape "${VLF_PUBLIC_IPV4}")"
printf '    "tcp_port": %s,\n' "${VLF_PORT_TCP}"
printf '    "udp_port": %s,\n' "${VLF_PORT_UDP}"
printf '    "tls_server_name": "%s",\n' "$(json_escape "${VLF_TLS_SERVER_NAME:-}")"
printf '    "client_id": "%s",\n' "$(json_escape "${VLF_CLIENT_ID}")"
printf '    "secret": "%s",\n' "$(json_escape "${VLF_CLIENT_SECRET}")"
printf '    "relay_base": "%s"\n' "$(json_escape "${relay_base}")"
printf '  }\n'
printf '}\n'
