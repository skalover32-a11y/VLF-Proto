#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="${SCRIPT_DIR}/print-client-json.sh"

if [[ ! -f "${HELPER}" ]]; then
  echo "FAIL: helper not found: ${HELPER}" >&2
  exit 1
fi

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if ! grep -Fq "${needle}" <<<"${haystack}"; then
    echo "FAIL: ${message}" >&2
    exit 1
  fi
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

env_ip="${tmp_dir}/ip.env"
cat > "${env_ip}" <<'EOF'
VLF_PUBLIC_IPV4=198.51.100.10
VLF_DOMAIN=
VLF_TLS_SERVER_NAME=
VLF_PORT_TCP=443
VLF_PORT_UDP=8443
VLF_CLIENT_ID=smoke-client
VLF_CLIENT_SECRET=smoke-secret
VLF_RELAY_BASE_IP=http://198.51.100.10:8080
VLF_RELAY_BASE_DOMAIN=
EOF

json_ip="$(bash "${HELPER}" "${env_ip}")"
assert_contains "${json_ip}" '"host": "198.51.100.10"' "ip-only host fallback failed"
assert_contains "${json_ip}" '"ip_override": "198.51.100.10"' "ip_override mismatch"
assert_contains "${json_ip}" '"tcp_port": 443' "tcp_port mismatch"
assert_contains "${json_ip}" '"udp_port": 8443' "udp_port mismatch"
assert_contains "${json_ip}" '"tls_server_name": ""' "tls_server_name empty fallback failed"
assert_contains "${json_ip}" '"client_id": "smoke-client"' "client_id missing"
assert_contains "${json_ip}" '"secret": "smoke-secret"' "secret missing"
assert_contains "${json_ip}" '"relay_base": "http://198.51.100.10:8080"' "relay_base IP fallback failed"

env_domain="${tmp_dir}/domain.env"
cat > "${env_domain}" <<'EOF'
VLF_PUBLIC_IPV4=198.51.100.10
VLF_DOMAIN=gw.example.com
VLF_TLS_SERVER_NAME=sni.example.com
VLF_PORT_TCP=443
VLF_PORT_UDP=443
VLF_CLIENT_ID=smoke-client
VLF_CLIENT_SECRET=smoke-secret
VLF_RELAY_BASE_IP=http://198.51.100.10:8080
VLF_RELAY_BASE_DOMAIN=http://gw.example.com:8080
EOF

json_domain="$(bash "${HELPER}" "${env_domain}")"
assert_contains "${json_domain}" '"host": "gw.example.com"' "domain host override failed"
assert_contains "${json_domain}" '"tls_server_name": "sni.example.com"' "tls_server_name mismatch"
assert_contains "${json_domain}" '"relay_base": "http://gw.example.com:8080"' "relay_base domain override failed"

echo "PASS print-client-json smoke"
