#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/vlf-proto/.env}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "gateway env file not found: ${ENV_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

PUBLIC_IP="${VLF_PUBLIC_IPV4:-}"
DOMAIN="${VLF_DOMAIN:-}"
TLS_SNI="${VLF_TLS_SERVER_NAME:-}"
PORT_UDP="${VLF_PORT_UDP:-443}"
PORT_TCP="${VLF_PORT_TCP:-443}"
RELAY_PORT="${VLF_METRICS_PORT:-8080}"
CLIENT_ID="${VLF_CLIENT_ID:-gateway-client}"
CLIENT_SECRET="${VLF_CLIENT_SECRET:-}"
CERT_FILE="${VLF_CERT_FILE:-/etc/vlf-proto/tls.crt}"

if [[ -z "${PUBLIC_IP}" ]]; then
  PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi

PIN=""
if command -v openssl >/dev/null 2>&1 && [[ -f "${CERT_FILE}" ]]; then
  PIN="$(openssl x509 -in "${CERT_FILE}" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -binary 2>/dev/null \
    | openssl base64 -A 2>/dev/null || true)"
fi

echo "# ------------------------------------------------------------"
echo "# VLF client environment examples"
echo "# Source: ${ENV_FILE}"
echo "# ------------------------------------------------------------"
echo
echo "# IP-only mode (no hostname/SNI required)"
echo "export GATEWAY_HOST=${PUBLIC_IP}"
echo "export GATEWAY_PORT_UDP=${PORT_UDP}"
echo "export GATEWAY_PORT_TCP=${PORT_TCP}"
echo "export RELAY_BASE=http://${PUBLIC_IP}:${RELAY_PORT}"
echo "export VLF_CLIENT=${CLIENT_ID}"
echo "export VLF_SECRET=${CLIENT_SECRET}"
if [[ -n "${PIN}" ]]; then
  echo "export VLF_PIN_SPKI=${PIN}"
fi
echo
echo "# Example command"
echo "socks_client --server ${PUBLIC_IP} --port-udp ${PORT_UDP} --port-tcp ${PORT_TCP}"

if [[ -n "${DOMAIN}" ]]; then
  [[ -n "${TLS_SNI}" ]] || TLS_SNI="${DOMAIN}"
  echo
  echo "# Domain/SNI mode"
  echo "export GATEWAY_HOST=${DOMAIN}"
  echo "export GATEWAY_PORT_UDP=${PORT_UDP}"
  echo "export GATEWAY_PORT_TCP=${PORT_TCP}"
  echo "export RELAY_BASE=http://${DOMAIN}:${RELAY_PORT}"
  echo "export VLF_TLS_SERVER_NAME=${TLS_SNI}"
  echo "export VLF_CLIENT=${CLIENT_ID}"
  echo "export VLF_SECRET=${CLIENT_SECRET}"
  if [[ -n "${PIN}" ]]; then
    echo "export VLF_PIN_SPKI=${PIN}"
  fi
  echo
  echo "# Example command"
  echo "socks_client --server ${DOMAIN} --tls-server-name ${TLS_SNI} --port-udp ${PORT_UDP} --port-tcp ${PORT_TCP}"
fi
