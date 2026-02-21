# VLF Runtime Gateway (Relay + Session QUIC/TCP)

Production-grade MVP gateway in Go with two traffic lanes:

- `RELAY` lane: stateless-ish HTTP polling for TCP/web traffic.
- `SESSION` lane: primary QUIC session gateway with control TLV stream, TCP over QUIC streams, UDP over QUIC DATAGRAM (+ fragmentation).
- `SESSION TCP` lane: TLS/TCP fallback transport for session control + TCP flow data when UDP/QUIC is blocked.

## Repository layout

- `cmd/gateway` - main gateway binary
- `cmd/tcp-echo` - TCP echo service for smoke tests
- `cmd/udp-echo` - UDP echo service for smoke tests
- `cmd/proto_bench` - pre-alpha protocol benchmark tool
- `internal/relay` - Relay HTTP API v0.1
- `internal/session` - Session QUIC protocol v0.1
- `internal/auth` - HMAC auth + replay protection
- `internal/limits` - rate/pps/flow limits
- `internal/store` - in-memory state + TTL wheel
- `internal/metrics` - Prometheus metrics
- `internal/config` - YAML config loader + dev cert generation
- `scripts` - smoke tests
- `docker-compose.yml`
- `Dockerfile`

## Quick start (Docker)

```bash
docker compose up -d
```

Services:

- `gateway` (HTTP relay on `:8080`, session on `443:443` TCP + `443:443/udp`, optional extra `8443:443/udp` mapping to session UDP)
- `tcp-echo` (internal `:9000`)
- `udp-echo` (internal `:9001`)
- optional `prometheus` profile (`:9090`)

Gateway config in container: `config/config.yaml`.

## Smoke tests

Run after `docker compose up -d`.

`./vlf_e2e.sh` now asserts host TCP `:443` is exposed/listening using:

```bash
ss -ltnp | grep ':443'
```

Relay:

```bash
./scripts/relay_smoke.sh
```

Relay smoke directly from docker network (no host Go toolchain required):

```bash
NET=$(docker network ls --format '{{.Name}}' | grep -E 'vlf-proto|vlf' | head -n1)
docker run --rm --network "$NET" -v "$PWD":/src -w /src golang:1.24-alpine sh -lc \
  'apk add --no-cache git ca-certificates && \
   RELAY_BASE=http://gateway:8080 RELAY_DIAL_HOST=tcp-echo RELAY_DIAL_PORT=9000 \
   VLF_CLIENT=smoke-client VLF_SECRET=smoke-secret \
   go run ./scripts/relay_smoke.go'
```

`relay_smoke.go` accepts `VLF_CLIENT` or `VLF_CLIENT_ID`, and `VLF_SECRET`.

Session smoke (auto fallback: QUIC -> TCP session -> HTTP relay):

```bash
./scripts/session_smoke.sh
# or
go run ./scripts/session_smoke.go
```

Common session smoke env vars:

- `GATEWAY_HOST` (default `localhost`)
- `GATEWAY_PORT_UDP` (default `443`)
- `GATEWAY_PORT_TCP` (default `443`)
- `RELAY_BASE` (default `http://<GATEWAY_HOST>:8080`)
- `VLF_DEBUG=1` enables detailed transport diagnostics (DNS, UDP probe, dial errors).
- `VLF_DISABLE_RELAY_FALLBACK=1` forces failure if QUIC/TCP session transports fail (useful for negative pin/auth tests).

## Protocol Bench (pre-alpha)

`cmd/proto_bench` runs real protocol traffic benchmarks through the VLF session client stack.

Implemented benchmark groups:

1. TCP throughput: opens `N` parallel TCP flows through session protocol and measures Mbps + p95/p99 RTT per chunk.
2. UDP PPS: opens UDP flow, sends at target PPS for `--duration`, reports loss/jitter (seq-based).
3. Concurrency: runs `--clients` parallel sessions with TCP+UDP checks and handshake latency stats.
4. Fallback share: measures QUIC/TCP/relay distribution under current transport flags.
5. Soak: long-running repeated probes with `--soak=30m` / `2h`.

Run (Linux/macOS):

```bash
./scripts/run-bench.sh --clients 50 --duration 60s --tcp-mb 512 --udp-ps 5000
```

`run-bench.sh` reads `scripts/.env` when present.

Run (Windows PowerShell):

```powershell
.\scripts\run-bench.ps1 -- --clients 50 --duration 60s --tcp-mb 512 --udp-ps 5000
```

`run-bench.ps1` also imports `scripts/.env` by default.

Direct Go run:

```bash
go run ./cmd/proto_bench --clients 50 --duration 60s
```

Output:

- stdout summary table (transport + throughput/latency/loss)
- `report.json` (default `proto_bench_report.json`)
- `report.md` (default `proto_bench_report.md`)
- optional metrics endpoint via `--metrics-listen :2112` (`/metrics`)

Important flags:

- `--target-tcp-host`, `--target-tcp-port` (defaults `tcp-echo:9000`)
- `--target-udp-host`, `--target-udp-port` (defaults `udp-echo:9001`)
- `--tcp-total-mb` (alias: `--tcp-mb`)
- `--udp-pps` (alias: `--udp-ps`)
- `--prefer-quic`, `--disable-quic`, `--disable-tcp-session`, `--disable-relay-fallback`
- `--force-udp-block` (client-side QUIC disable mode to emulate blocked UDP path)
- `--soak`

Windows full test runner (dotenv + report generation):

```powershell
.\scripts\vlf-test-runner.ps1
```

The runner can build binaries with native Go or Dockerized Go toolchain (`BUILD=1` in `scripts/.env`).
It writes:

- `scripts/out/run_<timestamp>/report.json`
- `scripts/out/run_<timestamp>/report.md`
- `scripts/out/run_<timestamp>/runner.log.txt`

Legacy shortcut wrapper:

```powershell
.\scripts\test-vlf.ps1
```

Minimal Windows `.env` example (`scripts/.env`):

```dotenv
MODE=External
GATEWAY_HOST=troynichek-live.ru
GATEWAY_PORT_UDP=8443
GATEWAY_PORT_TCP=443
RELAY_BASE=http://troynichek-live.ru:8080
VLF_CLIENT_ID=smoke-client
VLF_SECRET=smoke-secret
# or: VLF_SECRET=b64:c21va2Utc2VjcmV0
VLF_PIN_SPKI=
BUILD=1
```

Expected output:

- `PASS relay smoke`
- `PASS session smoke`

## Relay lane API v0.1

Base path: `/v1/relay/*`

### Auth headers (required)

- `X-VLF-TS` - unix ms
- `X-VLF-Nonce`
- `X-VLF-Client`
- `X-VLF-Sig` - hex(HMAC_SHA256(secret, `method|path|ts|nonce|body_hash`))

`body_hash` is hex SHA-256 of raw request body.

Replay protection:

- nonce per `client_id` stored in TTL cache (`auth.replay_ttl`)
- repeated nonce rejected
- clock skew allowed: `±auth.clock_skew`

### Secret format (`client_secrets` and smoke clients)

HMAC secret handling is unified on server and clients:

- plain secret: `smoke-secret` -> UTF-8 bytes as-is
- base64 secret: `b64:<base64>` -> decoded bytes

Examples:

- `VLF_SECRET=smoke-secret`
- `VLF_SECRET=b64:c21va2Utc2VjcmV0`

### Endpoints

- `POST /v1/relay/open`
- `POST /v1/relay/send?conn_id=...`
- `GET /v1/relay/recv?conn_id=...&max=32768`
- `POST /v1/relay/ping?conn_id=...`
- `POST /v1/relay/close?conn_id=...`

Behavior details:

- each `conn_id` owns one outbound TCP socket
- downstream is fixed ring buffer (`max_recv_window_bytes`)
- `/recv` reads ring buffer in O(1) operations
- upstream send bursts are queued with bounded window (`relay_send_window_bytes`)
- idle TTL (`timeouts.relay_idle`) closes connection
- backpressure strategy: **downstream overflow closes connection** (`downstream_overflow`) to cap memory

## Session lane (QUIC + TCP fallback) v0.1

Transport:

- QUIC UDP (`listen_quic`, default `:443`)
- TLS/TCP (`listen_tcp`, default `:443`) for fallback transport
- ALPN/protocol id from config (`protocol_id`, default `vlf-runtime/0.1`)
- QUIC DATAGRAM enabled

Model:

- one session connection = one authenticated session
- one client-initiated bidi control stream for TLV commands
- TCP flow = dedicated client-initiated bidi stream
- UDP flow = QUIC DATAGRAM with fragmentation

Fallback order used by `scripts/session_smoke.go`:

1. QUIC (`GATEWAY_PORT_UDP`, default `443`)
2. TCP session (`GATEWAY_PORT_TCP`, default `443`)
3. HTTP relay fallback (`RELAY_BASE`)

### TLV frame format

- `type` = uvarint
- `len` = uvarint
- `payload[len]`

Frame types:

- `AUTH`, `AUTH_OK`, `AUTH_FAIL`
- `OPEN_TCP`, `OPEN_TCP_OK`, `OPEN_TCP_FAIL`
- `OPEN_UDP`, `OPEN_UDP_OK`, `OPEN_UDP_FAIL`
- `CLOSE_FLOW`
- `PING`, `PONG`
- `TCP_DATA` (used on TCP session transport for flow payload)

### AUTH payload

Fields:

- `client_id` (string)
- `ts_ms` (u64)
- `nonce` (12-32 bytes)
- `sig` (HMAC-SHA256 bytes)
- `caps` (u64)

Material for signature:

- `AUTH|client_id|ts_ms|nonce_hex|caps`

Server verifies signature + replay + skew and returns `AUTH_OK` with:

- `session_id`
- `expires_ms`
- limits (`up/down kbps`, `max_flows`, `max_udp_pps`)

### OPEN_TCP

`OPEN_TCP` payload:

- `flow_id` (u64)
- `dst_host` or `dst_ip`
- `dst_port` (u16)

`OPEN_TCP_OK` payload:

- `flow_id`
- `mode=1` meaning: client opens a new bidi stream now and sends first 8 bytes = `flow_id`.
- `mode=3` on TCP session transport meaning: flow data is exchanged via `TCP_DATA` frames on the control channel.

### OPEN_UDP

`OPEN_UDP` payload:

- `flow_id` (u64)
- `dst_host` or `dst_ip`
- `dst_port` (u16)

`OPEN_UDP_OK` payload:

- `flow_id`

### DATAGRAM payload

Raw format:

- `[flow_id:u64][flags:u8][seq:u32][payload...]`

Flags:

- `bit0`: fragmented
- `bit1`: last_fragment

`max_dgram_payload` is configurable (default `1200`).

Fragmentation is implemented in both directions:

- client -> server
- server -> client

Reassembly is per `(flow_id, seq)` with short TTL cleanup.

## Limits

Configured in `limits` section:

- `max_conns_per_client`
- `max_total_conns`
- `max_bytes_per_minute_per_client`
- `max_recv_window_bytes`
- `relay_send_window_bytes`
- `max_flows_per_session`
- `max_udp_pps`
- `max_bytes_per_minute_per_session`

## Observability

### Metrics

`GET /metrics` exposes Prometheus metrics, including:

- `vlf_active_sessions`
- `vlf_active_relay_conns`
- `vlf_bytes_in_total{lane="relay|session"}`
- `vlf_bytes_out_total{lane="relay|session"}`
- `vlf_udp_pps`
- `vlf_tcp_streams`
- `vlf_auth_failures_total`
- `vlf_replay_drops_total`
- `vlf_open_failures_total{lane,reason}`

### Logs

JSON structured logs via `zap`.

Identifiers included:

- HTTP relay: `request_id`, `conn_id`
- Session lane: `session_id`, `flow_id`

## Config

Main file: `config/config.yaml`

Key fields:

- `listen_http`
- `listen_quic`
- `listen_tcp`
- `tls.cert_path`, `tls.key_path`, `tls.auto_generate`
- `client_secrets` (MVP static map)
- `limits.*`
- `timeouts.relay_idle`, `timeouts.session_idle`, `timeouts.dial_timeout`
- `max_dgram_payload`

Gateway docker setup mounts `./certs` to `/app/certs` and uses:

- `tls.cert_path: /app/certs/gateway.crt`
- `tls.key_path: /app/certs/gateway.key`

For development certs:

- when `tls.auto_generate: true`, gateway auto-generates self-signed cert if missing.

Generate your own self-signed cert (recommended for reproducible pinning):

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/gateway.key \
  -out certs/gateway.crt \
  -days 365 \
  -subj "/CN=gateway" \
  -addext "subjectAltName=DNS:gateway,DNS:localhost,IP:127.0.0.1"
```

Compute SPKI pin (`sha256(SPKI DER)` in base64):

```bash
PIN=$(openssl x509 -in certs/gateway.crt -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A)
echo "$PIN"
```

Run session smoke in pin mode:

```bash
VLF_PIN_SPKI="$PIN" ./scripts/session_smoke.sh
```

Run session smoke in insecure mode (default):

```bash
./scripts/session_smoke.sh
```

## HTTPS for Relay

Default dev config uses plain HTTP (`allow_insecure_http: true`).

To enforce HTTPS for relay:

1. Set `allow_insecure_http: false`.
2. Provide valid `tls.cert_path` and `tls.key_path`.
3. Restart gateway.

## Linux UDP buffer tuning (recommended for QUIC)

`quic-go` benefits from larger UDP socket buffers. On Linux hosts:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
sudo sysctl -w net.core.rmem_default=262144
sudo sysctl -w net.core.wmem_default=262144
```

Persist via `/etc/sysctl.d/*.conf` in production.

## Goroutine/resource shutdown checks

Gateway supports graceful shutdown for HTTP, QUIC sessions, relay connections, and TTL wheels.

Debug endpoint is available:

- `/debug/pprof/`
- `/debug/pprof/goroutine?debug=1`

You can compare goroutine counts before/after smoke runs and shutdown.

## Local (non-docker) validation used during implementation

Used config: `config/config.local.yaml`.

Validated commands:

- `go test ./internal/auth`
- `go build ./cmd/gateway`
- `go build -o scripts/out/relay_smoke.exe ./scripts/relay_smoke.go`
- `go build -o scripts/out/session_smoke.exe ./scripts/session_smoke.go`
- metrics scrape from `/metrics`.

## Acceptance criteria mapping

1. `docker compose up -d` starts gateway + echo services.
2. `./scripts/relay_smoke.sh` verifies relay open/send/recv/close.
3. `go run ./scripts/session_smoke.go` verifies AUTH + OPEN_TCP + OPEN_UDP + fragmentation.
4. clean shutdown paths implemented + pprof endpoint for goroutine checks.
5. `/metrics` exports required metrics; logs include request/session/flow identifiers.
