# VLF Runtime Gateway (Relay + Session QUIC)

Production-grade MVP gateway in Go with two traffic lanes:

- `RELAY` lane: stateless-ish HTTP polling for TCP/web traffic.
- `SESSION` lane: QUIC session gateway with control TLV stream, TCP over QUIC streams, UDP over QUIC DATAGRAM (+ fragmentation).

## Repository layout

- `cmd/gateway` - main gateway binary
- `cmd/tcp-echo` - TCP echo service for smoke tests
- `cmd/udp-echo` - UDP echo service for smoke tests
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

- `gateway` (HTTP on `:8080`, QUIC/UDP on `:443`)
- `tcp-echo` (internal `:9000`)
- `udp-echo` (internal `:9001`)
- optional `prometheus` profile (`:9090`)

Gateway config in container: `config/config.yaml`.

## Smoke tests

Run after `docker compose up -d`.

Relay:

```bash
./scripts/relay_smoke.sh
```

Session (QUIC TCP+UDP):

```bash
go run ./scripts/session_smoke.go
# or
./scripts/session_smoke.sh
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

## Session lane (QUIC) v0.1

Transport:

- QUIC UDP (`listen_quic`, default `:443`)
- ALPN/protocol id from config (`protocol_id`, default `vlf-runtime/0.1`)
- QUIC DATAGRAM enabled

Model:

- one QUIC connection = one session
- one client-initiated bidi control stream for TLV commands
- TCP flow = dedicated client-initiated bidi stream
- UDP flow = QUIC DATAGRAM with fragmentation

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
- `tls.cert_path`, `tls.key_path`, `tls.auto_generate`
- `client_secrets` (MVP static map)
- `limits.*`
- `timeouts.relay_idle`, `timeouts.session_idle`, `timeouts.dial_timeout`
- `max_dgram_payload`

For development certs:

- when `tls.auto_generate: true`, gateway auto-generates self-signed cert if missing.

## HTTPS for Relay

Default dev config uses plain HTTP (`allow_insecure_http: true`).

To enforce HTTPS for relay:

1. Set `allow_insecure_http: false`.
2. Provide valid `tls.cert_path` and `tls.key_path`.
3. Restart gateway.

## Goroutine/resource shutdown checks

Gateway supports graceful shutdown for HTTP, QUIC sessions, relay connections, and TTL wheels.

Debug endpoint is available:

- `/debug/pprof/`
- `/debug/pprof/goroutine?debug=1`

You can compare goroutine counts before/after smoke runs and shutdown.

## Local (non-docker) validation used during implementation

Used config: `config/config.local.yaml`.

Validated commands:

- `go test ./...`
- `go run ./scripts/relay_smoke/main.go` (with local env)
- `go run ./scripts/session_smoke.go` (with local env)
- metrics scrape from `/metrics`.

## Acceptance criteria mapping

1. `docker compose up -d` starts gateway + echo services.
2. `./scripts/relay_smoke.sh` verifies relay open/send/recv/close.
3. `go run ./scripts/session_smoke.go` verifies AUTH + OPEN_TCP + OPEN_UDP + fragmentation.
4. clean shutdown paths implemented + pprof endpoint for goroutine checks.
5. `/metrics` exports required metrics; logs include request/session/flow identifiers.
