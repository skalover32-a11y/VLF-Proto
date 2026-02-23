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
   go run ./scripts/relay_smoke/main.go'
```

`scripts/relay_smoke/main.go` accepts `VLF_CLIENT` or `VLF_CLIENT_ID`, and `VLF_SECRET`.

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
- `VLF_PROTO_ID` (primary ALPN, default `vlf-runtime/0.1`)
- `VLF_PROTO_ID_COMPAT` (optional comma-separated extra ALPN ids for client compatibility)
- `VLF_DEBUG=1` enables detailed transport diagnostics (DNS, UDP probe, dial errors).
- `VLF_DISABLE_RELAY_FALLBACK=1` forces failure if QUIC/TCP session transports fail (useful for negative pin/auth tests).

## Protocol Bench (pre-alpha)

`cmd/proto_bench` runs real protocol traffic benchmarks through the VLF session client stack.

Implemented benchmark groups:

1. TCP throughput: opens `N` parallel TCP flows through session protocol and measures Mbps + p95/p99 RTT per chunk.
2. UDP PPS: opens UDP flow, sends at target PPS for `--duration` with burst pacing (`--udp-burst`), reports loss/jitter (seq-based).
3. Concurrency: runs `--clients` parallel sessions with TCP+UDP checks and handshake latency stats.
4. Fallback share: measures QUIC/TCP/relay distribution under current transport flags.
5. Soak: long-running repeated probes with `--soak=30m` / `2h`.

Run (Linux/macOS):

```bash
./scripts/run-bench.sh --clients 50 --duration 60s --tcp-mb 512 --udp-ps 5000 --udp-burst 10 \
  --tcp-min-mbps 1.0 --udp-max-loss 0.05 --udp-max-jitter-ms 50
```

`run-bench.sh` reads `scripts/.env` when present.

Run (Windows PowerShell):

```powershell
.\scripts\run-bench.ps1 -- --clients 50 --duration 60s --tcp-mb 512 --udp-ps 5000 --udp-burst 10 `
  --tcp-min-mbps 1.0 --udp-max-loss 0.05 --udp-max-jitter-ms 50
```

`run-bench.ps1` also imports `scripts/.env` by default.

Bench matrix runners (predefined combinations):

Linux/macOS:

```bash
./scripts/run-bench-matrix.sh
./scripts/run-bench-matrix.sh --duration 20s
```

Windows PowerShell:

```powershell
.\scripts\run-bench-matrix.ps1
.\scripts\run-bench-matrix.ps1 -Duration 20s
```

Matrix coverage:

- clients: `1`, `2`
- udp-pps: `300`, `600`, `900`, `1200`
- udp-payload-bytes: `256`, `1200`
- udp-burst: `10`
- tcp-flows: `1`, tcp-total-mb: `8`
- quality thresholds: `udp-max-loss=0.05`, `udp-max-jitter-ms=50`, `tcp-min-mbps=1`

Each matrix run writes reports to:

- `reports/<timestamp>/c<clients>_pps<udp-pps>_pl<udp-payload>/`
  - `proto_bench_report.json`
  - `proto_bench_report.md`
  - `console.log`

The matrix runner always continues after failed runs and prints PASS/FAIL summary at the end.

Direct Go run:

```bash
go run ./cmd/proto_bench --clients 50 --duration 60s
```

Output:

- stdout summary table (transport + throughput/latency/loss)
- `report.json` (default `proto_bench_report.json`)
- `report.md` (default `proto_bench_report.md`)
- optional metrics endpoint via `--metrics-listen :2112` (`/metrics`)
- if gateway metrics are reachable via `RELAY_BASE`, report also includes `server_udp_drop_reasons`

Important flags:

- `--target-tcp-host`, `--target-tcp-port` (defaults `tcp-echo:9000`)
- `--target-udp-host`, `--target-udp-port` (defaults `udp-echo:9001`)
- `--tcp-total-mb` (alias: `--tcp-mb`)
- `--udp-pps` (alias: `--udp-ps`)
- `--udp-burst` (default `10`, max packets per pacing tick for UDP PPS test)
- `--tcp-min-mbps` (default `1.0`, below threshold => TCP benchmark FAIL by quality)
- `--udp-max-loss` (default `0.05` = 5%, above threshold => UDP benchmark FAIL by quality)
- `--udp-max-jitter-ms` (default `50`, above threshold => UDP benchmark FAIL by quality)
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

## SOCKS5 Thin Client (TCP+UDP, pre-alpha)

Local SOCKS5 client for Windows/Linux that tunnels traffic via VLF session transport.

Implemented SOCKS5 features:

- auth methods:
  - `no-auth` (`0x00`)
  - `username/password` (`0x02`, RFC 1929)
- commands:
  - `CONNECT` (TCP)
  - `BIND` (practical implementation for compatibility)
  - `UDP ASSOCIATE`
- address types:
  - IPv4, domain, IPv6 in TCP requests and UDP headers
- UDP ASSOCIATE:
  - per-association UDP socket bind and returned bind address/port
  - SOCKS5 UDP header parse/encode (`RSV|FRAG|ATYP|DST.ADDR|DST.PORT|DATA`)
  - `FRAG=0` supported
  - `FRAG!=0` dropped with clear logs and counters
  - NAT table with reverse path (`VLF UDP flow <-> SOCKS UDP datagrams`)
  - idle cleanup and limits

Build:

```bash
go build ./cmd/socks_client
```

Run:

```bash
./socks_client --server <gateway-host> --server-ip <gateway-ip> --tls-server-name <gateway-host> --port-udp 8443 --port-tcp 443
```

Auth flags:

- `--auth none|userpass` (default `none`)
- `--username <u> --password <p>` for `--auth userpass`

UDP flags:

- `--udp-idle-timeout` (default `60s`)
- `--udp-max-associations` (default `128`)
- `--udp-max-nat` (default `4096`)

Gateway dial flags:

- `--server` logical gateway host (used for SNI by default)
- `--server-ip` optional direct dial IP/host override (recommended with sing-box TUN to avoid DNS loops)
- `--tls-server-name` optional SNI override
- `--resolve-once` (default `true`) resolves `--server` once at startup and pins the dial host
- if `--relay-base` is not specified, default is `http://<dial-host>:8080`

Metrics:

- `--metrics-listen 127.0.0.1:2113` (default enabled)
- Prometheus endpoint: `http://127.0.0.1:2113/metrics`
- key counters:
  - `vlf_socks_connect_total`
  - `vlf_socks_bind_total`
  - `vlf_socks_udp_associate_total`
  - `vlf_socks_auth_failures_total`
  - `vlf_socks_udp_packets_in_total`
  - `vlf_socks_udp_packets_out_total`
  - `vlf_socks_udp_active_associations`
  - `vlf_socks_udp_active_nat_entries`

Policy mode:

- `--mode auto|normal|fast|survival` (default `auto`)
- `auto` starts in `normal` and can switch:
  - to `fast` when a flow exceeds one of:
    - duration > `10s`
    - download > `64MB`
    - avg downrate > `20Mbps` over `5s`
  - to `survival` when:
    - QUIC failures >= `3` in `30s`
    - transport errors spike (windowed error threshold)
- in `auto` mode adaptive admission cap is applied when congestion is detected:
  - if RTT p95 > `250ms` for `2` consecutive stats ticks: enable cap
    - `max_new_flows_per_sec=2`
    - `max_active_flows=current+4`
  - if RTT p95 < `150ms` for `3` consecutive ticks: disable cap
- `survival` prefers TCP session/relay path over QUIC.

Live decisions and stats:

- mode/transport switches are logged with reasons
- RTT probe is sent every `1s` over active session transport (`PING`/`PONG` token echo)
- periodic stats every `10s`:
  - mode, last transport, active flows
  - total bytes up/down
  - windowed Mbps up/down/total
  - RTT p50/p95 from probe samples in the last `10s` window
  - switches count
  - adaptive cap state (`caps=...`)
- stats output format:
  - `--stats-format text` (default): human-readable log line
  - `--stats-format json`: one JSON line every `10s` to stdout with fields:
    - `mode`, `transport`, `active_flows`
    - `mbps_up`, `mbps_down`, `mbps_total`
    - `bytes_up`, `bytes_down`
    - `rtt_p50`, `rtt_p95`
    - `switches`
    - `caps` (present when cap is enabled)

Defaults:

- listen: `127.0.0.1:1080`
- transport order uses `internal/sessionclient` (`QUIC -> TCP session -> relay`, configurable by env/flags)
- auth defaults from env loader:
  - `VLF_CLIENT` / `VLF_CLIENT_ID`
  - `VLF_SECRET` (plain or `b64:...`)

Quick test:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

Expected: returned IP is gateway egress IP.

QUIC-blocked simulation:

```bash
./socks_client --server <gateway-host> --port 443 --mode auto --disable-quic
```

### sing-box outbound via VLF SOCKS

Example outbound (SOCKS5 + UDP capable):

```json
{
  "type": "socks",
  "tag": "vlf-socks",
  "server": "127.0.0.1",
  "server_port": 1080,
  "version": "5",
  "username": "vlf",
  "password": "vlfpass"
}
```

Run `socks_client` with matching auth:

```bash
./socks_client --listen 127.0.0.1:1080 --auth userpass --username vlf --password vlfpass \
  --server <gateway-host> --server-ip <gateway-ip> --tls-server-name <gateway-host> \
  --port-udp 8443 --port-tcp 443 --mode auto
```

One-window runner (Windows, combined logs for analysis):

```powershell
.\scripts\run-vlf-stack.ps1 `
  -GatewayHost troynichek-live.ru `
  -GatewayIP 5.180.46.33 `
  -SingBoxConfig .\config.json
```

What it does:

1. Starts `socks_client` and waits for `127.0.0.1:1080`.
2. Starts `sing-box` in the same PowerShell window.
3. Streams both process logs with prefixes (`SOCKS-*`, `SING-*`) to one console.
4. Writes run artifacts to `scripts/out/stack/<timestamp>/`:
   - `combined.log`
   - `socks_client.stdout.log`, `socks_client.stderr.log`
   - `sing_box.stdout.log`, `sing_box.stderr.log`
   - `run.json` (args, pids, start/end, exit codes)

Useful flags:

- `-Build` rebuilds `socks_client` before start
- `-SessionDebug` passes `--debug` to `socks_client`
- `-RunSeconds 120` auto-stop after 120s
- `-NoSingBox` run only `socks_client` (still with logging)
- `-NoPin` force-disable TLS pinning for this run (`VLF_PIN_SPKI` cleared in process env)
- `-PinSPKI "<base64>"` override pin value for this run

Troubleshooting for sing-box TUN (`no internet`, repeated UDP to `172.19.0.2:53`):

1. Ensure `socks_client` is running before `sing-box` and listening on `127.0.0.1:1080`.
2. Use `--server-ip <gateway-ip>` to avoid runtime DNS recursion through TUN.
3. In sing-box routing, keep gateway host/IP and `socks_client.exe` on `direct` detour to avoid loopback recursion.
4. Configure sing-box DNS explicitly; if DNS packets to `172.19.0.2:53` are forwarded into SOCKS, DNS will fail.

## TUN Mode (Windows, Stages 1-3)

`cmd/tun_client` provides full-system tunneling via Wintun + gVisor netstack.

Implemented stages:

- Stage 1: IPv4 TCP interception from TUN to VLF TCP flows.
- Stage 2: DNS interception (`UDP/53`) with upstream resolver forwarding.
- Stage 3: general UDP interception with per-flow NAT table and idle cleanup.

Current scope:

- Windows only
- IPv4 TUN path
- TCP + UDP via VLF session lane
- policy stack matches SOCKS client:
  - `--mode auto|normal|fast|survival`
  - RTT probe every `1s`
  - adaptive concurrency caps in `auto`
  - `--stats-format text|json`

Build:

```bash
go build ./cmd/tun_client
```

Run (Administrator PowerShell):

```powershell
.\tun_client.exe --server <gateway-host> --port-udp 8443 --port-tcp 443 --mtu 1350 `
  --dns-resolver 1.1.1.1:53 --udp-idle-timeout 60s --force-ipv4 true
```

Port flags:

- `--port-udp` for QUIC/UDP session lane.
- `--port-tcp` for TCP session lane fallback.
- legacy `--port` still works, but sets both ports to one value.
- `--force-ipv4` (default `true`) forces gateway control dials over IPv4, which avoids IPv6 route blackholes in current IPv4-only TUN mode.

What it configures:

- creates/reuses Wintun interface (`--tun-name`, default `VLF-TUN`)
- sets IPv4 address `198.18.0.2/15` and gateway `198.18.0.1`
- installs split default routes:
  - `0.0.0.0/1` via `198.18.0.1`
  - `128.0.0.0/1` via `198.18.0.1`
- adds explicit `/32` bypass route for resolved gateway server IP through the original route to avoid routing loops
- session dials are pinned to the resolved gateway IP (SNI stays `--server`), so runtime DNS outages do not break active tunneling
- on shutdown (Ctrl+C), removes added routes and interface IP settings
- DNS behavior:
  - with `--dns-override=true` (default), all intercepted UDP/53 is forwarded to `--dns-resolver` (default `1.1.1.1:53`)
  - if QUIC UDP path is unavailable, DNS requests fall back to DNS-over-TCP through VLF TCP flow
- UDP behavior:
  - per-flow NAT mapping (5-tuple based)
  - reverse path from VLF UDP flow back into TUN
  - idle timeout via `--udp-idle-timeout` (default `60s`)
  - if gateway QUIC UDP is rejected (e.g. ALPN mismatch), UDP tunnel attempts are backoff-limited to reduce error storms

Validation:

1. Start `tun_client` as Administrator.
2. Open Edge (no proxy settings).
3. Navigate to `https://api.ipify.org`.
4. Run `nslookup example.com`.
5. Optional UDP check (PowerShell):
   `Test-NetConnection -ComputerName 1.1.1.1 -Port 53 -InformationLevel Detailed`
6. Expected:
   - ipify returns gateway egress IP
   - DNS queries resolve successfully
   - UDP applications can exchange traffic through the tunnel

Troubleshooting:

- If startup fails with admin error, relaunch terminal elevated.
- If internet path looks broken after crash, restart `tun_client` and exit cleanly once, or remove routes manually:
  - `Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' | Remove-NetRoute -Confirm:$false`
- If QUIC is blocked in the network, run with fallback preference:
  - `.\tun_client.exe --server <gateway-host> --port 443 --mode auto --disable-quic`
- If interface creation fails, verify Wintun driver installation and endpoint security software policies.
- If DNS fails, explicitly set resolver and keep override enabled:
  - `.\tun_client.exe --dns-resolver 1.1.1.1:53 --dns-override true`
- If UDP apps are unstable, increase idle timeout:
  - `.\tun_client.exe --udp-idle-timeout 120s`

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
- gateway also accepts compatibility ALPN ids:
  - built-in: `vlf-runtime/0.1`, `vlf-session/0.1`
  - optional env: `VLF_PROTOCOL_ID_COMPAT=proto1,proto2`
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
- `session_datagram_workers`
- `session_datagram_queue`
- `max_bytes_per_minute_per_session`

## Observability

### Metrics

`GET /metrics` exposes Prometheus metrics, including:

- `vlf_active_sessions`
- `vlf_active_relay_conns`
- `vlf_bytes_in_total{lane="relay|session"}`
- `vlf_bytes_out_total{lane="relay|session"}`
- `vlf_udp_forwarded_total`
- `vlf_udp_packets_total` (backward-compatible alias of `vlf_udp_forwarded_total`)
- `vlf_udp_dst_rx_total`
- `vlf_udp_to_client_total`
- `vlf_udp_to_client_fail_total`
- `vlf_udp_pps`
- `vlf_recv_datagrams_total`
- `vlf_recv_bytes_total`
- `vlf_dropped_datagrams_total{reason}`
- `vlf_datagrams_processing_pps`
- `vlf_datagram_queue_length`
- `vlf_tcp_streams`
- `vlf_auth_failures_total`
- `vlf_replay_drops_total`
- `vlf_open_failures_total{lane,reason}`

`vlf_udp_pps` behavior:

- live forwarded PPS gauge (`client -> dst`) updated every second
- holds the last non-zero value for a short idle window
- drops to `0` after no forwarded traffic for `VLF_UDP_PPS_HOLD_SECONDS` (default `3`)

For monitoring/alerting, use the counter as canonical source:

```promql
rate(vlf_udp_forwarded_total[10s])
```

### Logs

JSON structured logs via `zap`.

Identifiers included:

- HTTP relay: `request_id`, `conn_id`
- Session lane: `session_id`, `flow_id`

With `log_level: debug`, session lane also prints per-second UDP datagram stats (processed dgrams/sec, queue length, drop reasons).

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

Optional env overrides:

- `VLF_UDP_PPS_HOLD_SECONDS` (default `3`) controls how long `vlf_udp_pps` stays non-zero after traffic stops.

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

## Bench Debugging Helpers

Server-side metric snapshots around a bench run:

```bash
./scripts/metrics-diff.sh before
# run proto_bench / matrix here
./scripts/metrics-diff.sh after
./scripts/metrics-diff.sh diff
```

Optional args:

- `./scripts/metrics-diff.sh before http://127.0.0.1:8080 /tmp/vlf_metrics`

Tracked counters:

- `vlf_recv_datagrams_total`
- `vlf_udp_forwarded_total`
- `vlf_udp_dst_rx_total`
- `vlf_udp_to_client_total`
- `vlf_udp_to_client_fail_total`
- `vlf_dropped_datagrams_total{reason=...}`

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
- `go build -o scripts/out/relay_smoke.exe ./scripts/relay_smoke/main.go`
- `go build -o scripts/out/session_smoke.exe ./scripts/session_smoke.go`
- metrics scrape from `/metrics`.

## Acceptance criteria mapping

1. `docker compose up -d` starts gateway + echo services.
2. `./scripts/relay_smoke.sh` verifies relay open/send/recv/close.
3. `go run ./scripts/session_smoke.go` verifies AUTH + OPEN_TCP + OPEN_UDP + fragmentation.
4. clean shutdown paths implemented + pprof endpoint for goroutine checks.
5. `/metrics` exports required metrics; logs include request/session/flow identifiers.
