# Privacy Overview

This repository implements a gateway/relay runtime and thin clients for VLF protocol experiments and deployments.

A formal independent third-party security audit has not yet been completed.

## What This Component Is

The gateway accepts authenticated client sessions and relays TCP/UDP flows through HTTP relay, QUIC session and TCP session fallback lanes. It also exposes metrics and smoke/benchmark tools.

## Data It May Process

- Client identifiers and HMAC authentication material.
- Session IDs, nonces, timestamps and replay-protection state.
- Destination hostnames, IP addresses and ports requested by clients.
- TCP stream payloads and UDP datagrams while relaying traffic.
- Metrics about bytes, flows, errors, drops and transport behavior.
- Runtime logs from gateway, clients, smoke tests and installers.
- TLS certificates and private keys generated or provided for gateway operation.

## Data It Should Not Publish

The project should not publish production client secrets, session tokens, raw user traffic, private keys, production domains, private IPs or real user identifiers in public logs or issues.

No traffic resale, traffic injection or ad injection is intended by project policy. This is a policy and implementation intent, not an externally audited fact.

## Logs and Diagnostics

Gateway logs and metrics are operational diagnostics. They may include client IDs, transport decisions, flow IDs, destination metadata, error reasons and rate-limit decisions. Do not treat logs as safe for public sharing without redaction.

## Third-Party Dependencies

The Go module uses dependencies including `quic-go`, Prometheus client libraries, `zap`, `gvisor` and WireGuard-related packages. Review `go.mod`, `go.sum`, `Dockerfile`, installer scripts and systemd unit generation before production use.

## Data Retention

This repository does not define server-side retention policy. See service-level privacy policy.

In-memory replay/session state is runtime state. External logs, Prometheus storage and host-level journal retention are controlled by deployment configuration.
