# Threat Model

A formal independent third-party security audit has not yet been completed.

## Assets

- User traffic confidentiality.
- Client IDs and HMAC secrets.
- Session IDs, nonces and replay-protection state.
- Gateway TLS private keys and config files.
- Relay/session frame payloads.
- Metrics and logs.
- Build scripts, Docker images and installer output.

## Trust Boundaries

- Public gateway ports are untrusted.
- Authenticated sessions are trusted only after HMAC/replay validation.
- Relay, QUIC and TCP session lanes share gateway resources.
- Metrics and health endpoints should be trusted-network only.
- Deployed host config and TLS files are host-local secrets.

## Threats

- Credential leakage.
- Replay attacks.
- Session hijacking.
- Oversized frames or malformed payloads.
- Resource exhaustion through many sessions, flows, UDP packets or relay objects.
- Unauthenticated control messages.
- Transport downgrade or misrouting between QUIC, TCP session and relay fallback.
- Dependency or build compromise.
- Logging of client secrets or sensitive destination metadata.

## Mitigations Observed

- HMAC authentication with client ID, timestamp and nonce.
- Replay-protection package and TTL state.
- Session, flow, packet and byte limit packages.
- Separate relay/session code paths.
- Prometheus metrics for operational visibility.
- Installer systemd hardening defaults.

## Recommended Improvements

- Add protocol-level fuzz tests for frame decoding and relay payloads.
- Document exact replay cache guarantees.
- Add explicit maximum frame size and payload-size tests where missing.
- Add negative tests for unauthenticated control frames.
- Review metrics and logs for sensitive values.
- Define production secret rotation and incident response.

## Non-Goals

- DDoS absorption at infrastructure scale.
- Security guarantees for compromised clients or servers.
- Privacy policy for service-level retention outside this repository.
