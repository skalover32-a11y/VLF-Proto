# Audit Status

A formal independent third-party security audit has not yet been completed.

This document tracks internal security review and audit readiness for the VLF Runtime Gateway.

## Current Status

| Area | Status |
| --- | --- |
| Formal third-party audit | Not completed |
| Internal self-assessment | In progress |
| Public review | Open |
| Replay/session review | TODO |
| Release/build review | TODO |

## Reviewed in This Documentation Pass

- Gateway repository layout.
- HTTP relay, QUIC session and TCP fallback design as described by code and README.
- HMAC auth and replay-protection scope.
- Session/frame/flow lifecycle at a high level.
- Metrics, Docker, installer and systemd hardening surfaces.

This is a self-assessment, not an independent audit.

## Review Checklist

- [ ] Frame parser bounds and oversized frame handling.
- [ ] Replay cache correctness and clock skew behavior.
- [ ] Session hijacking resistance.
- [ ] Resource exhaustion limits for sessions, flows, bytes and UDP datagrams.
- [ ] Unauthenticated control message handling.
- [ ] Transport downgrade or misrouting behavior.
- [ ] Metrics/log redaction for client IDs and destinations.
- [ ] Installer and systemd hardening review.
- [ ] Dependency review for `go.mod` and container base images.

## Future External Audit Plan

TODO: define target commit, test gateway, client matrix, protocol fixtures and disclosure process.
