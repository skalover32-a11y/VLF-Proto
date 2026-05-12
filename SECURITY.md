# Security Policy

This repository contains the VLF Runtime Gateway and client-side protocol tools implemented in Go.

A formal independent third-party security audit has not yet been completed. The project is open to responsible disclosure and external review.

## Supported Versions and Branches

| Branch or version | Status |
| --- | --- |
| `main` | Supported for current development and security fixes |
| Latest deployed gateway built from this repository | Supported when the commit can be identified |
| Older experimental builds | Best-effort only |

TODO: define tagged release support windows after the deployment cadence is finalized.

## Reporting a Vulnerability

- Security contact: TODO: add public security contact
- Report privately first with affected commit, component, transport path and reproduction steps.
- Use synthetic client IDs and secrets. Do not send production gateway credentials or real user traffic.
- Redact tokens, HMAC secrets, client identifiers, private keys, production domains and private IP addresses.

Please do not publish exploit details, replay material, frame payloads or gateway credentials before coordination.

## Scope

In scope:

- Gateway lanes: HTTP relay, QUIC session and TCP session fallback.
- HMAC authentication, replay protection and client secret handling.
- Session lifecycle, flow management, frame parsing and UDP fragmentation.
- Rate/pps/flow limits and resource exhaustion protections.
- Prometheus metrics and health/diagnostic behavior.
- Installer scripts, Docker runtime and systemd hardening defaults.
- `socks_client`, `tun_client` and benchmark/smoke clients in this repository.

Out of scope unless caused by this code:

- social engineering;
- volumetric DDoS against deployed infrastructure;
- compromise of third-party hosting, DNS, TLS CA or package registries;
- attacks using leaked production secrets obtained outside this repository.

## Expected Response Process

1. Acknowledge and triage the report.
2. Reproduce on a test gateway with synthetic credentials.
3. Assess impact across relay, QUIC session and TCP session paths.
4. Prepare a fix, mitigation or documented limitation.
5. Coordinate disclosure timing where practical.

## Safe Harbor

Good-faith research is welcome when it avoids service disruption, data exfiltration and testing against accounts or gateways you do not control. This statement does not override applicable law or third-party provider rules.
