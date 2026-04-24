# VLF Proto Canary Rollout

This rollout assumes the production gate has passed locally and in CI. Do not enable new transport features by default during the first rollout.

## Phase 0 - Preflight

- Wait for green GitHub Actions, especially `CGO_ENABLED=1 go test -race ./...` on Linux.
- Build release artifacts from a clean checkout.
- Save a rollback artifact or tag for the currently stable gateway, transit, and client versions.
- Record current stable versions and deployment refs for gateway, transit, Windows client, and Android client.
- Confirm production client config has `VLF_PRODUCTION=1` and a valid `VLF_PIN_SPKI`.

## Phase 1 - Gateway / Transit Only

- Update one gateway or transit node first.
- Keep profiles, scoring, migration, and resume disabled.
- Verify legacy client compatibility.
- Verify modern client compatibility.
- Watch auth failures, QUIC fallback behavior, relay metrics, process memory, and restart count.
- Send malformed/oversized frame smoke traffic in a controlled environment and confirm no memory spike.

## Phase 2 - Client Canary

- Enable production client mode only with:
  - `VLF_PRODUCTION=1`
  - `VLF_PIN_SPKI=<valid base64 sha256 SPKI pin>`
- Keep profiles, scoring, migration, and resume disabled.
- Use a canary group of 1-3 internal devices.
- Watch reconnects, idle recovery, QUIC close reasons, TCP fallback, memory, goroutines, and user-visible packet loss.

## Phase 3 - Profiles Only

- Enable profiles only for the canary group.
- Keep scoring, migration, and resume disabled.
- Verify mixed-peer rollout: legacy peers must continue on legacy auth/control behavior.
- Confirm no mandatory `PROFILE_*` dependency appears in normal traffic.

## Phase 4 - Scoring

- Enable scoring only after profiles canary is stable.
- Keep migration and resume disabled.
- Confirm scoring remains observational and does not create hidden migration traffic.
- Watch degradation reason flags for noisy or stale samples.

## Phase 5 - Migration / Resume

- Enable migration last, in a separate canary.
- Enable resume tokens after migration has a stable rollback path.
- Use separate rollback conditions for migration and resume.
- Confirm no profile switch spam, no resume replay accepts, and no false `resume_fast_path` reports.

## Rollback Criteria

Rollback immediately if any of these occur:

- Auth failures grow above baseline.
- QUIC fallback loop or reconnect loop appears.
- Process memory grows without returning to baseline.
- Goroutine count grows continuously.
- Reconnect failures increase for canary users.
- CI race gate fails.
- Production client starts without SPKI pin.
- Transit/gateway restart count increases after rollout.

## Features That Stay Off By Default

- `VLF_TRANSPORT_PROFILES_ENABLED=0`
- `VLF_PROFILE_SCORING_ENABLED=0`
- `VLF_PROFILE_MIGRATION_ENABLED=0`
- `VLF_RESUME_TOKENS_ENABLED=0`
- gateway `transport.transport_profiles_enabled=false`
- gateway `transport.profile_scoring_enabled=false`
- gateway `transport.profile_migration_enabled=false`
- gateway `transport.resume_tokens_enabled=false`
