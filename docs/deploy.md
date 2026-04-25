# Deploy: gateway and transit (Phase-1 canary)

This document describes the safe, pinned, one-command update path for the two
production server roles: the main VLF gateway and the VLF transit (hop) node.

Both wrappers (`scripts/update-gateway.sh` and `scripts/update-transit.sh`) are
thin Phase-1 wrappers around the existing installer/updater scripts. They:

1. Hard-fail unless `VLF_REF` is set to a pinned tag or commit sha (no silent
   `main`).
2. Refuse to run if any Phase-1 risky transport flag is `=1` in the env file.
3. Append safe defaults (`...=0`) for missing risky flags - never overwriting
   operator-set values.
4. Snapshot the current binary, env file, and config to a timestamped backup
   directory under `/opt/vlf-proto/backups` (gateway) or
   `/opt/vlf-proto-transit/backups` (transit).
5. Delegate to the existing `scripts/update.sh` (gateway) or
   `scripts/transit-update.sh` (transit) for the actual git pull / build /
   `systemctl restart`.
6. Run a deterministic `systemctl is-active` health check after restart, with
   a configurable timeout.
7. On any failure, restore the previous binary + env + config from the backup
   directory and restart the service.

Phase-1 risky flags that must remain `0` (env file) / `false` (config YAML):

- `VLF_TRANSPORT_PROFILES_ENABLED` / `transport.transport_profiles_enabled`
- `VLF_PROFILE_SCORING_ENABLED` / `transport.profile_scoring_enabled`
- `VLF_PROFILE_MIGRATION_ENABLED` / `transport.profile_migration_enabled`
- `VLF_RESUME_TOKENS_ENABLED` / `transport.resume_tokens_enabled`

For the full rollout sequence and rollback criteria, see
`docs/canary-rollout.md`.

## Gateway: one-command update

```bash
curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<VLF_REF>/scripts/update-gateway.sh \
  | sudo VLF_REF=<VLF_REF> bash
```

Replace `<VLF_REF>` with a pinned tag or commit sha (e.g.
`vlf-proto-pre-canary-2026-04-25`). The wrapper exits with a clear error if
this variable is empty.

Optional flags forwarded to the inner `scripts/update.sh` are passed after
`--`. Example with explicit health-check timeout and forwarded port flags
during a bootstrap install:

```bash
sudo VLF_REF=<VLF_REF> bash scripts/update-gateway.sh --health-timeout 60 -- \
  --port-tcp 443 --port-udp 443 --port-udp-alt 8443 --metrics-addr 127.0.0.1
```

Dry-run (no root required, no changes applied):

```bash
VLF_REF=<VLF_REF> bash scripts/update-gateway.sh --dry-run
```

## Transit: one-command update

```bash
curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<VLF_REF>/scripts/update-transit.sh \
  | sudo VLF_REF=<VLF_REF> bash -s -- \
      --backend-host gateway.example.com \
      --backend-tcp-port 443 --backend-udp-port 443
```

Backend host/port flags after `--` are forwarded to `transit-update.sh` and in
turn to `transit-install.sh` when the host is being bootstrapped for the first
time. On an already-installed host they are ignored with a warning, matching
the existing transit-update behavior.

Dry-run:

```bash
VLF_REF=<VLF_REF> bash scripts/update-transit.sh --dry-run -- \
  --backend-host gateway.example.com
```

## Env file templates

Templates with risky flags explicitly set to `0` and only placeholder values
ship in the repo:

- `configs/gateway.env.example` - copy to `/etc/vlf-proto/.env`.
- `configs/transit.env.example` - copy to `/etc/vlf-transit/.env`.

These files contain only placeholders (`example.com`, `203.0.113.10`-style).
Real domains, IPs, client ids, and secrets are populated on the host and must
not be committed.

## Health check, backup, rollback

After a successful inner update the wrapper polls
`systemctl is-active --quiet <service>` for up to `VLF_HEALTH_TIMEOUT` seconds
(default `30`, configurable via `--health-timeout` or env). If the service
does not become active in time, or if the inner update itself fails, the
wrapper restores the snapshot taken before the update and runs
`systemctl restart <service>`.

The backup directory is printed to stdout on success and contains:

- `vlf-gateway.bin` / `vlf-transit.bin` (the previous binary)
- `env` (the previous env file)
- `config.yaml` (the previous gateway/transit config)

Old backups are not pruned automatically; rotate them out of band when needed.

## CI smoke

`.github/workflows/ci.yml` runs `bash -n` on every shell script under
`scripts/` and exercises the new wrappers in `--dry-run` mode so accidental
breakage of the deploy path is caught before merge.
