# VLF Transit Hop

`vlf-transit` is the universal extra-hop ingress for VLF deployments where the public endpoint must live on a separate transit node and the real `vlf-gateway` stays on an origin node.

## Topology

```text
client -> transit node (vlf-transit) -> origin node (vlf-gateway)
```

`vlf-transit` forwards these lanes without changing the VLF wire protocol:

- session TCP lane: public `443/tcp` -> origin `443/tcp`
- session UDP lane: public `443/udp` -> origin `443/udp`
- optional UDP alt lane: public `8443/udp` -> origin `443/udp`
- optional relay lane: public `8080/tcp` -> origin `8080/tcp`

## What to install where

### 1. Origin node

The origin node keeps running the regular VLF gateway.

If relay traffic must pass through the transit hop, prepare the origin node with an interactive command:

```bash
curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<REF>/scripts/transit-origin-prepare.sh | sudo bash -s -- --bind-host 0.0.0.0 --ufw
```

The script will ask for the transit node IP/CIDR when `--allow-source` is not passed.

Fully non-interactive form:

```bash
curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<REF>/scripts/transit-origin-prepare.sh | sudo bash -s -- --bind-host 0.0.0.0 --ufw --allow-source 203.0.113.10
```

What this does:

- rewrites `/etc/vlf-proto/config.yaml` `listen_http` to the bind you specify
- updates `/etc/vlf-proto/.env` so future gateway updates keep the same bind
- optionally adds a source-scoped UFW rule for the transit node
- restarts `vlf-gateway`

### 2. Transit node

Install the transit hop with an interactive command:

```bash
curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<REF>/scripts/transit-install.sh | sudo bash -s -- --ufw
```

The script will ask for the origin backend host when it is not passed.

Fully non-interactive form:

```bash
curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<REF>/scripts/transit-install.sh | sudo bash -s -- \
  --backend-host 198.51.100.20 \
  --backend-tcp-port 443 \
  --backend-udp-port 443 \
  --backend-relay-port 8080 \
  --port-tcp 443 \
  --port-udp 443 \
  --port-udp-alt 8443 \
  --relay-port 8080 \
  --metrics-listen 127.0.0.1:9091 \
  --ufw
```

Important flags:

- `--backend-host <host>`: required origin gateway host/IP in non-interactive mode
- `--backend-tcp-port <port>`: origin TCP lane, default `443`
- `--backend-udp-port <port>`: origin UDP lane, default `443`
- `--backend-relay-port <port>`: origin relay lane, default `8080`
- `--port-tcp <port>`: public TCP lane, default `443`
- `--port-udp <port>`: public UDP lane, default `443`
- `--port-udp-alt <port>`: public UDP alt lane, default `8443`, use `0` to disable
- `--relay-port <port>`: public relay lane, default `8080`
- `--no-relay`: disable relay forwarding on the transit node
- `--metrics-listen <addr>`: transit metrics bind, default `127.0.0.1:9091`
- `--ufw`: open the public transit ports in UFW
- `--force`: reinstall transit in place

## Update transit

```bash
curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<REF>/scripts/transit-update.sh | sudo bash -s --
```

`transit-update.sh` always redeploys through `transit-install.sh --force`, so code, config and systemd wiring stay in sync.

## Remove transit

```bash
curl -fsSL https://raw.githubusercontent.com/skalover32-a11y/VLF-Proto/<REF>/scripts/transit-uninstall.sh | sudo bash -s -- --purge
```

## Installed files

Transit install creates:

- binary: `/usr/local/bin/vlf-transit`
- config: `/etc/vlf-transit/config.yaml`
- env: `/etc/vlf-transit/.env`
- service: `/etc/systemd/system/vlf-transit.service`
- repo checkout: `/opt/vlf-proto-transit`

## Diagnostics

Transit node:

```bash
systemctl status vlf-transit --no-pager
journalctl -u vlf-transit -n 100 --no-pager
ss -lntup | egrep '(:443|:8443|:8080|:9091)\s'
curl -fsS http://127.0.0.1:9091/metrics | head
```

Origin node:

```bash
systemctl status vlf-gateway --no-pager
journalctl -u vlf-gateway -n 100 --no-pager
ss -lntup | egrep '(:443|:8080)\s'
```

## Rollout rule

For an extra-hop deployment, point client subscriptions at the transit node public endpoint, not at the origin node. The origin node remains the VLF backend; the transit node is just the ingress and forwarder.
