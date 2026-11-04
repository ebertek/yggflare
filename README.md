# Yggflare

Yggflare is a self-hosted controller for **Cloudflare Access, Tunnel ingress and
DNS**. It reads Docker Compose declarations and private device inventories to detect
drift and, when explicitly enabled, reconcile managed resources.

It also provides vendor-neutral LAN discovery, a read-only inventory UI, Discord
alerts, Prometheus metrics and local backups.

**Default posture:** Cloudflare writes, orphan deletion and the web listener are
disabled. Discovery never changes authoritative DNS or inventory files.

## Quick start

### Requirements

- Linux host with Docker Compose and a supported Cloudflare account/Tunnel.
- A Docker socket, host networking and host D-Bus access for the supplied Compose deployment.
- Permission to run Nmap SYN scans.
- Private storage for configuration, state, backups and API credentials.

**Security:** Docker socket access is effectively host-root access, even when mounted
read-only. Run Yggflare only on a trusted host.

### 1. Configure your host

Use [compose.yaml](compose.yaml) and provide these values through its environment (for
example, a local `.env` file):

| Variable | Example | Purpose |
|---|---|---|
| `YGGFLARE_HOME` | `/srv/yggflare` | Host directory for configuration and persistent data |
| `YGGFLARE_MERGED_ROOT` | `/srv/compose` | Compose source tree to inspect, mounted read-only |
| `YGGFLARE_LAN_CIDR` | `192.168.40.0/23` | IPv4 discovery boundary |
| `YGGFLARE_DEVICES_CIDR` | `192.168.40.0/24` | Static device address allocation |
| `YGGFLARE_DOCKER_CIDR` | `192.168.41.0/24` | Docker service allocation |
| `YGGFLARE_INTERNAL_DOMAIN` | `home.example.net` | Internal DNS zone |
| `YGGFLARE_EXTERNAL_DOMAIN` | `services.example.net` | External Access/Tunnel zone |
| `CLOUDFLARE_ACCOUNT_ID` | Your account ID | Cloudflare account |
| `CLOUDFLARE_TUNNEL_ID` or `CLOUDFLARE_TUNNEL_NAME` | Your existing Tunnel | ID takes precedence |

The sample Compose file mounts the following paths:

| Container path | Content |
|---|---|
| `/config` | Private inventory and retained DNS declarations; read-only |
| `/compose-source` | Compose files; read-only |
| `/data` | Scan state, Cloudflare ownership and presentation snapshots |
| `/backup` | Backup archives |
| `/run/secrets` | Cloudflare token and optional Discord webhook |

Create `config/` , `data/` , `backup/` and `secrets/` inside `YGGFLARE_HOME` . Store
the Cloudflare token in `secrets/cloudflare_api_token` and the optional Discord URL in
`secrets/network_discord_webhook` (an empty file disables notifications).

The token needs read access to the selected Access, Tunnel and DNS resources. Grant
edit permissions only if you intend to enable reconciliation.

### 2. Create an inventory

Save `config/static-hosts.json`:

```json
{
  "version": 1,
  "hosts": [
    {
      "hostname": "printer.home.example.net",
      "ipv4": "192.168.40.35",
      "mac": "02:00:00:00:00:35",
      "description": "Office printer",
      "ports": [
        {"protocol": "tcp", "port": 9100, "description": "Printing"}
      ],
      "aliases": ["print.home.example.net"],
      "device_class": "printer"
    }
  ]
}
```

The inventory accepts 1–256 active hosts. Addresses must fall within the configured
device range, outside the Docker range and outside each /27 allocation's
network/broadcast addresses.

Optional fields include `observed_macs` , `additional_ipv4` , `interface_macs` ,
`serial_number` and `purchase_date` . See the
[inventory validator](src/cloudflare/cloudflare_static_dns.py) for exact rules.

Other optional files in `/config`:

- `static-hosts-reserved.json` and `retired-devices.json`: display-only catalogs.
- `retained-dns.json`: audit-only exceptions for existing internal DNS records. These never authorize writes.

### 3. Launch and verify

```sh
docker compose config --quiet
docker compose pull
docker compose up -d

docker exec yggflare yggflare --version
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
```

The commands work from any directory once the container is running. Review the first
Cloudflare audit before enabling writes.

## Configuration

`YGGFLARE_*` controls application behaviour. `CLOUDFLARE_*` selects Cloudflare
credentials and resources. Values exported only to your shell do **not** reach the
container unless the Compose `environment:` section forwards them.

| Variable | Default | Function |
|---|---|---|
| `YGGFLARE_VERSION` | `main` | Image tag in the supplied Compose file |
| `CLOUDFLARE_EXTERNAL_ZONE_ID` / `CLOUDFLARE_INTERNAL_ZONE_ID` | Resolve by domain | Optional explicit zone IDs |
| `CLOUDFLARE_API_TOKEN_FILE` | `/run/secrets/cloudflare_api_token` | Mounted token path |
| `CLOUDFLARE_STATIC_DNS_REQUIRED` | `true` | Require static inventory during audits |
| `CLOUDFLARE_STATIC_DNS_SYNC` | `false` | Include static DNS changes in writable plans |
| `YGGFLARE_CLOUDFLARE_AUTO_APPLY` | `false` | Enable guarded automatic reconciliation |
| `YGGFLARE_CLOUDFLARE_AUTO_BATCH_SIZE` | `3` | Automatic operations per cycle; `0` means all validated changes |
| `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP` | `false` | Enable owned-orphan retirement; also requires auto-apply |
| `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP_BATCH_SIZE` | `1` | Orphans retired per cycle; `0` means all eligible orphans |
| `YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS` | `24` | Continuous absence required before deletion; 24–720 |
| `YGGFLARE_NETWORK_ALERT_CONFIRM_SCANS` | `2` | Repeated scans before port/DNS-SD notifications; 1–10 |
| `YGGFLARE_WEB_ENABLED` / `YGGFLARE_METRICS_ENABLED` | `false` / `false` | Read-only HTTP UI and optional metrics |
| `YGGFLARE_WEB_BIND` / `YGGFLARE_WEB_PORT` | `127.0.0.1` / `8787` | Web listener |
| `YGGFLARE_LOG_FORMAT` | `text` | Timestamped text or newline-delimited JSON |
| `YGGFLARE_WATCH_COMPOSE` / `YGGFLARE_WATCH_DOCKER` | `true` / `true` | React to source and Docker topology changes |
| `YGGFLARE_WATCH_POLL_SECONDS` | `15` | Compose file polling interval |
| `YGGFLARE_WATCH_DEBOUNCE_SECONDS` | `20` | Wait for writes to settle |
| `YGGFLARE_WATCH_COOLDOWN_SECONDS` | `60` | Minimum interval between reactive audits |

Application defaults apply even when a setting is omitted. To override a value not
forwarded by the supplied Compose file, add it to that service's `environment:` .

## Cloudflare reconciliation

Compose Traefik `Host` rules and the `cf.access` / `cf.access.policies` labels
describe protected external services. The static inventory describes internal DNS.
Yggflare compares these declarations with live Cloudflare resources.

### Review and apply

```sh
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare cloudflare preflight
docker exec yggflare yggflare cloudflare plan
docker exec yggflare yggflare cloudflare apply APPROVAL_FINGERPRINT
```

Replace `APPROVAL_FINGERPRINT` with the fingerprint printed by `plan` . Apply checks
the live state again and rejects a changed plan. Manual approval works with automatic
reconciliation disabled.

Manual plans include all validated actions by default. To constrain an approval, use
matching `--max-operations N` values for both `plan` and `apply` .

When automatic apply is enabled, Yggflare validates the **complete plan** before
executing a batch. New protected hostnames are created in **Access → Tunnel route →
DNS** order. Yggflare adds routes to the configured Tunnel; it does not create new
Tunnel objects.

### Ownership and cleanup

Only proven Yggflare-managed resources are eligible for retirement. Existing resources
need an explicit claim after verifying the live configuration:

```sh
docker exec yggflare yggflare cloudflare claim host.services.example.net
```

Review removal of a claimed hostname with:

```sh
docker exec yggflare yggflare cloudflare orphan-plan host.services.example.net
docker exec yggflare yggflare cloudflare orphan-apply host.services.example.net APPROVAL_FINGERPRINT
```

Automatic cleanup requires **both** `YGGFLARE_CLOUDFLARE_AUTO_APPLY=true` and
`YGGFLARE_CLOUDFLARE_AUTO_CLEANUP=true` . A managed hostname must remain absent for at
least the configured grace period. Deletion proceeds **external DNS → Tunnel route →
Access app**, with live revalidation at each step.

Unmanaged hostnames are never deleted. Leave the cleanup batch size at `1` unless
you've independently verified desired-state accuracy and recovery. Setting it to `0`
permits bulk retirement.

## Network discovery and alerts

The daily IPv4 scan checks responsive non-Docker addresses using Nmap's popular ports
plus configured and declared TCP ports. Avahi supplies separate DNS-SD service
evidence. Scans never change DNS records or device declarations.

Optional ARP, NDP, IPv6 and OS discovery are limited to explicitly configured
interfaces and address ranges:

```yaml
YGGFLARE_DISCOVERY_INTERFACES: "eth0,eth1"
YGGFLARE_DISCOVERY_IPV6_CIDRS: "fd00:1234:5678::/64"
YGGFLARE_DISCOVERY_ARP_SCAN: "true"
YGGFLARE_DISCOVERY_NDP_PROBE: "true"
YGGFLARE_DISCOVERY_IPV6_SCAN: "true"
YGGFLARE_DISCOVERY_OS_DETECTION: "true"
```

All four switches default to `false` . IPv6 scanning never sweeps an entire /64. The
supplemental target budget defaults to 512 unique addresses per IP family
(`YGGFLARE_DISCOVERY_MAX_TARGETS`, 1–4096). Nmap processes targets in batches of at
most 64; this batch size is **not** a discovery cutoff.

Additional SSDP, NetBIOS, LLDP, SMB, SNMP and passive fingerprint sources are
described in [Discovery options](docs/discovery.md) . Only enable sources appropriate
to your network.

### Identity and history

Yggflare correlates inventory declarations, observed MACs, IPv4/IPv6 addresses and
discovery evidence. It retains first/last observed timestamps, address changes and an
identity timeline.

Confidence is **high**, **medium** or **low** based on corroborating evidence—not a
proof of ownership. IP-only sightings remain provisional. Conflicting MAC claims are
presented separately; DNS-SD names and OS guesses are hints, not identity keys.

A missing observation does **not** prove that a device is offline. Histories are
bounded and saved in `/data/network-inventory/state.json` .

### Notifications

Unknown devices and changed MAC/IP observations notify immediately. Newly open TCP
ports and new DNS-SD service identities require **two successful observations** by
default; setting `YGGFLARE_NETWORK_ALERT_CONFIRM_SCANS=1` restores immediate
reporting.

Unconfirmed findings remain visible in the UI. Changing a DNS-SD service's dynamic
port does not create a new identity. A failed notification doesn't lose a scan: queued
Discord messages are retried later.

## Web UI and Prometheus

Enable these values in the service's `environment:`:

```yaml
YGGFLARE_WEB_ENABLED: "true"
YGGFLARE_METRICS_ENABLED: "true"
YGGFLARE_WEB_BIND: "127.0.0.1"
YGGFLARE_WEB_PORT: "8787"
```

The read-only UI is available at `http://127.0.0.1:8787/` on the Docker host. It includes:

| Route | View |
|---|---|
| `/inventory` | Declared and observed devices, filters and export links |
| `/discovery` | Source evidence, identity confidence and unresolved conflicts |
| `/ports` | Observed services and DNS-SD announcements |
| `/diff` | Declared-versus-observed differences |
| `/drift` | Active findings, pending confirmations and timelines |
| `/reserved` / `/retired` | Display-only catalogs |
| `/cloudflare` | Managed, orphaned and unmanaged resource status |
| `/api/inventory.json` / `/api/inventory.csv` | Inventory exports |

`/metrics` exposes aggregate Prometheus gauges, scan timestamps and Cloudflare
snapshot health. It includes no device labels or credentials and triggers no scans. A
basic scrape configuration:

```yaml
- job_name: yggflare
  scrape_interval: 30s
  static_configs:
    - targets: ["YOUR_HOST_IP:8787"]
```

See the [Grafana dashboard](dashboards/yggflare.json) for an optional import.

**The UI has no built-in authentication.** Restrict direct TCP access with a firewall
or loopback binding. If you expose it through a proxy, secure the proxy **and**
prevent bypassing it on the LAN. Cloudflare Access on a hostname alone does not
protect the listener.

## Scheduling, backups and diagnostics

| Job | Default schedule |
|---|---|
| Cloudflare audit and optional reconciliation | Startup, relevant changes, and every six hours |
| Network scan | Daily at 05:15 UTC |
| Backup | Daily at 04:00 UTC; keep 14 snapshots |

Watchers trigger Cloudflare audits, not new LAN scans. The controller logs job names,
durations and outcomes, and handles shutdown signals without requiring Docker init.

```sh
docker logs --tail 100 yggflare
docker exec yggflare yggflare --version
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare network run
docker exec yggflare yggflare network discord-test
docker exec yggflare yggflare backup verify ARCHIVE.tar.gz
docker exec yggflare yggflare backup restore-test ARCHIVE.tar.gz
```

`doctor` validates local dependencies and mounted secrets without making Cloudflare
changes. `network run` saves observations and may send alerts. `discord-test` sends a
deliberate test notification.

Backups may contain **plaintext credentials**. Restrict access and retain an off-host
copy. `verify` checks an archive without extracting it; `restore-test` extracts into
isolated temporary storage without replacing live data.

## Releases and development

The image is `ghcr.io/ebertek/yggflare` . Available tags are `main` ,
`sha-FULL_COMMIT_SHA` and `vMAJOR.MINOR.PATCH` ; no `latest` tag is published. Pin the
image by digest in production.

Each published image identifies its Git revision in startup logs and through
`yggflare --version` . After an update, rerun `doctor` and `cloudflare audit` before
enabling writes.

See [AGENTS.md](AGENTS.md) for development and test commands. CI checks Python tests,
Ruff, Black and the Docker build.

Licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE).
