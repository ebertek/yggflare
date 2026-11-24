# Yggflare

Yggflare is a self-hosted controller for **Cloudflare Access, Tunnel ingress and
DNS**. It reads Docker Compose declarations and private device inventories to detect
drift and, when explicitly enabled, reconcile managed resources.

It also provides vendor-neutral LAN discovery, a read-only inventory UI, Discord
alerts, Prometheus metrics and local backups.

**Default posture:** Cloudflare writes, orphan deletion and the web/MCP HTTP listeners are
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
executing a batch. For Access changes, the assigned reusable policies must include
at least one `allow` **or** `bypass` decision, followed by exactly one terminal
`deny`. Bypass deliberately skips Access authentication for matching requests:
review policy selectors carefully and never assume a policy is restricted from
its name alone. Reconciliation error messages identify the hostname and selected
policy decisions without exposing policy rules.

New protected hostnames are created in **Access → Tunnel route → DNS** order.
Yggflare adds routes to the configured Tunnel; it does not create new Tunnel
objects.

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
YGGFLARE_DISCOVERY_RA: "false"
YGGFLARE_DISCOVERY_IPV6_SCAN: "true"
YGGFLARE_DISCOVERY_OS_DETECTION: "true"
```

These optional collector switches default to `false`. IPv6 scanning never
sweeps an entire /64. `YGGFLARE_DISCOVERY_RA` optionally solicits router
advertisements on selected interfaces, recording scoped, read-only topology
evidence—not device identities or DNS inputs. The
supplemental target budget defaults to 512 unique addresses per IP family
(`YGGFLARE_DISCOVERY_MAX_TARGETS`, 1–4096). Nmap processes targets in batches of at
most 64; this batch size is **not** a discovery cutoff.

Additional SSDP, NetBIOS, LLDP, SMB, SNMP and passive fingerprint sources are
described in [Discovery options](docs/discovery.md). Only enable sources appropriate
to your network.

### Identity and history

Yggflare correlates inventory declarations, observed MACs, IPv4/IPv6 addresses and
discovery evidence. It retains first/last observed timestamps, address changes and an
identity timeline.

Confidence is **high**, **medium** or **low** based on corroborating evidence—not a
proof of ownership. IP-only sightings remain provisional. Conflicting MAC claims are
presented separately; DNS-SD names and OS guesses are hints, not identity keys.

A missing observation does **not** prove that a device is offline. Histories are
bounded and saved in `/data/network-inventory/state.json`.

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

The read-only UI is available at `http://127.0.0.1:8787/` on the Docker host.
`YGGFLARE_WEB_BIND` also accepts an explicit local IPv4 or IPv6 address, for example
`10.4.21.1` on a host-side interface. An unassigned address fails at startup;
hostnames are rejected. Keep loopback as the default.

An interface-specific bind reduces accidental exposure on other host addresses,
but **is not authentication or a substitute for firewall rules**. Confirm proxy
and Prometheus reachability before changing a production listener.

The interface includes:

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

## Model Context Protocol (MCP)

Yggflare includes a native, read-only MCP server for AI clients. It uses
the existing inventory presentation model and saved discovery and
Cloudflare lifecycle snapshots. Both stdio and optional Streamable HTTP
use the same twenty-four read-only tools. HTTP is disabled by default.

### Stdio transport

The stdio server runs when explicitly invoked:

```sh
docker exec -i yggflare yggflare mcp serve
```

Use `-i` without `-t`: stdout carries MCP protocol messages, not a
human-readable CLI. Authentication and transport security are provided
by the local Docker/SSH access boundary. Only trusted operators should
be allowed to run this command; Docker access is effectively root access.

Example VS Code user MCP configuration for a remote deployment (replace
the SSH host with an authorized host or SSH configuration alias):

```json
{
  "servers": {
    "yggflare": {
      "type": "stdio",
      "command": "ssh",
      "args": [
        "-T",
        "my-yggflare-host",
        "docker",
        "exec",
        "-i",
        "yggflare",
        "yggflare",
        "mcp",
        "serve"
      ]
    }
  }
}
```

SSH must support noninteractive authentication and the remote user must
already be authorized to execute Docker commands. Do not grant Docker
access solely to an untrusted MCP client. No MCP credentials are stored
in the repository.

| Tool | Purpose |
| --- | --- |
| `get_inventory_status` | Counts and snapshot freshness |
| `list_devices` | Search/paginate inventory, optionally unknown devices only |
| `get_device` | Exact address, MAC, hostname or alias and saved identity evidence |
| `get_inventory_drift` | Declared versus observed differences |
| `get_discovery_changes` | Recent saved discovery events |
| `get_cloudflare_lifecycle` | Saved DNS, Access and Tunnel resource presence |
| `get_service_exposure` | Correlate Docker aliases with saved Cloudflare lifecycle |
| `get_cloudflare_audit` | Saved proposed, blocked, static DNS and review-only DNS findings |
| `get_cloudflare_access` | Ordered decisions and expected assignment match, not selectors |
| `get_cloudflare_dns` | DNS metadata, numeric addresses and configured tunnel match |
| `get_cloudflare_tunnel` | Ordered routes and sanitized origin metadata, not connector health |
| `get_discovery_status` | Saved collector observation counts and freshness |
| `get_discovery_evidence` | Supplemental observations by address or source |
| `get_identity_conflicts` | Competing MAC/address evidence |
| `get_device_history` | Page retained identity records by ID, label, address or MAC |
| `get_identity_changes` | Retained identity timeline |
| `list_network_services` | Scan-confirmed ports and separate DNS-SD advertisements |
| `get_pending_network_findings` | Findings awaiting confirmation |
| `get_network_findings` | Latest reported stable finding keys |
| `get_yggflare_health` | Controller heartbeat and image revision |
| `get_job_status` | Last attempt and last success for scheduled jobs |
| `get_job_history` | Bounded scheduler execution history |
| `get_backup_status` | Local archive metadata and backup job status |
| `get_notification_status` | Saved pending delivery count; delivery remains unverified |

Job evidence is retained for the last 20 completed/unknown attempts per
scheduled job. A started attempt with no completion evidence is
`completion_unknown`, not a confirmed running or successful job. Archive
presence does not imply integrity or restoration; an empty notification queue
does not establish recipient receipt. These tools do not run diagnostics,
read archives, send notifications or execute jobs.

The audit snapshot is available after the next successful presentation refresh;
older snapshots report `audit_available=false` or
`configuration_available=false`. Access assignment match is not a proof of
safe selectors or policy enforcement. DNS payloads other than numeric addresses
are omitted; configured Tunnel targets are compared without returning IDs.
Origin userinfo, paths and queries are never returned. Findings are not executable
plans, omit policy IDs/selectors and arbitrary DNS payloads, and are capped at
2,000 with explicit truncation metadata. Supplemental source counts describe
observations, not collector coverage or success. Pending findings are distinct
from pending Discord deliveries. All list tools retain the 50-item page limit.

Tools do not run scans, call Cloudflare, trigger reconciliation, send
notifications, or change inventory. The inventory model may inspect local
Docker metadata using its existing sanitized projection. Results contain
private infrastructure metadata; only connect trusted clients. Cloudflare
lifecycle data does not prove external reachability or describe Access
policy selectors. Check freshness and pagination; missing observations
are not proof that a device is offline.

Inventory rows are service records, not a physical-device count. Docker
Compose project/service identity takes precedence over reused container
names. Explicitly resolved shared namespaces are distinguished from
ambiguous address matches; competing MAC evidence remains visible.
Observed addresses on a local macvlan interface can be identified using
kernel metadata when it does not contradict the saved MAC. The UI and
MCP projections do not alter discovery state or alert delivery.
`get_inventory_drift` accepts `severity="drift"` or `severity="unknown"`
and returns separate counts even when filtered. Recent findings indicate
whether their message is still in the latest reported findings; historical
absence does not prove recovery. Cloudflare ownership counts are not a
configuration drift or security assessment.

### Streamable HTTP transport

The optional listener is independent of the inventory web UI and serves
`/mcp`. The controller refreshes Cloudflare lifecycle snapshots when either
interface is enabled. HTTP is stateless with JSON responses; native clients
must send a bearer token. Browser origins are rejected (no browser CORS).

| Variable | Default | Purpose |
| --- | --- | --- |
| `YGGFLARE_MCP_ENABLED` | `false` | Start the HTTP listener at controller startup |
| `YGGFLARE_MCP_BIND` | `127.0.0.1` | Specific numeric local address; wildcard binds are rejected |
| `YGGFLARE_MCP_PORT` | `8788` | Dedicated MCP listener port |
| `YGGFLARE_MCP_TOKEN_FILE` | `/config/mcp-token.txt` | File containing a random bearer token |
| `YGGFLARE_MCP_ALLOWED_HOSTS` | Bind address and port (also localhost on loopback) | Optional comma-separated exact HTTP Host values |

Generate a secret in the private host-mounted configuration directory
before enabling HTTP. For the example Compose deployment:

```sh
umask 077
openssl rand -hex 32 > "$YGGFLARE_HOME/config/mcp-token.txt"
```

Enable `YGGFLARE_MCP_ENABLED=true` and recreate the container using your
normal deployment process. The listener refuses to start with a missing,
invalid or unreadable token, invalid configuration or occupied port.
Rotate the token by replacing the file and recreating the container.
The token is private and may be included in protected backup archives.

With default settings the URL is `http://127.0.0.1:8788/mcp` on the Docker
host. For access from a workstation use an SSH tunnel:

```sh
ssh -N -L 8788:127.0.0.1:8788 my-yggflare-host
```

Example VS Code configuration:

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "yggflare-mcp-token",
      "description": "Yggflare MCP bearer token",
      "password": true
    }
  ],
  "servers": {
    "yggflare": {
      "type": "http",
      "url": "http://127.0.0.1:8788/mcp",
      "headers": {
        "Authorization": "Bearer ${input:yggflare-mcp-token}"
      }
    }
  }
}
```

For a reverse proxy, use TLS, preserve the bearer authorization header,
restrict backend network access, and explicitly allow its forwarded Host
value. Never send the token over unencrypted remote HTTP. An explicit
non-loopback bind is an advanced option; firewall rules and TLS termination
are the operator's responsibility. OAuth and automatic proxy/Cloudflare
configuration are not included. No additional MCP tool permissions are
introduced.

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
docker exec yggflare yggflare network status
docker exec yggflare yggflare network status --details
docker exec yggflare yggflare network run
docker exec yggflare yggflare network discord-test
docker exec yggflare yggflare backup verify ARCHIVE.tar.gz
docker exec yggflare yggflare backup restore-test ARCHIVE.tar.gz
```

`doctor` validates local dependencies and mounted secrets without making Cloudflare
changes. `network status` reads the last completed scan, showing pending alerts and
identity counts without scanning, mutating state or sending notifications. Use
`network status --details` to inspect unresolved MAC conflicts or `--json` for
structured output. `network run` saves observations and may send alerts.
`discord-test` sends a deliberate test notification.

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
