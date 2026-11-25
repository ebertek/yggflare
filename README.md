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

### Operator views

The Web UI includes **Docker services**, **Topology**, **Cloudflare audit** and
**Operations** tabs. These expose the same bounded, sanitized query results as
MCP, including ingress correlation, job history, backup and notification
evidence. Filter the current page or follow its pagination links; observed
service names and other evidence are untrusted text.

Equivalent container CLI commands (append `--json` for structured output):

```sh
docker exec yggflare yggflare services list
docker exec yggflare yggflare services show SERVICE --project PROJECT
docker exec yggflare yggflare services drift
docker exec yggflare yggflare services dependencies SERVICE
docker exec yggflare yggflare services ingress HOSTNAME
docker exec yggflare yggflare network topology
docker exec yggflare yggflare cloudflare status
docker exec yggflare yggflare cloudflare dns HOSTNAME
docker exec yggflare yggflare cloudflare access HOSTNAME
docker exec yggflare yggflare cloudflare tunnel HOSTNAME
docker exec yggflare yggflare system status
docker exec yggflare yggflare system jobs
docker exec yggflare yggflare system history
docker exec yggflare yggflare backup status
docker exec yggflare yggflare network notifications
```

List views return at most 50 records; use `--offset` with the returned
`next_offset`. These commands read evidence only; the existing
`cloudflare audit`, `network run`, and explicit backup verification commands
retain their separate behavior. Protect direct Web UI access with network
firewall restrictions as well as reverse-proxy authentication.

### Traefik runtime evidence

Optional read-only Traefik collection is disabled unless
`YGGFLARE_TRAEFIK_API_URL` is configured as a numeric HTTP(S) origin in
the configured LAN CIDR or on loopback. Use an already restricted internal
API endpoint; do not enable an insecure/public dashboard for this feature.
HTTPS uses normal certificate verification. No credentials, redirects,
proxies, arbitrary paths or client-selected endpoints are supported.
Every five minutes the controller collects the documented HTTP/TCP/UDP
list endpoints (including pagination); Traefik's terminal
`X-Next-Page: 1` is handled explicitly, including exactly full final
pages. Invalid continuations, duplicate rows and exceeded bounds fail
closed. Failed collection retains the last complete snapshot and marks
it unverified. Logs identify the fixed endpoint and page with a sanitized
failure category, never raw API content. See the
[Traefik API documentation](https://doc.traefik.io/traefik/reference/install-configuration/api-dashboard/).

```sh
docker exec yggflare yggflare traefik refresh
docker exec yggflare yggflare traefik status
docker exec yggflare yggflare traefik routes
docker exec yggflare yggflare traefik services
docker exec yggflare yggflare traefik middlewares
```

The Traefik Web UI tab, aggregate Prometheus metrics and MCP tools read saved observations only; explicit
CLI refresh is the only interactive collection action. Router literal host
mentions do not establish rule evaluation or external reachability. Backend
URL paths, queries, userinfo, raw middleware settings and error messages are
excluded. Configuration is optional and should be enabled only after
validating the API's reachability and access restrictions.

### Komodo and Uptime Kuma

Both optional collectors run every five minutes when configured and keep
the last complete snapshot on failure. They accept numeric LAN/loopback
origins only. HTTPS verifies certificates; LAN HTTP requires an explicit
`YGGFLARE_KOMODO_ALLOW_HTTP=true` or `YGGFLARE_KUMA_ALLOW_HTTP=true`
opt-in (credentials would traverse the LAN in plaintext). Prefer a restricted
TLS endpoint and do not use an administrator credential.

| Adapter | Origin setting | Docker secret file setting and fixed path |
|---|---|---|
| Komodo | `YGGFLARE_KOMODO_API_URL` | `YGGFLARE_KOMODO_API_KEY_FILE=/run/secrets/komodo_api_key` |
| Komodo | | `YGGFLARE_KOMODO_API_SECRET_FILE=/run/secrets/komodo_api_secret` |
| Kuma | `YGGFLARE_KUMA_API_URL` | `YGGFLARE_KUMA_API_KEY_FILE=/run/secrets/kuma_api_key` |

Create a Komodo service user with read permission only on intended servers,
stacks and deployments. Use a dedicated Kuma Prometheus API key. Never
commit credentials to this repository or pass values on the command line.
Prefer Docker Compose secrets mounted at the fixed paths above. The
explicit file settings accept only their corresponding paths. Docker
file-backed secrets are read-only bind mounts; Git/Compose may expose
source mode 0644 rather than 0600. Yggflare accepts these modes only for
explicit Docker secrets on read-only mounts, and rejects nonregular files,
symlinks, group/world writable files, and invalid or oversized contents.

For the standalone Compose example, add a local override granting the
desired secrets, for example:

```yaml
services:
  yggflare:
    environment:
      YGGFLARE_KOMODO_API_KEY_FILE: /run/secrets/komodo_api_key
      YGGFLARE_KOMODO_API_SECRET_FILE: /run/secrets/komodo_api_secret
      YGGFLARE_KUMA_API_KEY_FILE: /run/secrets/kuma_api_key
    secrets:
      - komodo_api_key
      - komodo_api_secret
      - kuma_api_key
secrets:
  komodo_api_key:
    file: ./private/komodo_api_key
  komodo_api_secret:
    file: ./private/komodo_api_secret
  kuma_api_key:
    file: ./private/kuma_api_key
```

Keep the source files private on the host. Compose file-backed secrets
are not encrypted at rest and do not enforce uid/gid/mode overrides.
Recreate the container after updating a file-backed secret, especially
when the host file was replaced atomically.

If a file setting is unset, the previous private `/config/komodo-api-key.txt`,
`/config/komodo-api-secret.txt` or `/config/kuma-api-key.txt` file remains
supported and must be inaccessible to group/other users (e.g. mode 0600).
An explicitly configured missing or invalid Docker secret never falls
back to a config file.
The only Komodo calls are documented read RPCs ListServers, ListStacks and
ListDeployments; Kuma uses GET /metrics. No redirects, proxy environment,
raw configuration, URLs with credentials, logs or mutation API calls.
See [Komodo API](https://komo.do/docs/ecosystem/api) and
[Kuma Prometheus API keys](https://github.com/louislam/uptime-kuma/wiki/Prometheus-API-Keys).
The available resources are limited by credential permissions and the
exporter; no exact host match does not prove absence of monitoring.
Kuma's endpoint does not prove notification configuration or receipt.

The Komodo and Monitoring Web UI tabs, MCP queries and aggregate metrics
consume saved snapshots. Explicit operator refresh is separate.

```sh
docker exec yggflare yggflare komodo refresh
docker exec yggflare yggflare komodo status
docker exec yggflare yggflare komodo servers
docker exec yggflare yggflare komodo stacks
docker exec yggflare yggflare komodo services
docker exec yggflare yggflare komodo deployments
docker exec yggflare yggflare kuma refresh
docker exec yggflare yggflare kuma status
docker exec yggflare yggflare kuma monitors
docker exec yggflare yggflare kuma coverage --project PROJECT
```

### Independent connectivity evidence

Enable `YGGFLARE_PROBES_ENABLED=true` only after creating the private
`/config/probes.json` allowlist or a read-only Docker Compose config mounted
at `/yggflare-probes.json` with `YGGFLARE_PROBES_CONFIG_FILE=/yggflare-probes.json`.
Prefer the latter for GitOps: it avoids copying into the private config directory.
An explicitly configured missing, writable or invalid mount fails closed;
no fallback to the legacy file. Recreate the container after replacing the
source file. Example schema (illustrative addresses only):

```json
{
  "version": 1,
  "targets": [
    {
      "name": "internal-web",
      "hostname": "demo.example.invalid",
      "address": "192.168.1.20",
      "port": 443,
      "scheme": "https",
      "checks": ["dns", "tcp", "tls", "http"],
      "expected_statuses": [200, 302]
    }
  ]
}
```

At most 16 explicit targets and four checks per target are supported.
Numeric addresses must belong to the configured LAN/IPv6 CIDRs or loopback.
DNS uses the host resolver; TCP/TLS/HTTP connect directly to the numeric
address and do not follow DNS answers. TLS uses the normal trust store and
hostname validation. HTTP sends HEAD / only, no credentials, redirects,
body reads or arbitrary path. The five-minute collector has a 120-second
overall deadline and bounded socket timeouts. Failure preserves the last
complete snapshot. An HTTP response (including 302/401) is not proof of
Access enforcement or external reachability.

```sh
docker exec yggflare yggflare probes refresh
docker exec yggflare yggflare probes status
docker exec yggflare yggflare probes results
```

The Web UI Probes tab, aggregate metrics and MCP read saved evidence only.

### Finding lifecycle and evidence quality

The Findings tab and `yggflare network findings` / `network transitions`
read structured history from the saved network scan. Stable IDs are derived
from finding identity, not the notification text. History begins with the
first post-upgrade observation; legacy first-seen dates are not invented.
At most 1,024 findings and 256 transitions are retained; active observations
are prioritized, and truncation is reported. A failed browse does not
advance DNS-SD last-seen timestamps. Missing observations are not proof of
repair; an inventory match requires positive matching observation against
the current declaration. These presentation records never control alerts.

The Operations tab's Source evidence quality view and
`yggflare system evidence --json` distinguish freshness, last collection
verification, completeness and availability. Freshness thresholds reflect
the expected schedule, not guaranteed execution. Optional collectors now
also appear in scheduler history. New aggregate metrics describe finding
history and optional job outcomes.

```sh
docker exec yggflare yggflare network findings --json
docker exec yggflare yggflare network transitions --json
docker exec yggflare yggflare system evidence --json
```

Web pagination links carry the previous result-set fingerprint. CLI users
may pass `--snapshot-id` with `--offset` to reject changed result sets.
This fingerprint is not a frozen server-side snapshot or source timestamp.
Every paged MCP tool also accepts its own optional `snapshot_id` alongside
`offset` and `limit`. Reuse the same filters and restart on a mismatch.
Paged structured output includes the versioned, typed pagination envelope
and source-specific context; row fields remain adapter-specific.

## Model Context Protocol (MCP)

Yggflare includes a native, read-only MCP server for AI clients. It uses
the existing inventory presentation model and saved discovery and
Cloudflare lifecycle snapshots. Both stdio and optional Streamable HTTP
use the same forty-eight read-only tools. HTTP is disabled by default.

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
| `get_backup_status` | Local archive metadata, job status and recorded explicit verification |
| `get_notification_status` | Saved queue depth and webhook submission evidence |
| `list_docker_services` | Compose and local runtime services, including non-LAN services |
| `get_docker_service` | Exact project-scoped service or endpoint lookup |
| `get_compose_drift` | Candidate image, address, health and presence discrepancies |
| `get_service_dependencies` | Declared dependencies and shared-network evidence |
| `get_ingress_evidence` | Cross-source ingress, candidate deployment and monitor matches, local probe observations |
| `get_ingress_path` | Correlate exact service aliases with saved Cloudflare configuration |
| `get_network_topology` | Declared and local runtime network memberships and resolved namespace ownership |
| `get_traefik_status` | Saved Traefik snapshot availability, freshness and counts |
| `list_traefik_routes` | HTTP/TCP/UDP router identities and literal host mentions |
| `list_traefik_services` | Sanitized backend origins and reported status |
| `list_traefik_middlewares` | Middleware identity, type and status only |
| `get_komodo_status` | Saved Komodo collection state |
| `list_komodo_servers` | Reported server identities and states |
| `list_komodo_stacks` | Stack ownership, state and deployed/latest commit hashes |
| `list_komodo_services` | Stack service image/update metadata |
| `list_komodo_deployments` | Standalone deployment state and image metadata |
| `get_kuma_status` | Saved monitor collection state |
| `list_kuma_monitors` | Exported status and sanitized target host/port |
| `get_monitoring_coverage` | Candidate exact host matches, not verified per-service coverage |
| `get_probe_status` | Independent probe snapshot status |
| `list_probe_results` | Saved scoped DNS/TCP/TLS/HTTP outcomes |
| `list_finding_history` | Retained structured observations and lifecycle status |
| `list_finding_transitions` | Bounded historical status transitions |
| `get_evidence_overview` | Typed source freshness, availability and completeness |

Service topology uses a separate 30-second sanitized cache. It includes host
and bridge-only declarations without inventing LAN addresses. Local Docker
evidence does not establish remote deployment state; inactive profiles or
remote declarations may explain absence. Image reference equality does not
establish image digest equality. Ingress correlation is not a live Traefik
or reachability check.

Job evidence is retained for the last 20 completed/unknown attempts per
scheduled job. A started attempt with no completion evidence is
`completion_unknown`, not a confirmed running or successful job. Archive
presence does not imply integrity or restoration; an empty notification queue
does not establish recipient receipt. Existing explicit backup verify/restore-test
commands record the latest check outcome of each kind, tied to the unchanged
archive's file identity and timestamps. Changed or different archives have
unknown evidence; off-host retention and application recovery remain unverified.
Network scans record webhook attempts and successful submissions, not receipt.
The metrics endpoint exposes fixed scheduler attempt/success/completion-unknown
series and the last successful webhook submission timestamp. These tools do not run diagnostics,
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
from pending Discord deliveries. All list tools retain the 50-item page limit and return a projected result-set
fingerprint (`snapshot_id`). Pages may be shorter than requested due to the
256 KiB row budget; follow `next_offset`. `list_docker_services` and
`get_network_topology` accept the previous snapshot ID and reject changed
results. Other callers can compare IDs themselves.

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

### Resources, prompts and tool groups

Both transports expose fixed JSON resources (`yggflare://schema`, inventory,
operations, jobs, discovery, traefik, komodo, monitoring, probes) and six
review prompts where their required tools are enabled. No arbitrary paths,
live collectors or actions are exposed. Clients may still use tools directly.

`YGGFLARE_MCP_TOOL_GROUPS` defaults to `all`. Set a comma-separated subset
of `inventory,cloudflare,operations,traefik,komodo,kuma,probes` to restrict
registered tools, resources and prompts for that server process. Cross-source
queries require all relevant groups. Unknown groups fail startup. This is
a server-wide exposure control, not per-user authorization or isolation
from local CLI/Web UI access. The existing bearer and loopback safeguards
remain unchanged. Each server allows four concurrent queries with a two-second
admission wait and a 1 MiB serialized result limit. Optional
`YGGFLARE_MCP_AUDIT_LOG=true` writes fixed tool names, outcome and elapsed
time to stderr; no inputs or result data are logged. These bounds do not
provide a hard execution deadline for an already-started local read.

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
| `YGGFLARE_MCP_PRINCIPALS_FILE` | unset | Opt-in per-client scopes using `/config/mcp-principals.json` |
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

### Optional per-client authorization

The default single-token configuration is unchanged. For several trusted
HTTP clients with different information needs, create a private
`/config/mcp-principals.json` file, e.g.:

```json
{
  "version": 1,
  "principals": [
    {"name": "codex", "groups": ["inventory", "cloudflare", "operations", "traefik", "komodo", "kuma", "probes"]},
    {"name": "monitor", "groups": ["operations", "kuma"]}
  ]
}
```

Generate a distinct random token in each corresponding
`/config/mcp-token-NAME.txt` file (e.g. `mcp-token-codex.txt`).
Manifest and token files must be regular, non-symlink files with no group
or other permissions (use mode 0600). The manifest contains no token values,
arbitrary paths or wildcards. Each principal must explicitly list its
groups, all within the global `YGGFLARE_MCP_TOOL_GROUPS` ceiling.
A maximum of eight principals is supported. Set
`YGGFLARE_MCP_PRINCIPALS_FILE=/config/mcp-principals.json` and recreate the
container. This opt-in requires a loopback listener, replaces the original
single-token mode entirely, and fails startup on invalid configuration.
Rotate/revoke clients by editing the private files and recreating the
container. Each request authenticates against the configured tokens and
dispatches to a distinct stateless MCP server with only its allowed tools,
resources and prompts. All principal servers share the four-query
concurrency limit. This is group-level read-only authorization, not
per-resource tenancy, OAuth, or isolation from local CLI/Web UI access.
Stdio remains controlled by the server-wide tool groups.

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

Use `yggflare services assurance HOSTNAME` or the Services → Cross-source ingress evidence view to correlate saved ingress evidence with candidate exact Komodo stack/service identities, Kuma target hostnames and local probe observations. Each nested source is independently timestamped and bounded; an exact hostname or project match is not proof of ownership, external reachability or authentication. MCP `get_ingress_evidence` requires all six relevant source groups.

Adapter-specific row schemas are exposed for Traefik, Komodo, Kuma, probe results, scheduler history, candidate monitoring coverage and finding history. Fields not present in a saved observation remain optional; no synthetic defaults imply success.

Network discovery now retains aggregate scan coverage evidence: Nmap completion metadata, TCP requested/represented/omitted targets, explicit timeouts, port-evidence target count, selected port count, Docker exclusions and DNS-SD browse outcome. `get_discovery_status` exposes this metadata; legacy/offline snapshots are marked unavailable. Omissions from Nmap `--open` are not evidence of closed ports, timeouts or offline devices. Existing discovery/alert decisions are unchanged. All paginated MCP tools expose concrete typed row fields, with mixed legacy values retained where necessary.

The same discovery coverage is available in the Web UI under Operations → Discovery coverage, and through `yggflare network coverage --json`. It becomes available after a new live scan; no historical coverage is fabricated.

Kuma candidate correlation now matches exact ingress names, service hostnames, aliases, and explicit declared/runtime/LAN addresses. Each candidate reports its match basis, matching service identities, shared/ambiguous address evidence and whether its TCP port appears in the service declaration/evidence. It does not resolve DNS, infer host-mode IPs, treat proxy addresses as application addresses, or claim authoritative monitoring coverage. The same logic applies to ingress assurance and monitoring coverage across MCP, CLI and Web UI. For HTTP probes, set an explicit `expected_statuses` list to distinguish a returned HTTP response from a match to the configured expected status; update the allowlist and recreate the container when the underlying Compose config changes.

Supplemental discovery coverage reports the saved per-collector configuration, execution counts, no-reply outcomes, parse failures, unavailable executables, target limits and unverified Nmap completion for the fixed supported sources. It is available in MCP `get_discovery_status`, Web Operations → Discovery coverage and `yggflare network coverage --json`. Counts are invocations/batches, not complete device or port coverage; a configured source with no eligible targets can remain unattempted. SMB's configurable target limit and worker counts are explicit. No changes to discovery scope or alert policy.

Prometheus coverage metrics include fixed `yggflare_network_tcp_*` aggregate counts and `yggflare_discovery_<source>_*` invocation, failure, no-reply, parser and limitation evidence for configured sources. They describe the last saved scan, not cumulative counters; unavailable legacy observations are omitted. Metric names use a fixed allowlist, with no device identities or secret data in labels.

### Monitoring and discovery follow-up

Kuma parses targets according to monitor type: TCP monitors use explicit hostname/port labels, while Docker, group and push monitors have no inferred network endpoint. Exact Docker monitor friendly names are weak container/service candidates; duplicate names retain all matching project/service identities. Actual Docker host and container target are not exported. After upgrading, refresh the Kuma snapshot to replace legacy placeholder metadata.

The Monitoring UI includes candidate device monitoring coverage; CLI `yggflare kuma devices --json --all` and MCP `get_monitoring_coverage(scope="devices")` use exact saved numeric addresses of non-container inventory rows. No DNS lookups or live probes are performed. DHCP reuse, incomplete inventory and independent timestamps limit confidence.

SMB enumeration uses scoped targets with previously observed open TCP/445 or TCP/139, preferring 445. Set `YGGFLARE_DISCOVERY_SMB_MAX_TARGETS` (1–4096; defaults to `YGGFLARE_DISCOVERY_MAX_TARGETS`, otherwise 512) and `YGGFLARE_DISCOVERY_SMB_WORKERS` (1–16; default 8) to bound concurrent anonymous listings. Each listing retains its 10-second execution deadline. Invalid SMB settings disable only that collector and produce a sanitized warning. Missing port evidence is not proof of closure. Aggregate selection and outcomes (access denied, refusal, remote timeout, local deadline, execution failure and successful listings with/without shares) are reported without raw diagnostics. No credentials, new scan scope or alert policy changes.

Read-only paginated CLI commands accept `--limit 1..50` or `--all` (stable top-level result set, up to 10,000 rows/16 MiB, rejects changed snapshots; does not aggregate nested ingress layers). Examples: `yggflare kuma coverage --all --json`, `yggflare kuma monitors --limit 10 --json`.

### Evidence consistency refinements

Ingress assurance filters exact normalized literal HTTP router hosts before pagination, reuses one service projection per request, and distinguishes nested page truncation from upstream snapshot truncation. Device monitor coverage reports `target_port_selected` for the saved primary IPv4 TCP port set, `target_port_observed` only for positive open-port evidence, and `target_port_evidence` to distinguish selected-not-observed, not selected, observed open and unknown. Selection describes the global primary scan port set, not proof that a particular device was probed. Legacy scans have unknown selection until a new scan completes; IPv4 observations are never attributed to IPv6. No new scan targets, credentials or automatic reconciliation inputs.

### Komodo tracked stack inputs

Komodo refresh annotates stack rows with `tracked_stack_inputs`: `same_reported_revision`, `matched`, `changed`, or `unknown`. The revision mismatch remains separate. When both commit objects are already present in the read-only /compose-source Git checkout, compare the historical stack declaration (exact name and server), linked-repo declaration, stack directory tree, and explicitly declared config_files (including relative external files). No fetch or checkout is performed. This is candidate tracked input evidence, not effective Compose equivalence, runtime state, external volume configuration, or an instruction to redeploy. Missing history, unsupported layouts and ambiguous declarations remain unknown. Git is used only in the scheduled/explicit Komodo refresh, not MCP calls or metrics scrapes.
