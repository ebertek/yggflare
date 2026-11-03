# Yggflare

Yggflare reconciles **Cloudflare Access, Tunnel routes and DNS** against Docker Compose and private device inventories. It also discovers LAN devices and services, reports drift to Discord, serves a read-only inventory UI, and backs up configuration and state.

| Task | Schedule |
|---|---|
| Cloudflare audit and optional reconciliation | Startup, Compose/inventory changes, Docker topology changes, and every six hours |
| LAN inventory: Nmap and DNS-SD | Daily at 05:15 UTC |
| Backup of configuration, state and mounted secrets | Daily at 04:00 UTC; retain 14 snapshots |

Cloudflare writes, automatic orphan cleanup and the web UI are disabled by default. Source Compose files and inventory declarations remain read-only; observations and ownership records live under `/data`.

## Setup

Use the supplied [compose.yaml](compose.yaml) on a Linux Docker host. It uses host networking, the Docker socket and the host D-Bus socket for discovery. Docker socket access effectively grants host-root access; Nmap requires permission to perform SYN scans.

1. Set the required variables below in your Compose deployment environment. Use your own domains and private IPv4 CIDRs.
2. Create `config`, `data`, `backup` and `secrets` directories under `YGGFLARE_HOME`. Add `config/static-hosts.json` using the format below.
3. Put the Cloudflare API token in `secrets/cloudflare_api_token`. Give it access to the configured account's Access applications/policies, Tunnel and DNS zones, including edits if enabling writes. Put the optional Discord webhook in `secrets/network_discord_webhook`; create an empty file to disable notifications.
4. From the directory containing the Compose file, start the service:

```sh
docker compose config --quiet
docker compose pull
docker compose up -d
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
```

Keep automatic writes off until the audit matches your intended configuration. Runtime commands use `docker exec` and work from any directory; substitute your container name if it differs from `yggflare`.

### Required configuration

`YGGFLARE_*` configures the application; `CLOUDFLARE_*` selects Cloudflare resources and credentials. The first two variables below configure host bind mounts, not container paths.

| Variable | Value to supply |
|---|---|
| `YGGFLARE_HOME` | Host directory holding `config/`, `data/`, `backup/`, `secrets/`; e.g. `/srv/yggflare` |
| `YGGFLARE_MERGED_ROOT` | Host directory containing the Compose stacks to audit; e.g. `/srv/compose` |
| `YGGFLARE_LAN_CIDR` | LAN discovery range; e.g. `192.168.40.0/23` |
| `YGGFLARE_DEVICES_CIDR` | Static device address range; e.g. `192.168.40.0/24` |
| `YGGFLARE_DOCKER_CIDR` | Docker service address range; e.g. `192.168.41.0/24` |
| `YGGFLARE_INTERNAL_DOMAIN` | Internal DNS zone; e.g. `home.example.net` |
| `YGGFLARE_EXTERNAL_DOMAIN` | Access/Tunnel DNS zone; e.g. `services.example.net` |
| `CLOUDFLARE_ACCOUNT_ID` | Account containing the managed resources |
| `CLOUDFLARE_TUNNEL_NAME` / `CLOUDFLARE_TUNNEL_ID` | Supply a Tunnel name or ID; ID takes precedence |

### Optional configuration

Defaults below describe the application or supplied Compose file. Set booleans to `true` or `false`. **Variables must reach the container's `environment:` section**: exporting a variable alone only works when the Compose file references it. In particular, add web and automatic-cleanup settings to `environment:` when enabling those features.

| Variable | Default | Purpose |
|---|---|---|
| `YGGFLARE_VERSION` | `main` | Image tag in the supplied Compose file; version and commit tags are described below |
| `CLOUDFLARE_EXTERNAL_ZONE_ID` | Resolve by domain | External DNS zone ID |
| `CLOUDFLARE_INTERNAL_ZONE_ID` | Resolve by domain | Internal DNS zone ID |
| `CLOUDFLARE_API_TOKEN_FILE` | `/run/secrets/cloudflare_api_token` | Token file; supplied Compose mounts it automatically |
| `CLOUDFLARE_STATIC_DNS_REQUIRED` | `true` | Fail the Cloudflare audit if the static inventory is absent |
| `CLOUDFLARE_STATIC_DNS_SYNC` | `false` | Include static A/CNAME changes in reconciliation plans |
| `YGGFLARE_CLOUDFLARE_AUTO_APPLY` | `false` | Enable guarded, bounded automatic reconciliation |
| `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP` | `false` | Retire eligible owned orphans; also requires auto-apply |
| `YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS` | `24` | Required orphan absence period; 24–720 hours |
| `YGGFLARE_WEB_ENABLED` | `false` | Start the read-only HTTP UI |
| `YGGFLARE_METRICS_ENABLED` | `false` | Enable aggregate `/metrics` exposition on the existing web listener; requires the web UI enabled |
| `YGGFLARE_WEB_BIND` | `127.0.0.1` | Listener address: `127.0.0.1`, `::1` or `0.0.0.0` |
| `YGGFLARE_WEB_PORT` | `8787` | HTTP port; 1–65535 |
| `YGGFLARE_LOG_FORMAT` | `text` | Timestamped component logs; `json` emits newline-delimited JSON |
| `YGGFLARE_WATCH_COMPOSE` | `true` | Watch Compose files and active/retained inventory content |
| `YGGFLARE_WATCH_DOCKER` | `true` | Watch container/network topology; ignore health-status noise and self-events |
| `YGGFLARE_WATCH_POLL_SECONDS` | `15` | File polling interval; 5–300 seconds |
| `YGGFLARE_WATCH_DEBOUNCE_SECONDS` | `20` | Wait for changes to settle; 5–300 seconds |
| `YGGFLARE_WATCH_COOLDOWN_SECONDS` | `60` | Minimum gap between reactive audits; 0–3600 seconds |
| `YGGFLARE_NETWORK_DISCORD_WEBHOOK_FILE` | `/run/secrets/network_discord_webhook` in Compose | Webhook file; empty disables notifications |
| `YGGFLARE_STATIC_INVENTORY` | `/config/static-hosts.json` | Inventory default for direct network-audit invocation |
| `YGGFLARE_NETWORK_STATE_DIR` | `/data/network-inventory` | State default for direct network-audit invocation |
| `TZ` | `UTC` | Container timezone; scheduler and log timestamps use UTC |

The scheduler explicitly supplies the standard inventory/state paths to network scans. The two scan-specific overrides do not relocate the web UI or Cloudflare inputs. Container mount destinations are fixed at `/compose-source`, `/config`, `/data`, `/backup` and `/run/secrets`; change host bind sources as needed. The image configures its own Python import path.

## Inventory files

Files below live in `/config`. Keep private inventory, state, credentials and archives out of public repositories.

| File | Purpose |
|---|---|
| `static-hosts.json` | Active devices, static DNS declarations and expected ports |
| `retained-dns.json` | Optional, audit-only exceptions for intentionally retained DNS records; never authorizes writes |
| `static-hosts-reserved.json` | Optional planned allocations, shown in Reserved |
| `retired-devices.json` | Optional historical devices, shown in Retired |

A minimal active inventory contains 1–256 hosts:

```json
{
  "version": 1,
  "hosts": [
    {
      "hostname": "printer.home.example.net",
      "ipv4": "192.168.40.35",
      "mac": "02:00:00:00:00:35",
      "description": "Office printer",
      "ports": [{"protocol": "tcp", "port": 9100, "description": "Printing"}],
      "aliases": ["print.home.example.net"],
      "device_class": "printer"
    }
  ]
}
```

Hostnames must belong to the internal domain. Static addresses must be within the device range, outside the Docker range, and exclude each /27's network/broadcast addresses. Optional fields include `serial_number`, `purchase_date`, `observed_macs` (accepted alternatives), `interface_macs` (interface-to-MAC mapping), and `additional_ipv4` (explicit companion A records, subject to allocation validation).

`device_class` accepts `network`, `server`, `computer`, `mobile`, `iot`, `media`, `printer`, `sensor` or `other`. Boolean `retired` is a presentation label only; it does not remove DNS or stop scanning. See [the inventory validator](src/cloudflare/cloudflare_static_dns.py) for exact field constraints.

Reserved/retired catalogs accept a record list or an object containing a `hosts` or `devices` list. Displayed fields are `hostname`, `name`, `ipv4`, `ipv6`, `mac`, `aliases` (list), `description`, `notes`, `device_class`, `reason` and `retired_at`. They never enter active reconciliation. Invalid optional catalogs show a warning without disabling the UI.

Retained DNS uses `{"version":1,"records":[...]}` with `hostname`, `type`, optional `description`, and expected `content` (required for A/AAAA/CNAME). Its [validator](src/cloudflare/cloudflare_retained_dns.py) restricts exceptions to the configured `YGGFLARE_INTERNAL_DOMAIN`; exceptions are audit-only and never authorize DNS writes.

## Web UI and observations

Add to the service's `environment:`:

```yaml
YGGFLARE_WEB_ENABLED: "true"
YGGFLARE_WEB_BIND: "127.0.0.1"
YGGFLARE_WEB_PORT: "8787"
```

Open `http://127.0.0.1:8787` on the Docker host. **There is no built-in authentication.** Remote access needs an authenticated reverse proxy/tunnel and appropriate host firewall rules; protecting a proxy hostname does not protect direct LAN access to the port.

| Page | Contents |
|---|---|
| `/inventory` | Numeric /27 grouping and sorting; hostname/IP/MAC search, class/flag filters, collapse controls, last seen and mobile cards |
| `/reserved`, `/retired` | Planned and historical inventory catalogs |
| `/ports` | Endpoint, protocol, port, detected service and DNS-SD announcements |
| `/diff` | Declared versus observed MACs, ports, presence and identifiable IP moves |
| `/drift` | Current findings and the latest 200 observations |
| `/cloudflare` | Managed/orphaned/unmanaged/declared-unclaimed hosts, resource IDs and lifecycle observations |
| `/api/inventory.json`, `/api/inventory.csv` | Active inventory exports |

Flags identify missing identity information, drift, retirement and new discoveries; affected drift cells show expected and observed values. Last seen is a saved scan observation, not a heartbeat. Missing ports are unknown, not confirmed closed; offline does not mean retired.

Docker rows combine Compose and cached Docker metadata: hostnames, LAN IPv4/IPv6, MACs, aliases and port declarations. Services without LAN endpoints are omitted. Shared-network services such as download/mousehole inherit gluetun's endpoint while retaining their own identity. Ports come from Compose targets/expose, Docker exposed/bound ports, Traefik backends and recognized environment hints; these are declarations, not proof of listening sockets. The UI does not execute Compose interpolation or read `env_file` contents.

Bounded Nmap scans and light service detection provide observed ports and service evidence; detailed scans exclude detected running Docker container addresses; DNS-SD advertisements remain separate evidence. Shared-address observations do not identify the owning process. Initial discovery establishes a baseline without Discord alerts; later changes can notify Discord. Incomplete DNS-SD runs preserve previous announcements. Network observations never change DNS or inventory declarations.

HTTP requests read local snapshots only: no scans, Cloudflare calls or mutation endpoints. Docker metadata is cached for 30 seconds. Cloudflare snapshots refresh after controller reconciliation attempts; failed refreshes retain the last complete snapshot and snapshots older than eight hours are marked stale. Credentials and raw environment/inspection data are excluded.

## Prometheus monitoring

Enable `YGGFLARE_WEB_ENABLED=true` and `YGGFLARE_METRICS_ENABLED=true`
to serve a read-only Prometheus 0.0.4 text exposition at `/metrics` on
the **existing** web HTTP port. There is no extra listener or active scan:
each scrape reads bounded JSON snapshots from the mounted `/config` and
persisted `/data`. The exporter does not query Docker or Cloudflare, reveal
device identifiers or credentials, or alter any state.

Prometheus should scrape this endpoint directly on a trusted private
network, not through the Cloudflare Access login flow. When using host networking,
**restrict the web listener (including `/metrics`) to trusted clients by
firewall**; Access protection on a public hostname does not secure direct LAN
TCP access. A corrupt or oversized metrics input yields HTTP 503, not misleading
zero metrics. Missing snapshots expose presence gauges and omit unknown
timestamps/durations.

The gauges include current discovered IPv4 hosts, unknown hosts from persisted
non-Docker drift state, active network findings, DNS-SD services, optional
collector warnings, pending Discord deliveries, declared inventory hosts,
Cloudflare orphan hosts and snapshot staleness. They also expose the last
successful scan/Cloudflare audit timestamps and the latest **saved scan
duration** (not including Discord delivery). Metrics have no device labels.

A simple scrape job:

```yaml
- job_name: yggflare
  scrape_interval: 30s
  metrics_path: /metrics
  static_configs:
    - targets: ["YOUR_HOST_REACHABLE_IP:8787"]
```

For freshness alerts prefer PromQL timestamps, such as
`time() - yggflare_network_scan_last_success_timestamp_seconds` and
`yggflare_cloudflare_snapshot_stale == 1`. Network scans run daily; do
not treat absence of new devices as an error. See
[the monitoring dashboard](dashboards/yggflare.json) for optional Grafana
import. The host-mounted Prometheus configuration must be updated separately
where it is not automatically synchronized from the Compose source.

## Cloudflare operations

Compose Traefik Host rules, `cf.access: "true"` and ordered `cf.access.policies` labels describe desired Access/Tunnel services. Static inventory supplies internal A records and aliases. Watchers trigger the same guarded reconciliation as scheduled audits; they do not trigger LAN scans or bypass write opt-ins.

Run an audit and review a bounded plan before applying:

```sh
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare cloudflare preflight
docker exec yggflare yggflare cloudflare plan --max-operations 1
docker exec yggflare yggflare cloudflare apply <approval-fingerprint> --max-operations 1
```

Use the actual fingerprint printed by the plan. Apply rechecks live state and rejects a changed plan; manual approval works with auto-apply disabled. `preflight` validates live templates without writes.

Ownership is recorded privately in `/data/managed-hosts.json`. A verified Yggflare-created service is recorded automatically; existing resources need an explicit claim while still declared and matching live Access policies, DNS and ingress:

```sh
docker exec yggflare yggflare cloudflare claim example.services.example.net
```

Claim only services whose lifecycle Yggflare should own. Managed hosts remain declared; orphans are owned hosts removed from Compose. Unmanaged resources have no proven ownership and are never cleanup targets. A declaration alone does not establish ownership.

After removing an owned service from Compose, review and approve retirement:

```sh
docker exec yggflare yggflare cloudflare orphan-plan example.services.example.net
docker exec yggflare yggflare cloudflare orphan-apply example.services.example.net <approval-fingerprint>
```

Automatic retirement instead requires all three settings in the container environment:

```yaml
YGGFLARE_CLOUDFLARE_AUTO_APPLY: "true"
YGGFLARE_CLOUDFLARE_AUTO_CLEANUP: "true"
YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS: "24"
```

Cleanup validates ownership, resource identities, scope and current Compose absence, then removes **external DNS → Tunnel route → Access application**. Automatic cleanup processes at most one orphan per successful cycle after the grace period; reappearance or observation gaps over eight hours reset the timer. Missing ownership/history never permits deletion. Partial failures retain ownership for recovery; successful automatic retirement can notify Discord.

## Diagnostics and recovery

```sh
docker logs -f yggflare
docker inspect yggflare --format '{{.State.Health.Status}}'
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare network run
docker exec yggflare yggflare network discord-test
docker exec yggflare yggflare backup verify <archive-name>.tar.gz
docker exec yggflare yggflare backup restore-test <archive-name>.tar.gz
```

`doctor` checks local dependencies, mounts and health without calling Cloudflare or posting messages. Its **Discord configured** check now validates the mounted webhook URL itself (HTTPS, exact Discord host and endpoint, numeric webhook ID and token syntax), not merely whether the file exists; it never prints the credential. A malformed secret fails `doctor` immediately. `discord-test` validates the same URL before any HTTP POST, so a corrupted ID produces an actionable error rather than a generic HTTP 400. `network run` updates observations and may notify Discord; `discord-test` sends one test message. A Discord delivery error does not invalidate a completed network scan: observations are saved first, undelivered alerts remain queued in private state for the next scan, and a sanitized Discord HTTP/error code is printed as a warning. `discord-test` reports the HTTP error but does not alter scan state. The error summary excludes the webhook URL, token and raw Discord response; an HTTP 400 requires verifying the webhook's destination/channel configuration. The Docker health check monitors an independently refreshed controller heartbeat.

Backups contain **plaintext credentials** when secrets are mounted: restrict access and keep an off-host copy. `verify` checks an archive without extraction; `restore-test` validates an isolated temporary extraction without replacing live files. Logs go to stdout/stderr, with optional JSON output for log collectors.

## Images and development

Image: `ghcr.io/ebertek/yggflare`. Tags are `main` (development), `sha-<full-commit-sha>` and `vMAJOR.MINOR.PATCH`; there is no `latest` tag. Prefer a digest pin for reproducible deployment. Run the doctor and audit after updating.

[AGENTS.md](AGENTS.md) describes contributor workflows, test commands and safety invariants. CI runs unit tests, Ruff, Black and an image build; publishing requires tests and lint to pass.

Licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE).

### Supplemental ARP/NDP and IPv6 discovery

Set these variables in the container environment. Example for a Linux host:

```yaml
YGGFLARE_DISCOVERY_INTERFACES: "eth0,eth1"
YGGFLARE_DISCOVERY_IPV6_CIDRS: "fd00:1234:5678::/64"
YGGFLARE_DISCOVERY_ARP_SCAN: "true"
YGGFLARE_DISCOVERY_NDP_PROBE: "true"
YGGFLARE_DISCOVERY_IPV6_SCAN: "true"
YGGFLARE_DISCOVERY_OS_DETECTION: "true"
```

Interfaces and IPv6 CIDRs are comma-separated lists, empty by default. An empty
interface list disables supplemental discovery. IPv6 probing requires explicit
IPv6 CIDRs. All four probe switches default to `false` and accept only `true` or
`false`. The supplied Compose file passes these variables into the container.
The `/discovery` view shows source, interface, collection timestamp and evidence.

It runs with scheduled/manual
network scans. Neighbour-cache entries are historical hints, not proof of current
reachability. Failed/incomplete entries are excluded. Active ARP uses the configured
IPv4 LAN range (maximum 4096 addresses). NDP and IPv6 Nmap use neighbour-cache, running Docker and resolved DNS-SD
addresses restricted to the configured IPv6 prefixes; they never enumerate an
IPv6 /64. Additional candidates must route through a configured interface.
IPv4 OS probes also accept the normal scan's discovered non-Docker addresses.
Each family is limited to 64 address/interface pairs, with numeric address order
and a visible notice when the probe cap is reached.
Supplemental Nmap groups targets by family and interface, with a 90-second batch timeout and per-host limits. IPv6 Nmap checks the top 20 TCP ports with
`-sV --version-light`; `YGGFLARE_DISCOVERY_OS_DETECTION=true` also enables a bounded IPv4 top-20 TCP
service/OS pass and adds `-O --osscan-limit --max-os-tries 1` to enabled IPv6
scans. OS matches and Nmap accuracy values appear as estimates in Discovery;
no match means unknown, not a change of OS. The switch defaults to `false`.
The normal IPv4 scan remains separate and reports phase timings.
These observations never change static inventory, ownership or DNS.

Add a public IPv6 prefix only when you want it scanned; update it if delegation
changes. Link-local targets are not probed by this collector. The existing IPv4 scan and Avahi DNS-SD behavior are unchanged.
Optional LLDP/CDP, SSDP, SMB, SNMP and p0f collectors are documented in
[Additional discovery sources](docs/discovery.md); no default SNMP communities are attempted.
