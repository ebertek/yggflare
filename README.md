# Yggflare

Yggflare is a self-hosted controller for **Cloudflare Access, Tunnel ingress and DNS**, driven by Docker Compose, alongside **LAN device/service inventory, Discord alerts and recovery tooling**. It keeps your Compose source read-only and treats destructive Cloudflare actions as explicit, separately approved operations.

[Quick start](#deployment) · [Operations](#release-readiness-diagnostics) · [Cloudflare safety](#managed-host-lifecycle-and-safe-retirement) · [License](#license)

## Environment-variable naming

Yggflare uses exactly two application-owned environment namespaces:

- `YGGFLARE_*`: controller, network inventory, watches, web UI, and Cloudflare reconciliation/cleanup behavior. For example, `YGGFLARE_LAN_CIDR`, `YGGFLARE_WATCH_COMPOSE`, `YGGFLARE_CLOUDFLARE_AUTO_APPLY`, and `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP`.
- `CLOUDFLARE_*`: Cloudflare connection and resource settings (account, token, zones and tunnel).

This is a **breaking rename**. The former `YGG_*` and `CF_*` names are not recognized. Update deployment environment values in the same release as the image to avoid losing configuration, especially the Cloudflare write/cleanup opt-ins.

## How it works

- Audits Cloudflare on startup, when Compose/inventory inputs or Docker topology change, and every six hours as a fallback. Writes are disabled by default (`YGGFLARE_CLOUDFLARE_AUTO_APPLY=false`).
- Audits LAN devices and services daily at **05:15 UTC**.
- Creates a local backup daily at **04:00 UTC**, retaining 14 snapshots.
- Uses **UTC** for scheduling and log timestamps.
- Provides a Docker health check based on an independently refreshed heartbeat.
- Reads Compose definitions from `/compose-source` without modifying them. Private device inventories are supplied through `/config`. All mutable state stays in `/data`, and archives in `/backup`.

Yggflare runs on a host network and accesses Docker through `/var/run/docker.sock` for container inventory. **Docker socket access is effectively host-root access.** Nmap and Avahi access may require elevated privileges. Restrict who can configure or run this container.

## Deployment

The [Compose file](compose.yaml) pulls the prebuilt image from GHCR. Set Compose interpolation variables in your deployment environment, and create the two secret files under `${YGGFLARE_HOME}/secrets/`.

Example shell setup, using illustrative network addresses and domains:

```sh
export YGGFLARE_HOME=/srv/yggflare
export YGGFLARE_MERGED_ROOT=/srv/compose
export YGGFLARE_LAN_CIDR=192.168.40.0/23
export YGGFLARE_DEVICES_CIDR=192.168.40.0/24
export YGGFLARE_DOCKER_CIDR=192.168.41.0/24
export YGGFLARE_INTERNAL_DOMAIN=home.example.net
export YGGFLARE_EXTERNAL_DOMAIN=services.example.net
export CLOUDFLARE_ACCOUNT_ID=YOUR_ACCOUNT_ID
export CLOUDFLARE_TUNNEL_NAME=YOUR_TUNNEL_NAME
export YGGFLARE_CLOUDFLARE_AUTO_APPLY=false
export YGGFLARE_VERSION=main

docker compose config --quiet
docker compose pull
docker compose up -d
```

The example domains and ranges are not built-in defaults. Yggflare validates the configured domains and network ranges.

### Environment variables

| Variable | Purpose |
|---|---|
| `YGGFLARE_VERSION` | GHCR tag to pull; use `v1.0.0` for the first stable release or `main` for development |
| `YGGFLARE_HOME` | Host directory for config, state, backups and secrets |
| `YGGFLARE_MERGED_ROOT` | Read-only host directory containing Compose source files |
| `YGGFLARE_LAN_CIDR` | Network inventory scan scope |
| `YGGFLARE_DEVICES_CIDR` | IPv4 subnet allowed for static device DNS |
| `YGGFLARE_DOCKER_CIDR` | IPv4 subnet used to identify Docker services |
| `YGGFLARE_INTERNAL_DOMAIN` | Internal DNS zone |
| `YGGFLARE_EXTERNAL_DOMAIN` | External Cloudflare Access/Tunnel DNS zone |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |
| `CLOUDFLARE_TUNNEL_NAME` / `CLOUDFLARE_TUNNEL_ID` | Select Tunnel by name or ID |
| `CLOUDFLARE_INTERNAL_ZONE_ID` / `CLOUDFLARE_EXTERNAL_ZONE_ID` | Optional zone IDs; otherwise resolved by DNS name |
| `CLOUDFLARE_STATIC_DNS_REQUIRED` | Require the static-host inventory; default `true` |
| `CLOUDFLARE_STATIC_DNS_SYNC` | Include static DNS actions in reconciliation planning; default `false` |
| `YGGFLARE_CLOUDFLARE_AUTO_APPLY` | Enable unattended Cloudflare writes; default `false` |
| `YGGFLARE_LOG_FORMAT` | `text` (default) or newline-delimited `json` |
| `YGGFLARE_WATCH_COMPOSE` | Poll Compose YAML and inventory fingerprints for changes; default `true` |
| `YGGFLARE_WATCH_DOCKER` | Subscribe to Docker container/network events; default `true` |
| `YGGFLARE_WATCH_POLL_SECONDS` | Compose/inventory content check interval; default `15` seconds |
| `YGGFLARE_WATCH_DEBOUNCE_SECONDS` | Wait for changes to settle; default `20` seconds |
| `YGGFLARE_WATCH_COOLDOWN_SECONDS` | Minimum delay after an audit before another event-driven audit; default `60` seconds |
| `TZ` | UTC in the supplied Compose definition |

Container mount destinations are fixed: `/config`, `/data`, `/backup`, and
`/compose-source`. Change the host-side bind sources as needed; the former
`YGGFLARE_CONFIG`, `YGGFLARE_DATA`, `YGGFLARE_BACKUP`, and `YGGFLARE_SOURCE`
overrides are no longer read. `PYTHONPATH` is owned by the image, not Compose.
`YGGFLARE_CONTAINER_NAME` is no longer read: approval commands use the Compose
service `yggflare`, and Docker self-event filtering uses that service's label.
Run printed `docker compose exec -T yggflare ...` commands from the directory
containing the deployment Compose file (or supply its `-f` path). This works
when `container_name` is changed. Upgrade the image before removing the old
Compose `PYTHONPATH` entry.

### Secrets and data

| Path | Purpose |
|---|---|
| `secrets/cloudflare_api_token` | Cloudflare API credential, mounted as a Compose secret |
| `secrets/network_discord_webhook` | Optional Discord webhook; an empty file disables notifications |
| `config/static-hosts.json` | Private device inventory and DNS declaration |
| `config/retained-dns.json` | DNS entries intentionally retained outside normal inventory |
| `data/` | Audit observations, scheduling markers and heartbeat |
| `backup/` | Daily backup archives |

Do not publish secret files, `/data`, or backup archives. Backups can contain **plaintext credentials**; protect them, replicate them off-host and periodically test restoration. The `ports` inventory field uses structured entries such as `{"protocol":"tcp","port":443,"description":"HTTPS"}`.

## Read-only inventory web interface

Yggflare includes an optional, **disabled-by-default** inventory interface inspired by a spreadsheet-style LAN /27 worksheet. It reads the existing private JSON inventory, the last saved Nmap/DNS-SD scan, mounted Compose definitions and read-only Docker metadata; it does **not** initiate scans, call Cloudflare, or offer mutation endpoints.

```yaml
environment:
  YGGFLARE_WEB_ENABLED: "true"
  YGGFLARE_WEB_BIND: "127.0.0.1"
  YGGFLARE_WEB_PORT: "8787"
```

When enabled, browse `http://127.0.0.1:8787/inventory` **from the Docker host**. The default bind is loopback and the container uses host networking. The interface provides:

- `/inventory`: searchable, sortable inventory tables grouped by /27, with declared and observed status
- `/reserved` and `/retired`: planned allocations and historical devices from optional `/config/static-hosts-reserved.json` and `/config/retired-devices.json`
- `/ports`: one row per endpoint/protocol/port, open-port evidence, detected services, declaration sources and DNS-SD announcements
- `/diff`: static inventory versus observed MACs, ports and presence
- `/drift`: current device/port drift plus the latest 200 findings (new device/port/DNS-SD, changed MAC/IP)
- `/cloudflare`: saved live-audit classification, claimed resources and lifecycle state
- `/api/inventory.json` and `/api/inventory.csv`: read-only exports

Docker rows include hostnames (qualified with `YGGFLARE_INTERNAL_DOMAIN`), LAN
IPv4/IPv6 addresses, MACs, network aliases and Traefik router names. Compose
provides declarations even when Docker is unavailable; running-container metadata
supplies current addresses and image `EXPOSE` ports. Status distinguishes
`docker declared`, `docker running` and `docker stopped`; it does not imply
Cloudflare ownership or a successful port probe. Only services with a LAN IPv4 endpoint appear. Host-network, bridge-only and
other unallocated services are omitted. Services using `network_mode: service:…`
or `container:…` inherit a uniquely resolved parent's LAN endpoint and are labelled
**shared network**; their own hostname and port evidence remain distinct.
Compose service references are project-scoped; cycles/missing/ambiguous parents
are omitted. Parent Traefik routers/backends named for the child can provide
that child's aliases/ports. Shared address scan results describe the endpoint,
not proof that a particular child process owns a listening socket.

Port evidence combines Compose `ports` (container target, not published host port),
`expose`, Docker exposed/bound ports, Traefik backend ports/URLs and narrowly
recognized port/listen-address environment hints. These are candidates, **not
proof of listening sockets**; confirmed scan results remain in the separate
Observed column. Arbitrary environment values, secret files and raw Docker
inspection output are never served. Compose interpolation and `env_file` are not
executed/read by the UI; Docker supplies resolved runtime metadata when available.
No images are pulled or built, and Docker port scanning remains unchanged.

Metadata is cached for 30 seconds, with a visible fallback notice when Docker or
a Compose file cannot be read. IPv4, IPv6 and /27 groups sort numerically;
column clicks toggle ascending/descending order. JSON and CSV exports use the
same numerically ordered inventory; CSV includes aliases and ports.

The normal targeted TCP scan now uses bounded Nmap light service detection
(`-sV --version-light`, retaining the existing host/command timeouts). The view
labels probed service identities separately from Nmap's port-name guesses;
unknown services remain unknown. Docker scan exclusions are unchanged. DNS-SD
retains resolved addresses without TXT payloads and is matched by exact address,
port and protocol; advertisements alone do not prove a port is open. Older state
files remain readable, with unavailable metadata shown explicitly.

Drift history begins with scans after this upgrade, is capped at 200 findings,
and distinguishes initial-baseline findings (not notified) from later changes.
Active device/port drift comes from the existing `reported` state. The history
records observations, not proof of Discord delivery. Failed/incomplete DNS-SD
collection retains the previous announcements with their previous timestamp.

When the web UI is enabled, the controller runs a separate **GET-only** Cloudflare
audit after each scheduled/reactive reconciliation attempt, including cleanup.
It saves only host classification, resource identifiers, scope and timestamp to
`/data/cloudflare-view.json`, with a completion marker in
`cloudflare-view-status.json`. HTTP requests never call the Cloudflare API.
A failed refresh preserves the last complete snapshot and displays a warning;
snapshots older than eight hours are marked stale. Before the first successful
audit, only local claims are shown, without guessing lifecycle state.

Lifecycle distinguishes **managed**, **orphaned**, **unmanaged**, and **declared /
unclaimed** services. The last category avoids treating a Compose declaration as
ownership. Claimed Access/DNS IDs and route hostnames are displayed alongside live
resource IDs/counts. Scope-matched orphan first/last absence observations are
shown as timestamps, never as cleanup eligibility or a deletion countdown. There
are no claim, apply or delete buttons; the snapshot is never used by write paths.

### Inventory review controls

Hostnames, IPv4/IPv6 addresses, MACs, aliases, subnet names, descriptions,
DNS-SD details and Cloudflare resource IDs remain visible in the read-only UI
and applicable exports. No opt-in flag is needed for existing inventory details.
`YGGFLARE_WEB_SHOW_SECRETS` is not implemented; setting it has no effect.
Tokens, passwords, webhook URLs, raw environment values and secret files remain
excluded. Protect the UI with authentication as described above.

Each /27 group can be collapsed independently, with Expand all / Collapse all
controls. Search opens matching groups and restores their prior state when cleared.
Class and finding filters combine with text search. Color plus text badges mark
missing hostname/MAC information, confirmed drift, explicit retirement and newly
discovered devices. IPv6 and port information are optional, so their absence is
not automatically flagged. On narrow screens, rows become labelled cards and
sorting controls remain available.

The Last seen column records the last successful scan observation of an address;
it survives later scans where that address is absent. It is not a live heartbeat.
`/diff` compares static declarations with observed MACs, ports and presence.
Accepted `observed_macs` do not trigger drift. Unobserved declared ports are
labelled unknown, not closed; an offline device is never inferred to be retired.

Drift cells highlight the affected MAC, IP, port or presence field and show
both declared and observed values. The full comparison remains under `/diff`.
Badges stay on one line at desktop and mobile widths.

Reserved and retired catalogs are read-only and separate from the active /27
inventory. Each file accepts a JSON record list, or an object with a `hosts` or
`devices` list. Records may include `hostname`, `name`, `ipv4`, `ipv6`, `mac`,
`aliases` (list), `description`, `notes`, `device_class`, `reason`, and `retired_at`.
Other fields are not exported. Missing files show an empty tab; unsupported or
malformed files show a warning without disabling the active inventory. These
catalogs never feed DNS reconciliation, scanning or Cloudflare ownership.

Optional static-host metadata:

```json
{"hostname":"printer.home.example.net","ipv4":"192.168.40.35","device_class":"printer","retired":false}
```

`device_class` accepts `network`, `server`, `computer`, `mobile`, `iot`, `media`,
`printer`, `sensor` or `other`. Unclassified static hosts show Device; Compose/Docker
services show Docker and unrecognised scan rows show Unknown. `retired` must be a
boolean and is **presentation-only**: it does not stop scans, remove DNS or authorize
cleanup. A retired-labelled address still responding is highlighted as drift.
Do not add these metadata fields to deployment inventories before upgrading the
image, because older strict validators reject unknown fields.

The UI intentionally omits Cloudflare credentials, Discord URLs, and private config files. It does not replace `yggflare cloudflare audit` for current live results. **There is no built-in authentication.** Keep it on loopback, use an authenticated tunnel or reverse proxy for remote access, and never expose the HTTP port directly to the public Internet. To serve on the host network instead, explicitly set `YGGFLARE_WEB_BIND=0.0.0.0` and enforce firewall/authentication upstream.

## Logging and observability

Set `YGGFLARE_LOG_FORMAT=text` for timestamped, component-labelled stdout, or `YGGFLARE_LOG_FORMAT=json` for JSON lines with UTC `timestamp`, `level`, `component` and `message`. JSON lines can be parsed and indexed in Grafana Loki using an agent such as Grafana Alloy. The container writes to stdout and stderr; it does not require a separate log file.

Use `docker compose logs -f yggflare` to inspect the controller and `docker inspect yggflare --format '{{.State.Health.Status}}'` to check health.

## Manual Cloudflare reconciliation

Run administrative commands **on the Docker host** against the running
`yggflare` container. The installed `yggflare` CLI copies the merged
Compose definitions and private inventory into an isolated temporary snapshot,
just like the scheduled controller; it never modifies `/compose-source`.

```sh
# Read-only drift audit
docker exec yggflare yggflare cloudflare audit

# Review a bounded, read-only approval plan
docker exec yggflare yggflare cloudflare plan --max-operations 1
```

If a plan proposes only the intended operation, it prints an approval
fingerprint and a **host command to run from the deployment Compose directory**, for example:

```sh
docker compose exec -T yggflare yggflare cloudflare apply <approval-fingerprint> --max-operations 1
```

The CLI preserves the plan's `--max-operations` limit in the suggested
command. Applying requires the same live plan fingerprint and rechecks the
current Cloudflare state before each guarded write. If the plan changes,
the approval is rejected and must be reviewed again. Use the actual
fingerprint returned by your audit, not the example placeholder.

`YGGFLARE_CLOUDFLARE_AUTO_APPLY=false` can remain set for manually approved changes; the
unattended writer does not need to be enabled. To validate the Cloudflare
templates without modifying anything:

```sh
docker exec yggflare yggflare cloudflare preflight
```

## Managed host lifecycle and safe retirement

Yggflare maintains a **private ownership registry** at
`/data/managed-hosts.json`, included in the regular `/data` backups.
Missing registry data is treated as **no proven ownership**, never as a
reason to delete a live Cloudflare resource.

The read-only audit classifies external hostnames as:

- **Managed:** explicitly claimed while declared in Compose, or fully
  created and verified by Yggflare; still present in Compose
- **Orphaned:** previously claimed but no longer declared in Compose
- **Unmanaged:** present in Cloudflare but not claimed, regardless of whether
  it happens to be absent from Compose

Neither the six-hour audit nor `YGGFLARE_CLOUDFLARE_AUTO_APPLY=true` deletes resources
unless the **separate**, disabled-by-default `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP=true`
opt-in is configured. The normal resource reconciler remains non-destructive.

### Opt-in automatic orphan retirement

The optional cleanup workflow requires both `YGGFLARE_CLOUDFLARE_AUTO_APPLY=true` and
`YGGFLARE_CLOUDFLARE_AUTO_CLEANUP=true`. Its minimum grace period is 24 hours:

```yaml
environment:
  YGGFLARE_CLOUDFLARE_AUTO_APPLY: "true"
  YGGFLARE_CLOUDFLARE_AUTO_CLEANUP: "true"
  YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS: "24"
```

Only previously claimed/created managed resources can be retired. Yggflare
records first/last absence observations in `/data/orphan-observations.json`
and resets an orphan timer if Compose reintroduces the hostname or the
interval between successful observations exceeds eight hours. Missing
history never authorizes immediate removal. The reconciler verifies the
current mounted Compose, Cloudflare resource identities, ordered policies,
Tunnel configuration and registry before deleting. It removes at most one
orphan per successful cycle (DNS → Tunnel → Access), retaining ownership
on partial failure; completion generates a Discord confirmation when
configured. **Unmanaged resources are never eligible.** Invalid Compose
source or API failures block cleanup, and the default is off.

The normal manual `orphan-plan`/`orphan-apply` workflow remains available
regardless of unattended cleanup settings.

### Claiming existing managed services

Existing services migrated from Komodo are **not silently adopted**. While
a service is still declared in Compose and exactly matches its live Access
policies, proxied Tunnel DNS CNAME, and ingress route, opt in one hostname:

```sh
docker exec yggflare yggflare cloudflare claim example.ebi.nu
```

Claims pin the Access application ID, ordered policies, DNS record ID,
CNAME target, and complete ingress route to a specific account, zone and
Tunnel. Changing identity or scope blocks subsequent deletion.

An endpoint originally created by Yggflare's guarded reconciler is recorded
automatically **after** all its requested operations complete and its
endpoint has been verified. A partial create does not grant ownership.

### Retiring a claimed, removed hostname

After removing its Compose declaration and allowing GitOps to sync,
inspect the read-only audit:

```sh
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare cloudflare orphan-plan example.ebi.nu
```

Only a previously claimed, now-absent hostname can produce a retirement
plan. If the plan contains exactly the resources you intend to retire,
copy the printed `docker compose exec -T yggflare yggflare cloudflare orphan-apply ...`
command using the **actual** fingerprint.

Manual cleanup strictly orders operations as **external DNS CNAME first,
Tunnel ingress second, Access application last**. It rechecks the live
record IDs, contents, policy ordering, Tunnel configuration, Compose absence,
and registry ownership. Failure leaves the registry in place, so a new plan
can resume any remaining steps without guessing. No other Tunnel routes are
removed. Unclaimed hostnames cannot be deleted by this workflow.

**Migration:** Resources that disappeared before Yggflare first tracked them remain **unmanaged**. Do not bulk-claim existing Cloudflare records. A claim requires a currently declared and fully verified Compose hostname.

## Reactive reconciliation

The Compose watcher computes a content fingerprint of `compose.yaml`/`compose.yml`
under `/compose-source` and `static-hosts.json`/`retained-dns.json` under
`/config` every 15 seconds by default. It detects changes after Git pulls,
including atomic file replacement, without writing to the source tree.
Changes to unrelated files do not trigger reconciliation.

The Docker watcher listens on the existing Docker socket for container
start/stop/destroy/rename events and Docker network connects/disconnects.
Self-events and container health-status noise are ignored. When Docker events
are unavailable, the six-hour periodic reconciliation still runs.

Multiple changes are coalesced (20-second debounce); a 60-second cooldown
prevents a stack restart from producing a burst of Cloudflare API checks.
These timings can be customized through the `YGGFLARE_WATCH_*` variables above.
The normal Nmap/DNS-SD inventory scan remains **daily**, not on every Docker
event. Only the Cloudflare reconciliation is triggered reactively.

**Security:** a change notification merely requests the normal reconciliation
path. It does not alter the guarded plan, the operation limits, or
`YGGFLARE_CLOUDFLARE_AUTO_APPLY`. With `YGGFLARE_CLOUDFLARE_AUTO_APPLY=false`, every trigger remains
read-only. If you enable unattended writes, both scheduled and reactive
triggers use the same guarded writer, so review its policy and authorization
before enabling it.

## Image versions and releases

Published images are available at `ghcr.io/ebertek/yggflare`.

- `:main` follows development builds and is **not** a stable release tag.
- `:sha-<full-commit-sha>` identifies an exact build.
- `:vMAJOR.MINOR.PATCH` is produced when a matching Git tag is pushed, such as `:v1.0.0`.
- No `:latest` alias is published by this workflow.

Releases follow [Semantic Versioning](https://semver.org/): use `v1.0.0` for the first verified release, `v1.0.1` for compatible bug fixes and `v1.1.0` for backward-compatible features. The leading `v` denotes the Git/image tag; the semantic version is `1.0.0`. Prefer a pinned release tag (or digest) for deployed services:

```sh
export YGGFLARE_VERSION=v1.0.0
docker compose pull
docker compose up -d --no-build
```

Versioned release tags are immutable release references; prefer digest pinning in production. Run `docker exec yggflare yggflare doctor run` after upgrading and verify the backup restore-test before depending on recovery.

## Release-readiness diagnostics

Commands run in the deployed container; they never edit GitOps source files.

```sh
# Read-only checks for mounts, secrets, Docker, tools, scheduler and backup
docker exec yggflare yggflare doctor run

# Validate an existing backup archive without restoring live files
docker exec yggflare yggflare backup verify yggflare-YYYYMMDDTHHMMSSZ.tar.gz

# Extract and validate into temporary private /data storage; never replace live files
docker exec yggflare yggflare backup restore-test yggflare-YYYYMMDDTHHMMSSZ.tar.gz

# Explicitly run the LAN inventory scan (may update /data observations
# and send real drift notifications if a Discord webhook is configured)
docker exec yggflare yggflare network run

# Explicitly send ONE Discord delivery test; no network scanning
docker exec yggflare yggflare network discord-test
```

The doctor does not call Cloudflare or post messages. A missing/empty
`network_discord_webhook` is reported as a warning and must be configured
before delivery can be validated. The test notification is deliberately
opt-in. Real inventory scans are **not** read-only: they update observation
state and can deliver detected changes, but never edit DNS/Compose.

`backup verify` validates archive integrity without extraction. `backup restore-test` rehearses extraction in a temporary, restricted directory under `/data` and checks the restored inventory/JSON state, **without replacing live files**. Neither is a substitute for a full disaster-recovery exercise on an independent host.

## License

Licensed under **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Cloudflare, Discord and other referenced products retain their respective trademarks and terms.

## Validation

The repository includes Cloudflare, network-audit and controller unit tests; the CI workflow executes them and builds the image. Ruff and Black enforce Python style. The [publish workflow](.github/workflows/publish.yml) requires tests and lint to pass before uploading images.

Cloudflare auditing can be verified by confirming zero proposed operations and zero unintended static DNS drift with `YGGFLARE_CLOUDFLARE_AUTO_APPLY=false`. Before enabling unattended writes, independently validate write-path safeguards, network inventory alerts, persistence and backup recovery. Avoid running multiple automatic Cloudflare writers at the same time.
