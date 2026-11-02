# Yggflare

Yggflare is a self-hosted controller for **Cloudflare Access, Tunnel ingress and DNS**, driven by Docker Compose, alongside **LAN device/service inventory, Discord alerts and recovery tooling**. It keeps your Compose source read-only and treats destructive Cloudflare actions as explicit, separately approved operations.

[Quick start](#deployment) · [Operations](#release-readiness-diagnostics) · [Cloudflare safety](#managed-host-lifecycle-and-safe-retirement) · [License](#license)

## How it works

- Audits Cloudflare on startup, when Compose/inventory inputs or Docker topology change, and every six hours as a fallback. Writes are disabled by default (`CF_AUTO_APPLY=false`).
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
export YGG_MERGED_ROOT=/srv/compose
export YGG_LAN_CIDR=192.168.40.0/23
export YGG_DEVICES_CIDR=192.168.40.0/24
export YGG_DOCKER_CIDR=192.168.41.0/24
export YGG_INTERNAL_DOMAIN=home.example.net
export YGG_EXTERNAL_DOMAIN=services.example.net
export CLOUDFLARE_ACCOUNT_ID=YOUR_ACCOUNT_ID
export CLOUDFLARE_TUNNEL_NAME=YOUR_TUNNEL_NAME
export CF_AUTO_APPLY=false
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
| `YGG_MERGED_ROOT` | Read-only host directory containing Compose source files |
| `YGG_LAN_CIDR` | Network inventory scan scope |
| `YGG_DEVICES_CIDR` | IPv4 subnet allowed for static device DNS |
| `YGG_DOCKER_CIDR` | IPv4 subnet used to identify Docker services |
| `YGG_INTERNAL_DOMAIN` | Internal DNS zone |
| `YGG_EXTERNAL_DOMAIN` | External Cloudflare Access/Tunnel DNS zone |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |
| `CLOUDFLARE_TUNNEL_NAME` / `CLOUDFLARE_TUNNEL_ID` | Select Tunnel by name or ID |
| `CLOUDFLARE_INTERNAL_ZONE_ID` / `CLOUDFLARE_EXTERNAL_ZONE_ID` | Optional zone IDs; otherwise resolved by DNS name |
| `CLOUDFLARE_STATIC_DNS_REQUIRED` | Require the static-host inventory; default `true` |
| `CLOUDFLARE_STATIC_DNS_SYNC` | Include static DNS actions in reconciliation planning; default `false` |
| `CF_AUTO_APPLY` | Enable unattended Cloudflare writes; default `false` |
| `YGG_LOG_FORMAT` | `text` (default) or newline-delimited `json` |
| `YGG_WATCH_COMPOSE` | Poll Compose YAML and inventory fingerprints for changes; default `true` |
| `YGG_WATCH_DOCKER` | Subscribe to Docker container/network events; default `true` |
| `YGG_WATCH_POLL_SECONDS` | Compose/inventory content check interval; default `15` seconds |
| `YGG_WATCH_DEBOUNCE_SECONDS` | Wait for changes to settle; default `20` seconds |
| `YGG_WATCH_COOLDOWN_SECONDS` | Minimum delay after an audit before another event-driven audit; default `60` seconds |
| `TZ` | UTC in the supplied Compose definition |

Compose also sets in-container paths for `YGGFLARE_CONFIG`, `YGGFLARE_DATA`, `YGGFLARE_BACKUP` and `YGGFLARE_SOURCE`.

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

## Logging and observability

Set `YGG_LOG_FORMAT=text` for timestamped, component-labelled stdout, or `YGG_LOG_FORMAT=json` for JSON lines with UTC `timestamp`, `level`, `component` and `message`. JSON lines can be parsed and indexed in Grafana Loki using an agent such as Grafana Alloy. The container writes to stdout and stderr; it does not require a separate log file.

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
fingerprint and a **ready-to-run host command**, for example:

```sh
docker exec yggflare yggflare cloudflare apply <approval-fingerprint> --max-operations 1
```

The CLI preserves the plan's `--max-operations` limit in the suggested
command. Applying requires the same live plan fingerprint and rechecks the
current Cloudflare state before each guarded write. If the plan changes,
the approval is rejected and must be reviewed again. Use the actual
fingerprint returned by your audit, not the example placeholder.

`CF_AUTO_APPLY=false` can remain set for manually approved changes; the
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

Neither the six-hour audit nor `CF_AUTO_APPLY=true` deletes resources.
The normal automatic reconciler remains **strictly non-destructive**.

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
copy the printed `docker exec yggflare yggflare cloudflare orphan-apply ...`
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
These timings can be customized through the `YGG_WATCH_*` variables above.
The normal Nmap/DNS-SD inventory scan remains **daily**, not on every Docker
event. Only the Cloudflare reconciliation is triggered reactively.

**Security:** a change notification merely requests the normal reconciliation
path. It does not alter the guarded plan, the operation limits, or
`CF_AUTO_APPLY`. With `CF_AUTO_APPLY=false`, every trigger remains
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

Cloudflare auditing can be verified by confirming zero proposed operations and zero unintended static DNS drift with `CF_AUTO_APPLY=false`. Before enabling unattended writes, independently validate write-path safeguards, network inventory alerts, persistence and backup recovery. Avoid running multiple automatic Cloudflare writers at the same time.
