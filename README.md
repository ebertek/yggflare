# Yggflare

Yggflare is a containerized Cloudflare and local network inventory controller. It reconciles Cloudflare Access applications, Tunnel routes and DNS against Compose definitions and JSON device inventories, and audits local network devices and exposed services.

## How it works

- Audits Cloudflare every six hours; writes are disabled by default (`CF_AUTO_APPLY=false`).
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
| `YGGFLARE_VERSION` | GHCR tag to pull; `main` tracks development until a versioned release is available |
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

## Image versions and releases

Published images are available at `ghcr.io/ebertek/yggflare`.

- `:main` tracks the continuously tested development branch. It is **not** a stable release tag.
- `:sha-<full-commit-sha>` identifies an exact build.
- `:vMAJOR.MINOR.PATCH` is produced when a matching Git tag is pushed, such as `:v1.0.0`.
- No `:latest` alias is published by this workflow.

Releases follow [Semantic Versioning](https://semver.org/): use `v1.0.0` for the first verified release, `v1.0.1` for compatible bug fixes and `v1.1.0` for backward-compatible features. The leading `v` denotes the Git/image tag; the semantic version is `1.0.0`. Prefer a pinned release tag (or digest) for deployed services:

```sh
export YGGFLARE_VERSION=v1.0.0
docker compose pull
docker compose up -d --no-build
```

**The first stable release tag has not been created.** The `v1.0.0` examples document the future deployment workflow; the actual release requires complete parity validation first.

## Validation

The repository includes Cloudflare, network-audit and controller unit tests; the CI workflow executes them and builds the image. Ruff and Black enforce Python style. The [publish workflow](.github/workflows/publish.yml) requires tests and lint to pass before uploading images.

Cloudflare auditing can be verified by confirming zero proposed operations and zero unintended static DNS drift with `CF_AUTO_APPLY=false`. Before enabling unattended writes, independently validate write-path safeguards, network inventory alerts, persistence and backup recovery. Avoid running multiple automatic Cloudflare writers at the same time.
