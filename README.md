# yggflare — staged migration starter

Standalone, always-running Cloudflare + LAN inventory controller for the Ygg homelab.

**Status:** migration scaffold in `ebertek/yggflare`, not a production-ready cutover. The old Komodo jobs must remain enabled during shadow-mode validation.

## Architecture

- A single long-lived process schedules Cloudflare reconciliation every six hours.
- Network inventory runs daily at 05:15 local time (Europe/Stockholm).
- `CF_AUTO_APPLY` defaults to `false`; existing `cloudflare-manage.py --auto` guard remains the only automatic write path.
- `/config` stores *unversioned* private JSON inventory and settings files, `/data` stores audit state and scheduling markers, and `/backup` stores local snapshots.
- `/compose-source` is a **read-only mount** of the deployed merged GitOps checkout. The controller builds a read-only-to-itself *working snapshot* of Compose YAML with private inventory injected from `/config`.
- The container needs host network access, host D-Bus for Avahi, and Docker inspection through the Docker socket. Mounting the Docker socket grants effective host-root privileges; review this risk before production.
- The container initially runs as root to preserve Nmap/ARP behavior; hardening to scoped capabilities or a Docker API proxy is a follow-up.

## Prepare source

1. The legacy controller and network-audit modules are now imported under `src/cloudflare` and `src/network-inventory`; the deployment must use this version-controlled source, not copy from the runtime checkout.
2. Run the Cloudflare and network inventory tests, then build the Docker image. No legacy source import is needed.
3. Migrate configuration with `sudo ./scripts/migrate-config.sh /home/docker/ygg-compose /home/docker/yggflare` (copy only; DOES NOT modify either Git repository).
4. Supply Compose interpolation values using exported host environment variables or Komodo's environment configuration; do not create a `.env` file. Configure `CF_AUTO_APPLY=false` as a container environment value while shadow-testing.
5. Start shadow mode: `docker compose up -d`, inspect `docker compose logs -f`, and compare reports with the existing Komodo actions. Avoid concurrent auto writers.
6. Only after tests, parity, and backup restore drills, disable the legacy Komodo Cloudflare and inventory schedules, enable unattended writes by setting the Compose environment variable `CF_AUTO_APPLY=true` after disabling the old writer.

## Portable network layout

All managed IP ranges and both DNS zones are set with Compose environment variables. No subnet or DNS zone is the application's default. Startup fails if a required value is missing or invalid. Example configuration for the original deployment (adjust for your own environment):

| Variable | Example | Role |
|---|---|---|
| `YGG_LAN_CIDR` | `10.4.20.0/23` | Total network inventory scan scope |
| `YGG_DEVICES_CIDR` | `10.4.20.0/24` | Eligible static device A records |
| `YGG_DOCKER_CIDR` | `10.4.21.0/24` | Docker container A records |
| `YGG_INTERNAL_DOMAIN` | `ygg.nu` | Internal DNS zone |
| `YGG_EXTERNAL_DOMAIN` | `ebi.nu` | External Cloudflare Access/Tunnel hostnames |

Tests explicitly set these values as fixture data. Existing `(no settings file)` retains other reconciliation settings; its zone names are overridden by these runtime environment variables.

## Runtime configuration

There are **no application dotenv files** in Yggflare.

- **Compose environment (nonsecret):** `YGG_LAN_CIDR`, `YGG_DEVICES_CIDR`, `YGG_DOCKER_CIDR`, `YGG_INTERNAL_DOMAIN`, `YGG_EXTERNAL_DOMAIN`, `CF_AUTO_APPLY=false` (default), `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_TUNNEL_ID`, `CLOUDFLARE_EXTERNAL_ZONE_ID`, `CLOUDFLARE_INTERNAL_ZONE_ID`, `TZ`, `YGGFLARE_HOME`, and `YGG_MERGED_ROOT`. Set them through Komodo or exported environment variables when running Compose. All identifiers and switches are provided through environment variables.
- **Compose secrets:** `secrets/cloudflare_api_token` and `secrets/network_discord_webhook` on the host, mounted as `/run/secrets/cloudflare_api_token` and `/run/secrets/network_discord_webhook`. The Discord webhook is optional in behavior, but the Compose file expects the secret file to exist; create an empty file if unused. Never store either secret in a Compose environment value.
- **Persistent JSON:** `config/static-hosts.json`, `config/retained-dns.json`, and optional reserved/retired device records.
- **Inventory schema:** use only `ports: [{"protocol":"tcp","port":443}]`; legacy `open_ports` is deliberately rejected by both Cloudflare inventory validation and the network auditor. Convert old inventory before starting the container.

For example, provide host configuration through Komodo or exported variables before `docker compose up -d`:

```bash
export YGGFLARE_HOME=/home/docker/yggflare
export YGG_MERGED_ROOT=/home/docker/ygg-compose
export CF_AUTO_APPLY=false
export YGG_LAN_CIDR=10.4.20.0/23
export YGG_DEVICES_CIDR=10.4.20.0/24
export YGG_DOCKER_CIDR=10.4.21.0/24
export YGG_INTERNAL_DOMAIN=ygg.nu
export YGG_EXTERNAL_DOMAIN=ebi.nu
docker compose up -d
```

The migration helper **copies JSON and state only**, never imports the legacy `cloudflare.env` or `network-inventory.env`. Create secret files separately from secure original values and supply nonsecret identifiers in your deployment configuration.

## Important cutover safeguards

- Back up `/config`, `/data`, and the Compose secrets to **separate durable storage**. The included snapshot script produces **plaintext** archives; store and replicate them securely. Never expose archives through web.
- Historical Git commits may still contain retired secrets. Review repository history and rotate credentials when appropriate.
- Do not remove files from `ebertek-compose-secrets` until the new service has been proven stable, ownership/backup is established, and you are ready to remove old readers.
- Never edit tracked files under `/home/docker/ygg-compose`; source changes go to `ebertek-compose` and private changes to `ebertek-compose-secrets`.
- Existing controller performs Docker socket inspection, and fails closed if desired Compose data is absent. Do not use `--skip-docker` as a production workaround.
- Initial scaffold has no externally exposed metrics or HTTP UI. Add health endpoints only when hardened and tested.

## Backups

The controller creates **daily snapshots at 04:00 Europe/Stockholm**, containing `/config`, `/data`, and the mounted Compose secrets. Archives have mode 0600 and are kept for 14 local snapshots. Backups are **plaintext**, and `/backup` must reside on protected persistent storage. Schedule off-host replication using an existing backup system, and test restoration before cutover. A manual host-side snapshot is also available with `sudo ./scripts/backup.sh /home/docker/yggflare`.

## Verification status

The imported source and new regression tests are in GitHub; the combined CI and Docker build results are not yet verified. Full Cloudflare API parity, Docker build, Nmap/Avahi behavior, and backup/restore have **not** been verified against the live Pleiades environment. Do not enable unattended writes before those checks.

## Python quality automation

- [Lint](.github/workflows/lint.yml) runs Ruff checks, Black formatting checks, and Python compilation on pull requests and pushes to `main`.
- [Python autofix](.github/workflows/python-autofix.yml) runs on non-`main` branches within this repository, applying Ruff safe fixes followed by Black and committing the result when files change. Forked PRs never receive write credentials.
- Both workflows pin formatter versions. Run locally with:
  ```sh
  python -m pip install "ruff==0.14.14" "black==25.12.0"
  ruff check --fix .
  black .
  ruff check .
  black --check .
  ```
- The imported source may need an initial formatting pass to make the new checks green. Branch autofix does not rewrite `main` automatically.

## Cloudflare configuration (environment-only)

The former JSON settings file is obsolete. Set:
- `CLOUDFLARE_ACCOUNT_ID` (required).
- `CLOUDFLARE_TUNNEL_NAME` or `CLOUDFLARE_TUNNEL_ID` (at least one).
- `YGG_EXTERNAL_DOMAIN`, `YGG_INTERNAL_DOMAIN` (required).
- `CLOUDFLARE_EXTERNAL_ZONE_ID`, `CLOUDFLARE_INTERNAL_ZONE_ID` (optional explicit IDs; zone names are resolved from the domain variables otherwise).
- `CLOUDFLARE_STATIC_DNS_REQUIRED=true` and `CLOUDFLARE_STATIC_DNS_SYNC=false` (strict boolean values; auto-write disabled by default).
- `CF_AUTO_APPLY=false` until after parity validation and legacy writer shutdown.

Credential tokens and webhooks remain in Compose secrets, never environment variables. Existing private JSON inventories are still stored in `/config`; only the *settings* JSON is removed.
