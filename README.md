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
2. Run the Cloudflare and network inventory tests, then build the Docker image. The old import helper is for historical reference only.
3. Migrate configuration with `sudo ./scripts/migrate-config.sh /home/docker/ygg-compose /home/docker/yggflare` (copy only; DOES NOT modify either Git repository).
4. Supply Compose interpolation values using exported host environment variables or Komodo's environment configuration; do not create a `.env` file. Configure `CF_AUTO_APPLY=false` as a container environment value while shadow-testing.
5. Start shadow mode: `docker compose up -d`, inspect `docker compose logs -f`, and compare reports with the existing Komodo actions. Avoid concurrent auto writers.
6. Only after tests, parity, and backup restore drills, disable the legacy Komodo Cloudflare and inventory schedules, explicitly opt into unattended writes in `/config/cloudflare.env`, then enable the new controller's write mode using the Compose environment variable `CF_AUTO_APPLY=true`.

## Runtime configuration

There are **no application dotenv files** in Yggflare.

- **Compose environment (nonsecret):** `CF_AUTO_APPLY=false` (default), `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_TUNNEL_ID`, `CLOUDFLARE_EBI_ZONE_ID`, `CLOUDFLARE_YGG_ZONE_ID`, `TZ`, `YGGFLARE_HOME`, and `YGG_MERGED_ROOT`. Set them through Komodo or exported environment variables when running Compose. The IDs may also be resolved from `config/cloudflare-settings.json`; explicit Compose values override those settings.
- **Compose secrets:** `secrets/cloudflare_api_token` and `secrets/network_discord_webhook` on the host, mounted as `/run/secrets/cloudflare_api_token` and `/run/secrets/network_discord_webhook`. The Discord webhook is optional in behavior, but the Compose file expects the secret file to exist; create an empty file if unused. Never store either secret in a Compose environment value.
- **Persistent JSON:** `config/cloudflare-settings.json`, `config/static-hosts.json`, `config/retained-dns.json`, and optional reserved/retired device records.
- **Inventory schema:** use only `ports: [{"protocol":"tcp","port":443}]`; legacy `open_ports` is deliberately rejected by both Cloudflare inventory validation and the network auditor. Convert old inventory before starting the container.

For example, provide host configuration through Komodo or exported variables before `docker compose up -d`:

```bash
export YGGFLARE_HOME=/home/docker/yggflare
export YGG_MERGED_ROOT=/home/docker/ygg-compose
export CF_AUTO_APPLY=false
docker compose up -d
```

The migration helper **copies JSON and state only**, never imports the legacy `cloudflare.env` or `network-inventory.env`. Create secret files separately from secure original values and supply nonsecret identifiers in your deployment configuration.

## Important cutover safeguards

- Back up BOTH `/config` and `/data` to **separate durable storage**. The included snapshot script produces **plaintext** archives; store and replicate them securely. Never expose archives through web.
- Historical Git commits may still contain retired secrets. Review repository history and rotate credentials when appropriate.
- Do not remove files from `ebertek-compose-secrets` until the new service has been proven stable, ownership/backup is established, and you are ready to remove old readers.
- Never edit tracked files under `/home/docker/ygg-compose`; source changes go to `ebertek-compose` and private changes to `ebertek-compose-secrets`.
- Existing controller performs Docker socket inspection, and fails closed if desired Compose data is absent. Do not use `--skip-docker` as a production workaround.
- Initial scaffold has no externally exposed metrics or HTTP UI. Add health endpoints only when hardened and tested.

## Backups

The controller creates **daily snapshots at 04:00 Europe/Stockholm**, containing the `/config` and `/data` volumes. Archives have mode 0600 and are kept for 14 local snapshots. Backups are **plaintext**, and `/backup` must reside on protected persistent storage. Schedule off-host replication using an existing backup system, and test restoration before cutover. A manual host-side snapshot is also available with `sudo ./scripts/backup.sh /home/docker/yggflare`.

## Verification status

The imported source and new regression tests are in GitHub; the combined CI and Docker build results are not yet verified. Full Cloudflare API parity, Docker build, Nmap/Avahi behavior, and backup/restore have **not** been verified against the live Pleiades environment. Do not enable unattended writes before those checks.
