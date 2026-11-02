# yggflare — staged migration starter

Standalone, always-running Cloudflare + LAN inventory controller for the Ygg homelab.

**Status:** migration scaffold in `ebertek/yggflare`, not a production-ready cutover. The old Komodo jobs must remain enabled during shadow-mode validation.

## Architecture

- A single long-lived process schedules Cloudflare reconciliation every six hours.
- Network inventory runs daily at 05:15 local time (Europe/Stockholm).
- `CF_AUTO_APPLY` defaults to `false`; existing `cloudflare-manage.py --auto` guard remains the only automatic write path.
- `/config` stores *unversioned* private JSON and `.env` files, `/data` stores audit state and locking files, `/backup` is a distinct backup destination.
- `/compose-source` is a **read-only mount** of the deployed merged GitOps checkout. The controller builds a read-only-to-itself *working snapshot* of Compose YAML with private inventory injected from `/config`.
- The container needs host network access, host D-Bus for Avahi, and Docker inspection through the Docker socket. Mounting the Docker socket grants effective host-root privileges; review this risk before production.
- The container initially runs as root to preserve Nmap/ARP behavior; hardening to scoped capabilities or a Docker API proxy is a follow-up.

## Prepare source

1. The legacy controller and network-audit modules are now imported under `src/cloudflare` and `src/network-inventory`; the deployment must use this version-controlled source, not copy from the runtime checkout.
2. Run the Cloudflare and network inventory tests, then build the Docker image. The old import helper is for historical reference only.
3. Migrate configuration with `sudo ./scripts/migrate-config.sh /home/docker/ygg-compose /home/docker/yggflare` (copy only; DOES NOT modify either Git repository).
4. Edit `.env` from `.env.example` for host locations. Set `CF_AUTO_APPLY=false` in the *unversioned* `config/cloudflare.env` while shadow-testing.
5. Start shadow mode: `docker compose up -d`, inspect `docker compose logs -f`, and compare reports with the existing Komodo actions. Avoid concurrent auto writers.
6. Only after tests, parity, and backup restore drills, disable the legacy Komodo Cloudflare and inventory schedules, explicitly opt into unattended writes in `/config/cloudflare.env`, then enable the new controller's write mode.

## Important cutover safeguards

- Back up BOTH `/config` and `/data` to **separate durable storage**. The included snapshot script produces **plaintext** archives; store and replicate them securely. Never expose archives through web.
- Historical Git commits may still contain retired secrets. Review repository history and rotate credentials when appropriate.
- Do not remove files from `ebertek-compose-secrets` until the new service has been proven stable, ownership/backup is established, and you are ready to remove old readers.
- Never edit tracked files under `/home/docker/ygg-compose`; source changes go to `ebertek-compose` and private changes to `ebertek-compose-secrets`.
- Existing controller performs Docker socket inspection, and fails closed if desired Compose data is absent. Do not use `--skip-docker` as a production workaround.
- Initial scaffold has no externally exposed metrics or HTTP UI. Add health endpoints only when hardened and tested.

## Backups

For an initial manually-triggered snapshot, run `sudo ./scripts/backup.sh /home/docker/yggflare`. Schedule this script with your host backup system (for example, Komodo or the existing off-host backup job), **replicate archives off-host**, and test restoration before cutover. The scaffold does not yet install a schedule or guarantee backups happen automatically.

## Verification status

The imported source and new regression tests are in GitHub; the combined CI and Docker build results are not yet verified. Full Cloudflare API parity, Docker build, Nmap/Avahi behavior, and backup/restore have **not** been verified against the live Pleiades environment. Do not enable unattended writes before those checks.
