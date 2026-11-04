# AGENTS.md — Yggflare contributor and AI-agent guide

This file is repository-local context for developers and coding assistants. Read this and `README.md` before changing code. Treat actual source, tests and current GitHub state as authoritative when documentation may be stale.

## Purpose and boundaries

Yggflare is a Python 3.15 containerized controller for Cloudflare Access applications, Tunnel ingress and DNS reconciliation driven by merged Docker Compose and private JSON inventories. It also performs LAN Nmap/DNS-SD observations, Discord notifications, backups and health checks. Keep its default posture **read-only and fail-closed**.

- Public source repository: `ebertek/yggflare`. Main deployment Compose lives in **`ebertek/ebertek-compose`**. Private device inventories and retained DNS now live on the **mounted Yggflare `/config` volume**, not in `ebertek-compose-secrets` commits. Treat `/config` as the private source of truth; the container mounts it read-only.
- **Do not edit the deployed `~/ygg-compose` checkout.** It is the merged runtime output; durable public code and Compose changes belong in their respective source repositories. Private inventory edits belong on the host-mounted `/config` volume and must never be committed or mirrored into a public repository.
- The deployment host is commonly called Pleiades. Runtime paths inside Yggflare: `/compose-source` (read-only merged Compose), `/config` (read-only private inventories), `/data` (persistent state), `/backup` (archives) and `/run/secrets` (credentials). Do not put secrets in commits, PR descriptions, logs, fixtures or generated public artifacts.
- Licensing: Apache-2.0; preserve `LICENSE` and `NOTICE`.

## Code map

| Component | Responsibility |
|---|---|
| `controller.py` | UTC scheduler, Compose snapshot, heartbeat, Cloudflare/scan/backup execution |

The controller is the image's PID 1 by default. It must explicitly handle SIGTERM/SIGINT even without Docker Compose `init: true`, exit promptly during idle loops, and terminate active scheduled subprocess groups on shutdown. Preserve safe state boundaries: scans must not publish a partial successful snapshot; any partially applied Cloudflare operation must be reconciled on restart rather than assumed complete. Test shutdown against a real child process and check bounded TERM/KILL escalation.
| `watchers.py` | Compose/inventory fingerprint polling and Docker topology change triggers |
| `cli.py` | Container-facing `docker exec yggflare yggflare …` commands |
| `src/cloudflare/cloudflare-live.py` | Read-only live Cloudflare audit and drift assessment |
| `src/cloudflare/cloudflare-manage.py` | Guarded Cloudflare plan, approval and opt-in reconciliation |
| `src/cloudflare/cloudflare_orphans.py` | Ownership registry and fingerprint-approved deletion safeguards |
| `src/cloudflare/cloudflare-auto-cleanup.py` | Optional grace-period auto retirement; inspect code before enabling |
| `src/cloudflare/cloudflare_write_api.py` | Narrowly scoped Cloudflare writes; never add unrestricted delete functionality |
| `src/network-inventory/audit.py` | Nmap/DNS-SD scan, state observations and drift detection |
| `src/network-inventory/discord_format.py` | Grouped Discord webhook embeds |
| `backup.py`, `backup_verify.py`, `doctor.py` | Backups, isolated restore rehearsal, local diagnostics |
| `docker_inventory.py` | Sanitized, cached read-only Compose/Docker metadata for the web UI; never a reconciliation input |
| `web.py`, `web_views.py` | Read-only HTTP inventory, per-port services, drift history and Cloudflare lifecycle views |
| `src/cloudflare/cloudflare_view.py` | Allowlisted, atomic presentation snapshots; never used to authorize writes |
| `tests/`, `src/cloudflare/test_*.py`, `src/network-inventory/test_*.py` | Regression tests |

The inventory UI and automatic cleanup modules have landed on `main`. Check actual runtime deployment independently.

## Non-negotiable safety invariants

1. Never mutate `/compose-source` or the deployed GitOps checkout. Snapshots must be temporary and private; inventory state lives under `/data`.
2. Never create or delete Cloudflare resources from a mere string match or from an untrusted API field. Validate account, zone, tunnel, hostname, object IDs, policies, duplicate resources, and the latest Compose source.
3. `YGGFLARE_CLOUDFLARE_AUTO_APPLY` enables guarded reconciliation. The entire proposed action set must pass allowlist, duplicate, conflict and policy checks before any automatic work. Valid large plans use dependency-ordered progressive batches (default 3 operations per cycle, `YGGFLARE_CLOUDFLARE_AUTO_BATCH_SIZE`; explicit `0` opts into applying all validated actions). Manual fingerprint-approved plans have no fixed operation count ceiling unless `--max-operations` is set. `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP` is an independent deletion opt-in (default off; **enabled in the current `ebertek-compose` deployment source**) with `YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS=24`. Automatic retirement defaults to one independently revalidated owned orphan per cycle via `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP_BATCH_SIZE`; explicit `0` allows all eligible orphans and significantly increases deletion risk. Never treat an unmanaged Cloudflare resource as Yggflare-owned.
4. Ownership must be proven and persisted before any cleanup. Manual retirement uses a plan fingerprint and deletes **external DNS → Tunnel route → Access app**; leave Access protection until its route and DNS are gone. Preserve unrelated ingress routes. Recover safely after partial errors.
5. Never enable new external-facing listeners by default. A web UI must remain read-only and loopback-only unless protected by an authenticated reverse proxy/Access policy. Do not expose secret contents or unauthenticated operational actions.
6. Network scanning is bounded by configured LAN CIDRs. Avoid turning scan results into authoritative DNS changes automatically. Future inventory adoption should propose reviewed changes for the host-mounted `/config`, never mutate the read-only container mount or write to the merged Compose checkout.
7. Discord webhook URLs and Cloudflare tokens are secrets. No credential values in exceptions, test output or logs. Validate Discord webhook URL structure offline in `doctor` and before delivery using the shared `discord_webhook.py` helper; never print webhook IDs/tokens or turn malformed secret data into external HTTP requests.
8. Archive restoration tests operate only on private temporary storage; never overwrite production config, state or secrets. Block traversal, symlinks, hardlinks and extraction bombs.

## Environment variable convention

Use `YGGFLARE_*` for all Yggflare configuration (inventory, watch, logging, web, Cloudflare apply and orphan cleanup). Reserve `CLOUDFLARE_*` for actual Cloudflare API credentials and identity/resource settings. **Do not reintroduce `YGG_*` or `CF_*` aliases.** Update both `ebertek/yggflare` and `ebertek/ebertek-compose` when configuration changes, with compatible image and Compose released together.

Retained-DNS exceptions and inventory validation must use the validated
`YGGFLARE_INTERNAL_DOMAIN` rather than hardcoded example domains. Retained
records are read-only and scoped to that zone; never broaden their scope to
work around a validation failure. Keep public setup examples host-neutral.

## Build, test and release

- Image: `ghcr.io/ebertek/yggflare`. `:main` is development; `:vMAJOR.MINOR.PATCH` is stable. Prefer pinning to a digest in Compose so Renovate can update moving tags. The publish workflow passes `YGGFLARE_BUILD_VERSION` and `YGGFLARE_BUILD_REVISION` as Docker build args; the image exposes them for the early `[startup]` log and `yggflare --version`. Release logs must identify the real source commit; a local build without args deliberately reports `dev/unknown`. Keep the version/revision consistent with image OCI labels and test both text and JSON log modes.
- Before PR: run `ruff check .`, `black --check .`, and:
  ```bash
  python -m unittest discover -s tests -p 'test_*.py'
  python -m unittest discover -s src/cloudflare -p 'test_*.py'
  python -m unittest discover -s src/network-inventory -p 'test_*.py'
  ```
- CI, Lint, Python autofix and GHCR publish workflows are under `.github/workflows/`. Check **the latest PR head SHA** before declaring checks green; autofix can create additional commits.
- A `vX.Y.Z` tag triggers GHCR publishing. Release tags should represent reviewed `main` commits and must not be moved after publication. Consult the actual `publish.yml` for current `:main` tagging behavior.
- Use a feature branch and PR for durable changes. Do not make direct edits to production or assume merging/deployment occurred; verify it via GitHub/Komodo state.

## Operational verification (run on Pleiades; these are examples)

```bash
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare cloudflare plan --max-operations 1
docker exec yggflare yggflare backup verify <archive-name>.tar.gz
docker exec yggflare yggflare backup restore-test <archive-name>.tar.gz
docker exec yggflare yggflare network run
docker exec yggflare yggflare network discord-test
```

`network run` updates observation state and may send Discord drift alerts; `discord-test` deliberately sends a message. The other diagnostic/plan operations are designed to be read-only. Never run fingerprint-approved `apply` or `orphan-apply` without assessing the exact live plan and authorization.

## Current roadmap (verify on GitHub)

- **v1.0.0** was published November 2026 following live verification of Cloudflare lifecycle, 14/14 doctor checks, inventory scan, Discord delivery and isolated archive restore-test.
- Orphan cleanup (PR **#24**), read-only inventory UI (PR **#25**) and standardized environment naming without legacy aliases (PR **#27**) were merged. Companion `ebertek-compose` PRs **#229** and **#232** were also merged. Source merge is not proof that the latest runtime deployment or a specific endpoint has been verified.
- Environment configuration has **two namespaces only**: `YGGFLARE_*` for Yggflare app features and Cloudflare behavior, and `CLOUDFLARE_*` for connection/account/zone/tunnel settings. Old `YGG_*` and `CF_*` names are unsupported. The companion Compose migration pins a matching image digest to prevent mixed-version deployments.
- Deployment source enables `YGGFLARE_WEB_ENABLED=true`, `YGGFLARE_WEB_BIND=0.0.0.0`, and `YGGFLARE_WEB_PORT=8787`. Docker `network_mode: host` uses Traefik's explicit backend `http://10.4.21.1:8787`; `Scripts/startup/30-macvlan-host.sh` in `ebertek-compose` creates the Pleiades host-side macvlan shim `macvlan1-host` at `10.4.21.1/32`, enabling Traefik on `10.4.21.44` to reach the host. Cloudflare Access protects `yggflare.ebi.nu` but **does not protect direct LAN TCP/8787**: validate host firewall restrictions separately.
- Follow-up enhancements should prioritize correctness and security (state validation, preservation of the LAN /27 organization, graceful handling of malformed or absent observations, and authenticated exposure), not additional web-server complexity.

## Metrics and monitoring

Prometheus `/metrics` is opt-in via `YGGFLARE_METRICS_ENABLED=true` and is served on the existing read-only web HTTP listener. It reads bounded, persisted snapshots only; never trigger scanners, Docker inspection, Cloudflare API calls or mutation from a scrape. Keep metric series aggregate and low-cardinality: no hostname, IP, MAC, account, resource ID, token or user-controlled labels. The host-networked listener must be restricted to trusted scrape clients at the network/firewall layer; a Cloudflare Access policy does not protect direct LAN access.

## Working style for future sessions

The owner often works from a phone. **Make repository edits and open GitHub PRs rather than supplying standalone scripts, files or manual copy-paste patches.** Include tests and concise rationale; diagnose failing workflow logs and fix the same PR branch. Avoid unnecessary questions when the repository already contains the answer. Distinguish implemented, merged, deployed and production-verified features precisely.

Use separate commits for separate logical changes, even when they share a PR. Keep each commit understandable and testable on its own, with related tests and documentation alongside the change. Avoid bundling unrelated fixes or features into a single large commit.

The owner welcomes questions when requirements, tradeoffs or missing evidence materially affect the result. Ask for input in those cases while continuing independent work; use repository evidence and judgment for routine choices. Keep this guide up to date proactively as durable preferences and project conventions evolve.

The project currently has a single user; breaking changes are acceptable when needed. Do not add compatibility aliases or migration scaffolding solely for hypothetical external users. Keep the README concise and focused on current setup, supported functionality and configuration, not rename history or upgrade warnings. Still describe concrete deployment dependencies and keep image/config changes coordinated.

Keep this guide evergreen. Update it when architecture or safety invariants change, but avoid embedding secrets, personal identifying information, ephemeral audit fingerprints or long status logs.

## Inventory presentation invariants

- Keep numeric address/CIDR sorting consistent between initial HTML, browser sorting and exports. Missing/invalid addresses sort last.
- Docker metadata enriches presentation only. Never infer Cloudflare ownership from Docker status, or promote declared/inferred ports to scan-confirmed observations.
- Preserve Compose fallback when Docker is unavailable. Never expose raw environment, labels, inspection output or exception details through the UI. Keep Docker reads bounded and cached.

- With web enabled, controller refreshes the GET-only Cloudflare presentation snapshot after reconciliation attempts. Preserve last-good data and show failed/stale refreshes; never call Cloudflare on HTTP requests.
- Network state retains service detection metadata, resolved DNS-SD addresses (no TXT data), and at most 200 recent events. Keep scan-confirmed ports, probed identities, port-name hints and advertisements distinct.

- Existing inventory details (including hostnames, IPs and MACs) remain visible by default in pages and exports. `YGGFLARE_WEB_SHOW_SECRETS` is not implemented; do not use it to mask existing fields. Credentials and raw environment remain excluded.
- `inventory_view.py` derives review flags and static/observed diffs. Optional `device_class` and boolean `retired` are presentation metadata only: never change DNS/scanning/cleanup semantics based on them. Offline is not retired; unobserved ports are unknown, not closed.
- Scan state retains first/last-seen timestamps by LAN address. Display them as scan observations, not a live device heartbeat.

- Container destinations `/config`, `/data`, `/backup`, `/compose-source` are fixed. Do not reintroduce path or container-name environment knobs. The image owns `PYTHONPATH`; host bind sources remain configurable. Printed approvals and documentation use `docker exec yggflare`, which works from any directory. Do not use Compose exec commands. If the operator changes `container_name`, they substitute that name in the command.
- Docker inventory omits services without LAN endpoints and resolves shared-network parents uniquely (Compose service references within project). Never assign all parent ports to every child or infer process ownership from an endpoint scan.
- `inventory_catalog.py` projects optional reserved/retired JSON catalogs into separate read-only tabs, never reconciliation inputs. Missing/invalid optional catalogs must not disable the active UI. Private deployment schemas have not been verified from this public repository.
