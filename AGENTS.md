# AGENTS.md — Yggflare contributor and AI-agent guide

This file is repository-local context for developers and coding assistants. Read this and `README.md` before changing code. Treat actual source, tests and current GitHub state as authoritative when documentation may be stale.

## Purpose and boundaries

Yggflare is a Python 3.15 containerized controller for Cloudflare Access applications, Tunnel ingress and DNS reconciliation driven by merged Docker Compose and private JSON inventories. It also performs LAN Nmap/DNS-SD observations, Discord notifications, backups and health checks. Keep its default posture **read-only and fail-closed**.

- Public source repository: `ebertek/yggflare`. Main deployment configuration lives separately in **`ebertek/ebertek-compose`**, with private material in **`ebertek/ebertek-compose-secrets`**.
- **Do not edit the deployed `~/ygg-compose` checkout.** It is the merged runtime output; durable changes belong in the appropriate source repository and are synchronized by Komodo.
- The deployment host is commonly called Pleiades. Runtime paths inside Yggflare: `/compose-source` (read-only merged Compose), `/config` (read-only private inventories), `/data` (persistent state), `/backup` (archives) and `/run/secrets` (credentials). Do not put secrets in commits, PR descriptions, logs, fixtures or generated public artifacts.
- Licensing: Apache-2.0; preserve `LICENSE` and `NOTICE`.

## Code map

| Component | Responsibility |
|---|---|
| `controller.py` | UTC scheduler, Compose snapshot, heartbeat, Cloudflare/scan/backup execution |
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
| `web.py` | Optional read-only local HTTP inventory UI, once its feature PR is merged |
| `tests/`, `src/cloudflare/test_*.py`, `src/network-inventory/test_*.py` | Regression tests |

Some paths above may exist only in an open PR. Check `main` and merged state rather than assuming they have shipped.

## Non-negotiable safety invariants

1. Never mutate `/compose-source` or the deployed GitOps checkout. Snapshots must be temporary and private; inventory state lives under `/data`.
2. Never create or delete Cloudflare resources from a mere string match or from an untrusted API field. Validate account, zone, tunnel, hostname, object IDs, policies, duplicate resources, and the latest Compose source.
3. `CF_AUTO_APPLY` enables only explicitly guarded, bounded reconciliation. The separate orphan cleanup option is **off by default**. Do not treat an unmanaged Cloudflare resource as Yggflare-owned.
4. Ownership must be proven and persisted before any cleanup. Manual retirement uses a plan fingerprint and deletes **external DNS → Tunnel route → Access app**; leave Access protection until its route and DNS are gone. Preserve unrelated ingress routes. Recover safely after partial errors.
5. Never enable new external-facing listeners by default. A web UI must remain read-only and loopback-only unless protected by an authenticated reverse proxy/Access policy. Do not expose secret contents or unauthenticated operational actions.
6. Network scanning is bounded by configured LAN CIDRs. Avoid turning scan results into authoritative DNS changes automatically.
7. Discord webhook URLs and Cloudflare tokens are secrets. No credential values in exceptions, test output or logs.
8. Archive restoration tests operate only on private temporary storage; never overwrite production config, state or secrets. Block traversal, symlinks, hardlinks and extraction bombs.

## Build, test and release

- Image: `ghcr.io/ebertek/yggflare`. `:main` is development; `:vMAJOR.MINOR.PATCH` is stable. Prefer pinning to a digest in Compose so Renovate can update moving tags.
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
- Automatic orphan retirement with a minimum 24-hour grace period was developed in PR **#24**; verify merge and actual opt-in before claiming it operates in production.
- A read-only, spreadsheet-style inventory web UI, grouped by /27 with search/ports/DNS-SD/local ownership and CSV/JSON export, is being developed in PR **#25**. It is disabled by default. Check CI/Lint and merge status; do not assume a production endpoint exists.
- Follow-up enhancements should prioritize correctness and security (state validation, preservation of the LAN /27 organization, graceful handling of malformed or absent observations, and authenticated exposure), not additional web-server complexity.

## Working style for future sessions

The owner often works from a phone. **Make repository edits and open GitHub PRs rather than supplying standalone scripts, files or manual copy-paste patches.** Include tests and concise rationale; diagnose failing workflow logs and fix the same PR branch. Avoid unnecessary questions when the repository already contains the answer. Distinguish implemented, merged, deployed and production-verified features precisely.

Keep this guide evergreen. Update it when architecture or safety invariants change, but avoid embedding secrets, personal identifying information, ephemeral audit fingerprints or long status logs.
