# AGENTS.md — Yggflare contributor and AI-agent guide

This file is repository-local context for developers and coding assistants. Read this, `README.md` and [development](docs/development.md) before changing code. Treat actual source, tests and current GitHub state as authoritative when documentation may be stale.

## Purpose and boundaries

Yggflare is a Python 3.15 containerized controller for Cloudflare Access applications, Tunnel ingress and DNS reconciliation driven by merged Docker Compose and private JSON inventories. It also performs LAN Nmap/DNS-SD observations, Discord notifications, backups and health checks. Keep its default posture **read-only and fail-closed**.

- Public source repository: `ebertek/yggflare`. Main deployment Compose lives in **`ebertek/ebertek-compose`**. Private device inventories and retained DNS now live on the **mounted Yggflare `/config` volume**, not in `ebertek-compose-secrets` commits. Treat `/config` as the private source of truth; the container mounts it read-only.
- **Do not edit the deployed `~/ygg-compose` checkout.** It is the merged runtime output; durable public code and Compose changes belong in their respective source repositories. Private inventory edits belong on the host-mounted `/config` volume and must never be committed or mirrored into a public repository.
- The deployment host is commonly called Pleiades. Runtime paths inside Yggflare: `/compose-source` (read-only merged Compose), `/config` (read-only private inventories), `/data` (persistent state), `/backup` (archives) and `/run/secrets` (credentials). Do not put secrets in commits, PR descriptions, logs, fixtures or generated public artifacts.
- Licensing: Apache-2.0; preserve `LICENSE` and `NOTICE`.

## Code map

| Component | Responsibility |
|---|---|
| `src/yggflare/controller.py` | UTC scheduler, Compose snapshot, heartbeat, Cloudflare/scan/backup execution |
| `src/yggflare/watchers.py` | Compose/inventory fingerprint polling and Docker topology change triggers |
| `src/yggflare/cli.py` | Container-facing `docker exec yggflare yggflare …` commands |
| `src/cloudflare/cloudflare-live.py` | Read-only live Cloudflare audit and drift assessment |
| `src/cloudflare/cloudflare-manage.py` | Guarded Cloudflare plan, approval and opt-in reconciliation |
| `src/cloudflare/cloudflare_orphans.py` | Ownership registry and fingerprint-approved deletion safeguards |
| `src/cloudflare/cloudflare-auto-cleanup.py` | Optional grace-period auto retirement; inspect code before enabling |
| `src/cloudflare/cloudflare_write_api.py` | Narrowly scoped Cloudflare writes; never add unrestricted delete functionality |
| `src/network_inventory/audit.py` | Nmap/DNS-SD scan, state observations and drift detection |
| `src/network_inventory/device_identity.py` | Vendor-neutral, uncertain MAC/IP identity correlation and bounded history |
| `src/network_inventory/status.py` | Read-only CLI summary of persisted network findings and identity conflicts |
| `src/network_inventory/link_discovery.py`, `discovery_ra.py` | Scoped neighbour/Nmap/RA collection; RA metadata must never generate device IP candidates |
| `src/network_inventory/discord_format.py` | Grouped Discord webhook embeds |
| `src/network_inventory/alert_policy.py` | Confirm volatile TCP/DNS-SD signals before Discord, preserving immediate identity drift |
| `src/yggflare/backup.py`, `src/yggflare/backup_verify.py`, `src/yggflare/doctor.py` | Backups, isolated restore rehearsal, local diagnostics |
| `src/yggflare/docker_inventory.py` | Sanitized, cached read-only Compose/Docker metadata for the web UI; never a reconciliation input |
| `src/yggflare/mcp_server.py`, `src/yggflare/mcp_http.py` | Read-only MCP tools and opt-in authenticated Streamable HTTP |
| `src/yggflare/web.py`, `src/yggflare/web_views.py` | Read-only HTTP inventory, per-port services, drift history and Cloudflare lifecycle views |
| `src/cloudflare/cloudflare_view.py` | Allowlisted, atomic presentation snapshots; never used to authorize writes |
| `tests/application/`, `tests/cloudflare/`, `tests/network_inventory/` | Regression tests |

The controller is the image's PID 1 by default. It must explicitly handle SIGTERM/SIGINT even without Docker Compose `init: true`, exit promptly during idle loops, and terminate active scheduled subprocess groups on shutdown. Preserve safe state boundaries: scans must not publish a partial successful snapshot; any partially applied Cloudflare operation must be reconciled on restart rather than assumed complete. Test shutdown against a real child process and check bounded TERM/KILL escalation.

The inventory UI and automatic cleanup modules have landed on `main`. Check actual runtime deployment independently.

## Non-negotiable safety invariants

1. Never mutate `/compose-source` or the deployed GitOps checkout. Snapshots must be temporary and private; inventory state lives under `/data`.
2. Never create or delete Cloudflare resources from a mere string match or from an untrusted API field. Validate account, zone, tunnel, hostname, object IDs, policies, duplicate resources, and the latest Compose source.
3. `YGGFLARE_CLOUDFLARE_AUTO_APPLY` enables guarded reconciliation. The entire proposed action set must pass allowlist, duplicate, conflict and policy checks before any automatic work. For unattended Access app creation/updates, require at least one live reusable `allow` **or** `bypass` policy before exactly one terminal `deny`; revalidate decisions against Cloudflare immediately before each write. A bypass decision is not proof its selector is narrow; do not automatically invent or broaden policy rules. Error messages should identify the affected hostname and selected policy names/decisions, not leak selectors or secrets. Valid large plans use dependency-ordered progressive batches (default 3 operations per cycle, `YGGFLARE_CLOUDFLARE_AUTO_BATCH_SIZE`; explicit `0` opts into applying all validated actions). Manual fingerprint-approved plans have no fixed operation count ceiling unless `--max-operations` is set. `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP` is an independent deletion opt-in (default off; **enabled in the current `ebertek-compose` deployment source**) with `YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS=24`. Automatic retirement defaults to one independently revalidated owned orphan per cycle via `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP_BATCH_SIZE`; explicit `0` allows all eligible orphans and significantly increases deletion risk. Never treat an unmanaged Cloudflare resource as Yggflare-owned.
4. Ownership must be proven and persisted before any cleanup. Manual retirement uses a plan fingerprint and deletes **external DNS → Tunnel route → Access app**; leave Access protection until its route and DNS are gone. Preserve unrelated ingress routes. Recover safely after partial errors.
5. Never enable new external-facing listeners by default. A web UI must remain read-only and loopback-only unless protected by an authenticated reverse proxy/Access policy. Do not expose secret contents or unauthenticated operational actions. MCP HTTP is disabled by default, uses a separate loopback listener, requires a private bearer token, rejects browser origins and validates exact Host headers. Never add mutation tools or enable wildcard binds. Inventory presentation may distinguish explicit shared namespaces, local macvlan interface evidence, observed discrepancies, inconclusive observations and historical findings, but must preserve conflicting evidence and never turn those classifications into reconciliation or alert-suppression inputs.
6. Network scanning is bounded by configured LAN CIDRs. Avoid turning scan results into authoritative DNS changes automatically. Optional `YGGFLARE_DISCOVERY_RA` requires explicit IPv6 scope and interfaces, sends a short `rdisc6` solicitation on each, treats no-reply status 2 as normal, and stores only numeric, scoped topology hints with an empty device IP. Never promote RA prefixes or link-local router addresses into Nmap targets, confirmed identities, Discord alerts, DNS or Cloudflare writes. Future inventory adoption should propose reviewed changes for the host-mounted `/config`, never mutate the read-only container mount or write to the merged Compose checkout.
7. Discord webhook URLs and Cloudflare tokens are secrets. No credential values in exceptions, test output or logs. Validate Discord webhook URL structure offline in `doctor` and before delivery using the shared `src/yggflare/discord_webhook.py` helper; never print webhook IDs/tokens or turn malformed secret data into external HTTP requests.
8. Archive restoration tests operate only on private temporary storage; never overwrite production config, state or secrets. Block traversal, symlinks, hardlinks and extraction bombs.

## Environment variable convention

Use `YGGFLARE_*` for all Yggflare configuration (inventory, watch, logging, web, Cloudflare apply and orphan cleanup). Reserve `CLOUDFLARE_*` for actual Cloudflare API credentials and identity/resource settings. **Do not reintroduce `YGG_*` or `CF_*` aliases.** Update both `ebertek/yggflare` and `ebertek/ebertek-compose` when configuration changes, with compatible image and Compose released together.

Retained-DNS exceptions and inventory validation must use the validated
`YGGFLARE_INTERNAL_DOMAIN` rather than hardcoded example domains. Retained
records are read-only and scoped to that zone; never broaden their scope to
work around a validation failure. Keep public setup examples host-neutral.

## Build, test and release

Source is under `src/`; all regression tests are under `tests/`. Keep runtime `/app` paths stable when moving repository files. Runtime dependencies are in `requirements.txt`. See [development](docs/development.md) for the exact CI fixture environment and setup.

- Image: `ghcr.io/ebertek/yggflare`. `:main` is development; `:vMAJOR.MINOR.PATCH` is stable. Prefer pinning to a digest in Compose so Renovate can update moving tags. The publish workflow passes `YGGFLARE_BUILD_VERSION` and `YGGFLARE_BUILD_REVISION` as Docker build args; the image exposes them for the early `[startup]` log and `yggflare --version`. Release logs must identify the real source commit; a local build without args deliberately reports `dev/unknown`. Keep the version/revision consistent with image OCI labels and test both text and JSON log modes.
- Before PR: run `ruff check .`, `black --check .`, and:
  ```bash
  export PYTHONPATH=src/yggflare:src/cloudflare:src/network_inventory
  python -m unittest discover -s tests/application -p 'test_*.py'
  python -m unittest discover -s tests/cloudflare -p 'test_*.py'
  python -m unittest discover -s tests/network_inventory -p 'test_*.py'
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
docker exec yggflare yggflare network status --details
docker exec yggflare yggflare network run
docker exec yggflare yggflare network discord-test
```

`network status` and `network status --details` only read the saved scan and never trigger scans, notifications or Cloudflare requests. `network run` updates observation state and may send Discord drift alerts; `discord-test` deliberately sends a message. The other diagnostic/plan operations are designed to be read-only. Never run fingerprint-approved `apply` or `orphan-apply` without assessing the exact live plan and authorization.

## Current roadmap (verify on GitHub)

- Track implementation in [issue #65](https://github.com/ebertek/yggflare/issues/65) and the [v1.4.0 release candidate](docs/release-v1.4.0.md). PRs #76–89 are merged as of November 26, 2026. Latest published release at this review is v1.3.0; v1.4.0 is proposed, not yet published.
- The assurance, discovery, integration, interface, security and resilience cycle has landed in source. Keep production verification and final tag/image publication separate from source checks. Technitium integration remains deferred. UniFi work is resumed as a separate DNS migration and evidence initiative; keep the preflight GET-only, and require live API/PTR validation before designing guarded writes.
- Deployment-specific settings may change independently. Check the actual deployment source and current runtime rather than relying on historical host addresses, binds or image pins. Cloudflare Access on a public hostname does not protect direct LAN access to the underlying listener.
- Prioritize correctness, evidence quality, bounded inputs and security. Do not introduce new collectors or mutation paths merely to fill a roadmap item.

## Metrics and monitoring

Prometheus `/metrics` is opt-in via `YGGFLARE_METRICS_ENABLED=true` and is served on the existing read-only web HTTP listener. It reads bounded, persisted snapshots only; never trigger scanners, Docker inspection, Cloudflare API calls or mutation from a scrape. Keep metric series aggregate and low-cardinality: no hostname, IP, MAC, account, resource ID, token or user-controlled labels. The host-networked listener must be restricted to trusted scrape clients at the network/firewall layer; a Cloudflare Access policy does not protect direct LAN access.

## Adapter and probe safety

- `src/yggflare/integration_inventory.py` reads only Komodo's documented list RPCs and Kuma's Prometheus metrics. Never expose a generic API call, use a write/execute endpoint, return raw API responses or use admin credentials. Prefer explicitly configured, fixed-path read-only Docker secret mounts; legacy private config files retain strict private permissions. Never copy secrets into the config directory as a deployment workaround, read arbitrary paths or fall back after an explicitly selected secret fails. The read-only presentation paths must not load credentials.
- `src/yggflare/probe_inventory.py` runs only privately declared targets. Connect to explicitly scoped numeric addresses, use normal TLS verification and HTTP HEAD by default or explicitly configured GET /, reading headers only without following redirects. DNS answers never authorize additional connection targets. Only the scheduler and explicit local CLI refresh may initiate collection.
- UniFi collection and DNS previews use only GET and direct scoped DNS queries. The separate guarded UniFi writer can only create an approved IPv4 A policy with the existing fixed-path UniFi Compose secret. Recompute live planning inputs and gateway replies before creating, journal intent durably, and require its exact returned policy ID plus live policy and DNS verification before recording ownership. An uncertain acknowledgement blocks further creates. Automatic creates require a verified same-target manual pilot, explicit hostname allowlist and opt-in, and are limited to one per cycle. Never update or delete existing UniFi policies from this path.
- A complete collection is not proof that all resources are visible, all checks passed, or the endpoint is reachable externally. Keep the most recent successful collection on failed refresh; never report an unavailable source as an empty healthy inventory.
- MCP global group restrictions are an upper bound. Opt-in HTTP principal mode dispatches each authenticated request to a separately scoped stateless server; no fallback to the legacy token, arbitrary token paths, non-loopback bind or cross-group calls. Principal servers share the global concurrency limit. This is group-level authorization, not resource tenancy. Cross-source queries require all relevant groups. Keep local CLI and Web UI authorization separate from MCP. Log only fixed operation names, elapsed time and outcomes, never query arguments or payloads.

## Finding lifecycle and evidence

Structured finding history is presentation-only and must not alter alert suppression, delivery, inventory or reconciliation. Missing observations are never proof of resolution; require positive evidence for an inventory match. Preserve incomplete sources, explicitly bound retention and do not fabricate pre-upgrade history. Keep source availability, collection outcome, freshness and coverage independent. Treat snapshot IDs as filtered result-set fingerprints, not frozen snapshots.

## Operator interface parity

New evidence collectors and assurance features must have a shared sanitized query layer and be available through the read-only Web UI, operator CLI and MCP where applicable. Keep explicit action commands separate from evidence views; rendering, JSON output and MCP requests must not trigger network collectors, reconciliation or mutations. Document commands and views, and test all three interfaces. Do not expose raw adapter payloads, credentials, untrusted HTML or terminal control characters.

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
- `src/yggflare/inventory_view.py` derives review flags and static/observed diffs. Optional `device_class` and boolean `retired` are presentation metadata only: never change DNS/scanning/cleanup semantics based on them. Offline is not retired; unobserved ports are unknown, not closed.
- Scan state retains first/last-seen timestamps by LAN address and a separate bounded `identity_history` keyed only by declared inventory identity, unique MAC evidence, or provisional address observation. Competing MAC claims and shared/proxy MACs must never be silently merged. Preserve confidence labels, provenance, explicit uncertainty, and `not observed != offline`. The `identity_changes` timeline is strictly informational and cannot authorize inventory/DNS changes.
- New TCP ports and DNS-SD service identities require two consecutive successful observations by default (`YGGFLARE_NETWORK_ALERT_CONFIRM_SCANS`, valid 1-10). Keep raw observations and active drift immediately visible; suppress only the *Discord notification* until confirmed. No reply or incomplete DNS-SD browsing is not evidence of withdrawal. Preserve pending Discord delivery independently from alert confirmations, and prevent replays when migrating old state. Identity changes (new device, MAC/IP drift) must still alert immediately.
- Scheduled subprocess logs identify reconciliation, managed orphan cleanup, presentation refresh and network scans independently, including wall-clock durations, outcomes and interrupt handling; never log command arguments or secrets.

- Container destinations `/config`, `/data`, `/backup`, `/compose-source` are fixed. Do not reintroduce path or container-name environment knobs. The image owns `PYTHONPATH`; host bind sources remain configurable. Printed approvals and documentation use `docker exec yggflare`, which works from any directory. Do not use Compose exec commands. If the operator changes `container_name`, they substitute that name in the command.
- Docker inventory omits services without LAN endpoints and resolves shared-network parents uniquely (Compose service references within project). Never assign all parent ports to every child or infer process ownership from an endpoint scan.
- `src/yggflare/inventory_catalog.py` projects optional reserved/retired JSON catalogs into separate read-only tabs, never reconciliation inputs. Missing/invalid optional catalogs must not disable the active UI. Private deployment schemas have not been verified from this public repository.

Paged MCP tools must expose the shared typed page envelope and accept the preceding result-set fingerprint. Preserve existing source context in structured serialization; validate the full filtered set before slicing. Nested evidence is not a frozen multi-source snapshot.

Cross-source ingress evidence must preserve the original ingress tool's access groups; a distinct combined tool requires every source group it reads. Exact project/stack or hostname matches are candidates, not authoritative ownership or external reachability. Never initiate live checks from presentation methods.

Discovery coverage is presentation-only: Nmap run completion, represented targets, explicit timeouts and omitted targets are distinct evidence. Never infer host failure or port closure from omitted `--open` results. Do not alter scan scope, alert suppression or reconciliation when adding coverage metadata.

Monitoring correlation may use only exact saved service aliases/hostnames and explicitly declared or observed service addresses. Report match provenance and shared-address ambiguity; never infer service identity from a common proxy IP, arbitrary DNS lookups, or unspecified host-mode addresses. HTTP expected status is an operator expectation, not proof of authentication or application health.

Supplemental collector coverage uses fixed source names and aggregate invocation counts. Explicit no-reply outcomes are not failures; parsing errors, limits and missing execution evidence must remain distinct. Do not add raw subprocess output, credential data or addresses to coverage metadata.

Monitor metadata must be type-aware; literal null and placeholder URLs must not become endpoint evidence. Docker friendly names are weak candidates, never actual Docker target identity. Device monitoring correlation uses exact saved numeric addresses only. Preserve ambiguity, independent source timestamps and read-only authorization. SMB anonymous listings require already observed SMB ports, retain validated configurable target limits (1–4096) and bounded concurrency (1–16 workers), and export only fixed outcome counts, never raw diagnostics. CLI all-pages aggregation must reject changed snapshots and remain bounded.

Use one service snapshot within cross-source correlation, exact filters before pagination, and distinguish layer page truncation from upstream truncation. Selected TCP port sets are primary scan metadata; missing positive evidence never means a closed port. Do not infer IPv6 observations from IPv4 ports.

Komodo tracked stack input comparisons must read only existing Git objects in /compose-source during refresh, with fixed bounded commands and no remote access or checkout. Export status only, never manifest contents or private configuration values. Repository revision inequality alone is not stack drift; unchanged tracked inputs are not proof of equivalent runtime or all external inputs.

Monitoring selection summaries are global port-set comparisons, not proof of a scan against an endpoint. Never promote monitor targets into scans automatically. Configured probe coverage and historical check outcomes must remain independent, with HTTP pass requiring explicit expected-status match. Invalid/partial/duplicate snapshots remain unavailable. Metrics must be aggregate, omit unknown outcome counts, and perform no Git or live Docker/network operations. MCP keeps group requirements, bounded filters and valid finite JSON.
