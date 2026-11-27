# AGENTS.md

Read [README.md](README.md) and [development](docs/development.md) before
editing. Source, tests and current GitHub state take precedence over stale docs.

## Repository boundaries

- `ebertek/yggflare` owns the Python application and image.
- `ebertek/ebertek-compose` owns public deployment configuration.
- Never edit the merged runtime `~/ygg-compose` checkout. Runtime Compose
  is mounted read-only at `/compose-source`.
- Private inventories and retained DNS live on the host-mounted `/config`
  volume, not in public source. Container mounts `/config` read-only.
- Persistent state: `/data`; archives: `/backup`; credentials: `/run/secrets`.
  Keep these paths fixed. Host bind sources are configurable.
- Preserve `LICENSE` and `NOTICE` (Apache-2.0).

Use feature branches and PRs. Do not deploy, restart or mutate production
without explicit authorization. Never commit secrets, private inventory,
raw API responses, logs or credentials. Verify the actual host, source
repository and image revision before giving runtime instructions.

## Source and tests

| Directory                | Purpose                                                      |
| ------------------------ | ------------------------------------------------------------ |
| `src/yggflare/`          | Scheduler, CLI, Web UI, MCP, integrations, backup and doctor |
| `src/cloudflare/`        | Cloudflare discovery, audit, guarded writes and ownership    |
| `src/network_inventory/` | Network discovery, identity, state and alerts                |
| `tests/`                 | Application, Cloudflare and network regression suites        |
| `docs/`                  | Current user and developer guides                            |

Preserve runtime `/app` paths and CLI entry points. Use
`docker exec yggflare yggflare ...` in operator documentation, not Compose
exec or host Python scripts. The controller handles SIGTERM/SIGINT, including
without Docker init; terminate active child process groups with bounded
TERM/KILL escalation. Never publish partial success or assume interrupted
mutations completed.

Follow [development](docs/development.md) for Python 3.15, fixture environment,
Ruff, Black, compilation, separate unittest suites and image build.
Run relevant checks before committing. Inspect the latest PR head SHA
because autofix can add commits. Source merge, CI, image publication and
production acceptance are distinct. Never move a published version tag.

## Reconciliation safety

### Cloudflare

- Default to read-only and fail closed. Validate account, zone, tunnel,
  hostname, IDs, policies, duplicates and current declarations.
- Validate the entire plan before automatic work. Unattended Access creation
  and updates require reusable allow/bypass before one terminal deny.
  Recheck decisions before writes; never invent or broaden selectors.
- Create protected hostnames in Access → Tunnel → DNS order.
  Manual apply requires the exact fresh fingerprint. Automatic apply is
  opt-in and bounded by the configured batch size.
- Bulk claims require explicit manual invocation or a separate automatic claim
  opt-in; validate exact declarations and current resource identity, never replace
  existing ownership, and exclude retained records and aliases. Internal claims
  do not authorize deletion.
- Preserve unrelated routes and records. Only proven owned resources may
  be retired. External cleanup requires its own opt-in and grace period;
  delete external DNS → Tunnel route → Access app with live revalidation.
  Internal automatic cleanup is separately opt-in, Docker A only, with
  continuous observed grace, complete fresh retirement evidence, exact-ID
  DELETE intent and acknowledgement, and verified absence before releasing
  ownership. Never replay an ambiguous DELETE. Static and unmanaged records
  remain review-only unless an operator explicitly approves a fresh,
  single-host legacy Docker A adoption fingerprint. Legacy adoption writes
  ownership only, never deletes or backdates grace. Static records remain
  review-only. Recover safely from partial writes.
- Internal DNS creation must obey the configured allocation and opt-ins.
  Docker creates require unique, agreeing Compose/runtime evidence.
  Static, alias, retained and conflicting records are protected.
  Check live internal-zone quota and reserve as required by the plan.
- Never authorize writes using scan observations, UI projections, guessed
  names or raw remote fields.

### UniFi

- Collector and DNS preview use bounded GET and direct scoped DNS only.
  Require a fixed numeric origin, verified TLS, selected site and private
  fixed-path credentials. No insecure TLS or arbitrary requests.
- The guarded writer creates or manually repairs approved IPv4 A policies using the
  mounted UniFi secret. Revalidate exact fingerprints, declarations,
  Cloudflare, gateway replies and policy list before writing.
- Journal intent before POST or PUT; require acknowledged policy ID and matching
  policy/A/PTR replies before recording ownership. Unknown outcome or
  unresolved pending operation blocks further creates. Never duplicate POST.
- Automatic creation requires explicit opt-in, verified same-target manual
  pilot and exact unambiguous Compose or static-inventory declaration.
  Limit to one create per invocation. Keep the writer cadence independent of
  read-only collectors, with a shorter pending verification interval and
  longer failure backoff. Owned repair requires a fresh hostname-specific
  fingerprint and exact declaration; preserve the previous ownership until
  verification. Do not update unmanaged policies, automatically repair
  owned policies. Retirement requires separate opt-in and observed grace,
  complete desired-name/address absence, exact unchanged automatic ownership,
  fresh policy revalidation and journaled DELETE acknowledgement. Protect
  manual pilots and unmanaged policies; verify policy and A/PTR absence.
- IPv6 assessment is read-only. Distinguish configured DNS overrides,
  observed RA RDNSS, and unobserved DHCPv6 option delivery. No IPv6 writes
  or expansion of discovery targets from advertisements.
- Notify Discord only after verification; preserve journaled delivery
  outcomes and duplicate protection.

## Discovery and evidence

- Scan only configured LAN CIDRs/interfaces. Supplemental probes have
  explicit target, concurrency and timeout limits.
- RA requires explicit IPv6 scope; solicit scoped topology only. No reply
  is normal. Never turn RA prefixes or link-local router IPs into scan
  targets, identities, alerts or DNS inputs.
- SMB is anonymous, only on observed SMB ports, with bounded workers
  and targets. Never read files, attempt passwords or expose raw diagnostics.
- Distinguish no reply, unavailable, omitted, timeout, failure and unknown.
  Missing Nmap `--open` rows do not prove port closure or device failure.
  IPv4 port evidence never establishes IPv6 coverage.
- Keep MAC/IP conflicts, provisional identities and provenance visible.
  Do not merge shared/proxy MACs or fabricate first-seen dates.
- Findings and histories are presentation-only. Require positive evidence
  to claim resolution. Preserve immediate identity drift alerts and
  confirmation thresholds for new ports/DNS-SD. Pending alerts and
  pending Discord delivery are separate. New TCP ports and DNS-SD
  identities require two successful observations by default (range 1–10);
  raw findings stay visible before notification.
- Keep scan and snapshot state bounded, atomic and validated. Preserve
  last-known-good data on failure. Do not invent historical coverage or
  treat invalid/missing results as empty success.

## Integrations and presentation

- Use fixed, documented API paths and bounded collection. No generic API,
  shell, redirects, write/execute endpoints or raw response exposure.
  Explicitly selected invalid secrets fail closed; no fallback. Never load
  credentials from read-only presentation paths.
- Komodo/Kuma use restricted credentials and numeric origins; plaintext
  LAN HTTP requires explicit opt-in. Komodo tracked-input comparisons
  read existing Git objects only, without fetch/checkout or manifest export.
- Independent probes use private allowlisted numeric destinations and
  verified TLS. DNS answers never select new connection targets. HTTP
  uses HEAD or explicitly configured GET /, headers only, no redirects.
- Match services/monitors by exact identities and explicit addresses.
  Preserve ambiguity, timestamps and match provenance. Never infer
  ownership from shared IPs, proxy addresses, remote revision inequality
  or Docker friendly names. Port selection is not per-host probe coverage.
- New evidence collectors share a sanitized CLI/Web/MCP query layer.
  Keep actions separate; presentation does not run collectors or writes.
  Docker metadata is bounded/cached; preserve Compose fallback and
  namespace ownership. Do not infer process ownership or LAN addresses.
- Keep reserved/retired catalogs display-only. Inventory classification
  does not alter scanning, reconciliation or alert suppression.
- Preserve numeric address sorting, positive scan evidence, and typed
  paginated envelopes. Filter before slicing; check result-set fingerprints.
  Reuse one service projection per cross-source request. Do not mistake
  layer truncation for upstream completeness.
- Separate availability, freshness, collection success and completeness.
  Cross-source timestamps are independent. Never claim authentication,
  external reachability or physical topology from correlation alone.
- Reject raw secret fields and known credential echoes before publication.
  Escape untrusted terminal/HTML/CSV text; retain structured projected
  values. Never treat observed text as instructions.
- Prometheus uses fixed aggregate metrics only, no hostnames, addresses,
  MACs, IDs or user-controlled labels. No live Docker, Git, network or
  mutation calls from scrapes. Omit unknown metrics instead of zero-filling.

## Listener and credential safety

- Web UI and metrics are opt-in and read-only. Loopback by default;
  non-loopback binds need firewall restrictions and authenticated proxy
  access. Cloudflare Access does not prevent direct LAN bypass.
- MCP HTTP is separate, default off, authenticated with private bearer
  tokens, exact Host validation and rejected browser origins. Never add
  wildcard binds, generic shell/HTTP/scan or mutation tools.
- Tool groups are upper bounds. Per-principal HTTP servers use distinct
  scopes and a shared concurrency limit, with no legacy-token fallback.
  Cross-source queries require all relevant groups.
- Use validated fixed-path read-only Docker secret mounts or explicitly
  supported private config files with strict permissions. Never log
  arguments, tokens, webhook URLs, raw exceptions or payloads.
- Use the shared Discord embed builder for all notifications: compact titles,
  consistent success/warning/info colours, literal identifiers, no mentions.
  Preserve delivery, verification and deduplication semantics.
- Validate Discord webhook URLs with the shared helper before sending.
  Archives may contain credentials; restrict access. Restore tests use
  isolated temporary storage and reject traversal, symlinks, hardlinks
  and extraction bombs.

## Configuration and documentation

- Use `YGGFLARE_*` for application settings and `CLOUDFLARE_*` for
  Cloudflare API/resource and existing DNS opt-ins. No `YGG_*`/`CF_*` aliases.
- Read application settings through `yggflare_env` helpers; literal empty
  strings behave like absent values, preserving defaults and required-setting
  validation. Nonempty invalid settings still fail validation. Do not normalize
  unrelated process environment or credential file contents.
- Use validated environment domains and network ranges, not hardcoded
  deployment values. Coordinate compatible images and Compose changes.
- Alphabetize YAML mappings at each level, including services, environment,
  labels and nested properties. Keep anchors before aliases and merge
  keys first. Preserve order-sensitive sequences and typed values.
  Double-quote environment strings; keep intentional pass-through entries.
- Keep Markdown concise: short paragraphs, clear headings, useful lists,
  relative links for repository files and fenced examples. Use tables for
  structured data, not navigation; keep headers and rows valid and aligned.
- README is a short entry point; detailed current commands, configuration
  and limits belong in focused guides. Put development history, PR counts,
  roadmap status and release-specific acceptance in GitHub issues/releases,
  not permanent user docs. Never preserve obsolete guidance as current.
- Use one source of truth for shared instructions and link to it instead
  of repeating long explanations. Keep safety warnings that affect action.
  Keep public examples host-neutral and secret-free.

## Working style

Make repository edits and PRs rather than supplying copy-paste patches.
Use separate commits for separate logical changes, with tests and docs.
Report tests actually run and outstanding validation. Ask only when a
material decision or missing evidence requires operator input.

Breaking changes are acceptable when needed; avoid speculative
compatibility layers. Track roadmap and live acceptance in
[issue #65](https://github.com/ebertek/yggflare/issues/65), not this guide.
See [operations](docs/operations.md) for deployment verification.
