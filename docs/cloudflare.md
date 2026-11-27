# Cloudflare reconciliation

[Documentation index](README.md) · [Project README](../README.md)

Compose Traefik `Host` rules and the `cf.access` / `cf.access.policies` labels
describe protected external services. The static inventory describes internal DNS.
Yggflare compares these declarations with live Cloudflare resources.

## Review and apply

```sh
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare cloudflare preflight
docker exec yggflare yggflare cloudflare plan
docker exec yggflare yggflare cloudflare apply APPROVAL_FINGERPRINT
```

Replace `APPROVAL_FINGERPRINT` with the fingerprint printed by `plan`. Apply checks
the live state again and rejects a changed plan. Manual approval works with automatic
reconciliation disabled.

Manual plans include all validated actions by default. To constrain an approval, use
matching `--max-operations N` values for both `plan` and `apply`.

Automatic reconciliation validates the complete plan before executing a
batch. Access policy changes require at least one reusable `allow` or `bypass`
followed by exactly one terminal `deny`. Review policy selectors: bypass
deliberately skips Access authentication.

New external hostnames are created in **Access → Tunnel route → DNS** order.
Yggflare uses the configured Tunnel; it does not create Tunnel objects.

## Internal DNS coverage

| Source           | Behaviour                                                                             |
| ---------------- | ------------------------------------------------------------------------------------- |
| Static inventory | Detect missing, incorrect and conflicting A records; creation/update is opt-in.       |
| Docker           | Check declared IPv4 addresses and unique running addresses in `YGGFLARE_DOCKER_CIDR`. |
| Retained records | Review expected records only; no writes.                                              |

The internal zone is selected by `YGGFLARE_INTERNAL_DOMAIN`. Compose hostname
takes precedence over container/service name. Stopped services with a
declared IP remain visible. Host-mode, shared-network and bridge-only LAN
addresses are not invented.

Enable `CLOUDFLARE_DOCKER_DNS_SYNC=true` to create missing DNS-only A records
when one unambiguous Compose declaration agrees with runtime. Existing names,
shared addresses, static/alias/retained declarations and wildcard policies
are protected. Creation revalidates the evidence and verifies the result.
Stopped containers cannot authorize creation or deletion.

New Docker A records receive a private ownership entry in
`/data/managed-internal-dns.json` only after a successful creation
acknowledgement, matching live list identity and exact-ID detail verification.
The registry is bound to the account, internal zone, domain and Docker subnet.
It stores a record ID, canonical hostname, IPv4 address and detail fingerprint,
not raw API payloads. Backups include the registry and restoration validates it.

Existing DNS records are not adopted by default. An interrupted or
unverified create cannot establish ownership. Invalid scope, conflicting
ownership or corrupt registry state blocks new Docker A creation; investigate
rather than remove ownership history. Internal DNS deletion is separately opt-in.

### Internal DNS retirement review

```sh
docker exec yggflare yggflare cloudflare retirement-plan
docker exec yggflare yggflare cloudflare retirement-plan host.internal.example.net
```

This live, GET-only JSON preview reads both internal ownership registries,
the isolated Compose/private inventory snapshot, all local Docker containers
(including stopped containers), and DNS records in the configured internal
and external zones. The optional selector must be a canonical internal FQDN.

It classifies owned records, unaccounted DNS-only A records in the configured
allocations, and explicit hostname queries. Declared names and addresses,
runtime names/aliases/addresses, static companions, retained declarations,
shared addresses, wildcard records and visible DNS dependencies block a
candidate. An exact-ID GET must still match the owned record's fingerprint.
Missing, modified, ambiguous and unmanaged resources are never candidates
for automatic deletion.

`candidate_review_only` means the checked evidence did not reveal a blocker;
it is not proof of continuous absence, complete dependency coverage, or
permission to delete. For a selected hostname, `selected_dns_record_count`
includes unsupported record types; no review rows does not necessarily mean
the DNS name is absent. No grace observations, claims, writes or deletion
fingerprints are produced. This preview does not inspect arbitrary other
DNS zones, application data, non-Compose dependencies or client resolver
configuration. Web/MCP presentation is separate follow-up work.

### Automatic retirement of owned Docker A records

After reviewing the live preview and accepting the first controlled retirement,
enable both `YGGFLARE_CLOUDFLARE_AUTO_APPLY=true` and
`YGGFLARE_CLOUDFLARE_INTERNAL_AUTO_CLEANUP=true`. The latter defaults to
false and is independent of external endpoint cleanup.

- `YGGFLARE_CLOUDFLARE_INTERNAL_ORPHAN_GRACE_HOURS`: 24–720, default 24.
- `YGGFLARE_CLOUDFLARE_INTERNAL_CLEANUP_BATCH_SIZE`: 1–10, default 1.
- `YGGFLARE_CLOUDFLARE_INTERNAL_RETIRE_NOTIFY`: true/false, default false;
  uses the existing validated Discord webhook secret.

Each Cloudflare reconciliation cycle checks the current mounted Compose and
private inventory, local Docker and both DNS zones. The same owned identity
must remain a candidate across observations; gaps over eight hours, changed
ownership, reappearance or a failed review reset its grace period. A fresh
review immediately precedes each exact-ID DELETE. This first automatic path
is restricted to Docker ownership; static and unmanaged records are never
deleted. DNS API absence is verified before releasing ownership; this does
not prove recursive cache expiry, UniFi policy removal or client behaviour.

The private `/data/internal-dns-retirement.json` journal records intent before
DELETE and the returned ID before verification. An unacknowledged or
ambiguous DELETE blocks further retirement and is never replayed. A verified
deletion can finish removing ownership after a restart. Disable cleanup to
stop mutations and reset observations without discarding pending recovery.
Do not remove the journal to bypass an unknown outcome; investigate the live
record and registry first. Backups preserve and validate the journal in
isolation. Discord notices are best-effort, after verified completion only,
with no retry after an ambiguous delivery. No legacy endpoint is adopted by
this workflow.

### Explicit adoption of a retired, unmanaged Docker A record

For a single legacy internal hostname that is no longer declared, review:

```sh
docker exec yggflare yggflare cloudflare legacy-claim-plan host.internal.example.net
```

If the exact record identity and address are correct, and no remaining
application, network device, compatibility resolver or other external
dependency needs the record, approve the printed fingerprint:

```sh
docker exec yggflare yggflare cloudflare legacy-claim-apply host.internal.example.net APPROVAL_FINGERPRINT
```

This is explicit authorization to bring the retired A record under the
existing Docker ownership/retirement lifecycle, **not an immediate DELETE**.
The command uses Cloudflare GET only and writes private ownership state
only after a second, matching live plan. With internal automatic cleanup
enabled, the newly claimed record may be deleted after a new observed
grace period and all normal revalidation checks. If cleanup is disabled,
the claim does not turn it on. The grace period is not backdated.

Only one unique DNS-only A record in the configured Docker allocation can
be adopted this way. Existing ownership, static-device allocations, any
visible declaration/dependency/conflict, changed records and pending
retirement recovery block approval. The plan binds the account, both zones,
domain, allocation, record ID, address and exact detail fingerprint.
Neither bulk claims nor automatic claims use this legacy workflow.
No external DNS/Tunnel/Access or UniFi resources are adopted or deleted.


### DNS quota

With Docker creation enabled, Yggflare reads the internal zone's actual
usage and quota from `GET /zones/{zone_id}/dns_records/usage`.
`YGGFLARE_CLOUDFLARE_DNS_RESERVE` (default `10`) keeps slots free.

The complete internal creation plan must fit. Capacity is rechecked before
each Docker or static A creation. Unknown or insufficient capacity blocks
creation; records are never deleted to make room.

### Inspect findings

```sh
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare cloudflare status --all --json
```

The Web UI and MCP `get_cloudflare_audit` also expose `docker_dns` findings.
A matching A record does not establish reachability or PTR coverage.

## Ownership and cleanup

Only proven Yggflare-managed resources are eligible for retirement. Existing resources
need an explicit claim after verifying the live configuration:

```sh
docker exec yggflare yggflare cloudflare claim host.services.example.net
```

Bulk claim all matching declared Cloudflare endpoints and internal A records:

```sh
docker exec yggflare yggflare cloudflare claim-all
docker exec yggflare yggflare cloudflare claim-all external
docker exec yggflare yggflare cloudflare claim-all docker
docker exec yggflare yggflare cloudflare claim-all static
```

Set `YGGFLARE_CLOUDFLARE_AUTO_CLAIM=true` to repeat these checks during
Cloudflare reconciliation. Default is false; this is independent of auto-apply.
Claims only write private ownership state, not Cloudflare resources. Existing
ownership is never overwritten. Missing, mismatched and ambiguous resources are
skipped. Internal Docker claims require unique agreeing Compose/runtime addresses;
static claims require the private inventory and unique matching primary A records.
Retained records, aliases and companion addresses are excluded. Static claims are
stored separately in `/data/managed-static-dns.json`. Internal claims do not
authorize deletion or claim UniFi policies. External claims can make a hostname
eligible for the separately opted-in orphan cleanup after it disappears from Compose.

### Explicit adoption of a retired external endpoint

```sh
docker exec yggflare yggflare cloudflare legacy-external-claim-plan host.services.example.net
docker exec yggflare yggflare cloudflare legacy-external-claim-apply host.services.example.net APPROVAL_FINGERPRINT
```

The plan requires a complete, unique proxied Tunnel CNAME, exact ingress
route and single-host self-hosted Access application with reusable policy IDs.
Other DNS types (including A records), partial endpoints, wildcard or overlapping
destinations, visible aliases/dependencies and still-declared or running
services block adoption. The configured account, zones, Tunnel and full
DNS/Access detail hashes are bound to the reviewed fingerprint. No Access
policy or Cloudflare resource changes are made during adoption.

Approval explicitly grants ownership of one retired external hostname.
The existing cleanup settings and a new observed grace period govern
automatic retirement; manual orphan apply remains a separate approval.
Legacy-specific dependency/identity checks also run during retirement,
before each mutation and final verification. Failed legacy reviews prevent
the grace timer from aging. Confirm dependencies outside the checked Compose,
Docker, private inventory and two DNS zones independently before approval.
Other Tunnels and application data are not comprehensively inspected.
The existing external cleanup recovery semantics remain unchanged; this
does not add a per-operation acknowledgement journal.

Review removal of a claimed hostname with:

```sh
docker exec yggflare yggflare cloudflare orphan-plan host.services.example.net
docker exec yggflare yggflare cloudflare orphan-apply host.services.example.net APPROVAL_FINGERPRINT
```

Automatic cleanup requires **both** `YGGFLARE_CLOUDFLARE_AUTO_APPLY=true` and
`YGGFLARE_CLOUDFLARE_AUTO_CLEANUP=true`. A managed hostname must remain absent for at
least the configured grace period. Deletion proceeds **external DNS → Tunnel route →
Access app**, with live revalidation at each step.

Unmanaged hostnames are never deleted. Leave the cleanup batch size at `1` unless
you've independently verified desired-state accuracy and recovery. Setting it to `0`
permits bulk retirement.

### Retirement diagnostics

Explicit legacy Cloudflare plan/apply commands report elapsed-time progress
on stderr, leaving stdout unchanged. External reviews fetch all self-hosted
Access application details using at most four concurrent GETs per independent
round. No details are cached across rounds or across approval/deletion; an
incomplete or failed read blocks review. Target detail and dependency checks
remain mandatory.

A hostname-specific internal retirement review includes bounded
`private_blockers` and `private_blocker_count` for `private_protected` rows.
These identify static primary, alias, companion or retained DNS hostnames and
whether the hostname or address matched. No descriptions, arbitrary config
values or credentials are included. Shared address protections are unchanged.
