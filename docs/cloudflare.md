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

Existing DNS records are not automatically adopted. An interrupted or
unverified create cannot establish ownership. Invalid scope, conflicting
ownership or corrupt registry state blocks new Docker A creation; investigate
rather than remove ownership history. This is ownership capture only: internal
DNS deletion, adoption and retirement previews are not yet implemented.

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
